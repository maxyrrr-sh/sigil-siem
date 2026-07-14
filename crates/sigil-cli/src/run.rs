//! The Phase 0–1 runtime: build a live pipeline from config and run it
//! (ingest → decode → normalize → index + Sigma detection), serving the
//! read-only query/alert API alongside. Also hosts `replay`, a deterministic
//! file-driven path used for demos and tests (DESIGN §3 hot path, §5, §8).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use sigil_api::auth::AuthState;
use sigil_api::AlertStore;
use sigil_cluster::{Role, RoleSet};
use sigil_config::{Config, InputConfig};
use sigil_core::{Alert, Capability, Codec, Event, Result};
use sigil_correlate::{
    build_campaigns, build_incident, BeamSearchSelector, CampaignCandidate, CampaignConfig,
    CausalConfig, HashingEmbedder, Incident,
};
use sigil_detect::{build_detector, DetectorChain};
use sigil_enrich::{build_enricher, EnrichChain, Enricher};
use sigil_index::{parse_duration_micros, Analytics, ColumnarStore, EventIndex, ObjectColdStore};
use sigil_ingest::{build_codec, spawn_syslog_tcp, spawn_syslog_udp, FileTailer, TemplateMiner};
use sigil_normalize::Normalizer;
use sigil_plugin_wasm::CapabilityPolicy;
use sigil_sigma::{CorrelationEngine, SigmaEngine};
use sigil_store::Store;
use tokio::sync::mpsc;

use crate::output::Outputs;

/// Default tenant until multi-tenant routing exists.
const TENANT: &str = "default";
/// Roll the cold-tier buffer into a Parquet segment at this many events.
const ROLL_MAX: usize = 2000;

/// A raw, undecoded frame flowing from an input toward the pipeline.
struct RawFrame {
    codec_kind: String,
    should_index: bool,
    should_sigma: bool,
    bytes: Vec<u8>,
}

/// Run a node from a config file, serving the API on `api_addr`.
pub async fn run(config_path: &str, api_addr: String) -> Result<()> {
    let (cfg, report) = Config::load_and_validate(config_path)?;
    for w in &report.warnings {
        tracing::warn!("{w}");
    }
    if !report.ok() {
        for e in &report.errors {
            tracing::error!("{e}");
        }
        return Err(sigil_core::Error::Config(format!(
            "{} validation error(s); fix the config before running",
            report.errors.len()
        )));
    }

    let index = Arc::new(EventIndex::open(cfg.index.resolved_path())?);
    let mut columnar = ColumnarStore::open(
        cfg.index.resolved_cold_path(),
        cfg.index.resolved_catalog_path(),
    )?;
    // Cold object-store archive (DESIGN §7): enables warm→cold migration.
    if let Some(archive) = ObjectColdStore::from_config(&cfg.cluster.object_store)? {
        tracing::info!(archive = archive.describe(), "cold archive attached");
        columnar = columnar.with_archive(archive);
    }
    let analytics = Analytics::new(cfg.index.resolved_cold_path());
    let retention_micros = parse_duration_micros(&cfg.index.retention.cold);
    let warm_micros = parse_duration_micros(&cfg.index.retention.warm);
    let normalizer = Normalizer::new(TENANT);
    let enrich_chain = build_enrich_chain(&cfg);

    // Durable store (alert triage + saved objects); hydrate the in-memory ring.
    let store = Arc::new(Store::open(
        PathBuf::from(cfg.resolved_data_dir()).join("store.redb"),
    )?);
    let alerts = AlertStore::default().with_store(store.clone());
    alerts.hydrate();

    let auth = Arc::new(AuthState::from_config(&cfg.auth));
    let metrics = match metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder() {
        Ok(handle) => Some(Arc::new(handle)),
        Err(e) => {
            tracing::warn!(error = %e, "prometheus recorder unavailable; /metrics disabled");
            None
        }
    };

    let outputs = Outputs::new(&cfg.sigma.outputs);
    // Detection engine, shared with the API so rule edits take effect live.
    let engine = Arc::new(RwLock::new(build_engine(&cfg)?));
    let engine_len = engine.read().unwrap().len();
    // Sigma correlation (meta) rules over the live alert stream (DESIGN §8).
    let correlations = Mutex::new(build_correlations(&cfg)?);
    // Custom detectors evaluated after Sigma on the same detection path.
    let detectors = build_detector_chain(&cfg);

    // Resolve this node's roles (DESIGN §4.1). Monolith = all roles.
    let (roles, unknown) = RoleSet::from_targets(&cfg.cluster.targets);
    for u in &unknown {
        tracing::warn!("unknown cluster target `{u}`; ignoring");
    }
    let run_index = roles.runs(Role::Index);
    let run_query = roles.runs(Role::Query);
    let active: Vec<&str> = roles.roles().iter().map(|r| r.as_str()).collect();
    tracing::info!(roles = ?active, "active roles");

    let index_sources = sources_routed_to(&cfg, "index");
    let sigma_sources = sources_routed_to(&cfg, "sigma");
    // Run the detection path if Sigma has rules or any custom detector is set.
    let sigma_active = cfg.sigma.enabled && (engine_len > 0 || !detectors.is_empty());

    let (tx, mut rx) = mpsc::channel::<RawFrame>(8192);
    // Pre-normalized events from the EDR agent gateway enter the pipeline here,
    // bypassing decode/normalize. `ev_tx` is kept alive for the whole run so
    // `ev_rx.recv()` pends (rather than closing) when no gateway is active.
    let (ev_tx, mut ev_rx) = mpsc::channel::<Event>(8192);

    // Spawn an input task per configured input. Indexing/detection only run if
    // this node holds the `index` role.
    for input in &cfg.inputs {
        let should_index =
            run_index && (index_sources.is_empty() || index_sources.contains(&input.id));
        let should_sigma = run_index && sigma_active && sigma_sources.contains(&input.id);
        match input.kind.as_str() {
            "file" => spawn_file_input(input, should_index, should_sigma, tx.clone()),
            "syslog" => spawn_syslog_input(input, should_index, should_sigma, tx.clone()),
            other => {
                tracing::warn!(input = %input.id, kind = %other, "input kind not implemented; skipping")
            }
        }
    }
    drop(tx); // only input tasks hold senders now

    // EDR agent gateway (DESIGN §12). State is built whenever EDR is enabled so
    // the API can list agents / issue commands; the gRPC gateway itself only
    // runs on an `index` node (endpoint telemetry is an indexing concern).
    let edr_state = if cfg.edr.enabled {
        match sigil_edr::EdrState::new(store.clone(), &cfg.edr.enrollment_tokens) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::error!(error = %e, "failed to initialize EDR state; EDR disabled");
                None
            }
        }
    } else {
        None
    };
    if let Some(edr) = &edr_state {
        if run_index {
            let listen = cfg.edr.listen.clone();
            let state = edr.clone();
            let ev_tx = ev_tx.clone();
            let tenant = TENANT.to_string();
            let tls = load_edr_tls(&cfg);
            tokio::spawn(async move {
                if let Err(e) = sigil_edr::serve(&listen, state, ev_tx, tenant, tls).await {
                    tracing::error!(error = %e, "EDR agent gateway stopped");
                }
            });
        }
    }

    // Serve the query/alert/analytics API only if this node holds `query`.
    if run_query {
        let mut system = build_system_info(&cfg, &active, engine_len);
        system.auth_enabled = cfg.auth.enabled;
        system.persistence = true;
        let state = sigil_api::ApiState {
            index: index.clone(),
            alerts: alerts.clone(),
            analytics: analytics.clone(),
            engine: engine.clone(),
            rules_dir: cfg.sigma.rules_dir.as_ref().map(PathBuf::from),
            store: Some(store.clone()),
            auth: auth.clone(),
            system: Arc::new(system),
            metrics: metrics.clone(),
            edr: edr_state.clone(),
            config_path: Some(PathBuf::from(config_path)),
        };
        tokio::spawn(async move {
            if let Err(e) = sigil_api::serve(&api_addr, state).await {
                tracing::error!(error = %e, "api server stopped");
            }
        });
    } else {
        tracing::info!("query role inactive; API not served");
    }

    tracing::info!(
        index = %cfg.index.resolved_path(),
        cold = %cfg.index.resolved_cold_path(),
        rules = engine_len,
        "node running; Ctrl-C to stop"
    );

    // Consume frames. Hot (Tantivy) commits every second; cold (Parquet)
    // segments roll over by size or every 10s; retention runs every 60s.
    let mut codecs = CodecCache::default();
    let mut miner = TemplateMiner::default();
    let mut buffer: Vec<Event> = Vec::new();
    let mut commit = tokio::time::interval(Duration::from_millis(1000));
    let mut rollover = tokio::time::interval(Duration::from_secs(10));
    let mut retention = tokio::time::interval(Duration::from_secs(60));
    let mut dirty = 0usize;
    let mut interrupted = false;
    // Inputs may drain (e.g. none configured). A query API or EDR gateway keeps
    // the node — and this loop, which drains EDR telemetry via `ev_rx` — alive
    // until Ctrl-C. Only a pure batch node (no query, no EDR) exits on drain.
    let mut inputs_open = true;
    let serves_long = run_query || edr_state.is_some();

    loop {
        tokio::select! {
            frame = rx.recv(), if inputs_open => {
                match frame {
                    Some(frame) => {
                        for mut event in decode_normalize(&mut codecs, &normalizer, &enrich_chain, &frame)? {
                            event.template_id = Some(miner.mine(&event.message).template_id);
                            if frame.should_sigma {
                                detect(&engine, &correlations, &detectors, &event, &alerts, &outputs).await;
                            }
                            if frame.should_index {
                                index.add(&event)?;
                                metrics::counter!("sigil_events_indexed_total").increment(1);
                                dirty += 1;
                                buffer.push(event);
                                if buffer.len() >= ROLL_MAX {
                                    roll(&columnar, &mut buffer)?;
                                }
                            }
                        }
                    }
                    None => {
                        // All inputs ended. Keep serving (and draining EDR
                        // telemetry) if this is a long-running node.
                        inputs_open = false;
                        if !serves_long {
                            break;
                        }
                        tracing::info!("inputs drained; serving until Ctrl-C");
                    }
                }
            }
            maybe_event = ev_rx.recv() => {
                // Pre-normalized EDR agent telemetry: skip decode/normalize, run
                // the same detect + index tail. The gateway only feeds this on an
                // index node, so indexing is unconditional here.
                if let Some(mut event) = maybe_event {
                    event.template_id = Some(miner.mine(&event.message).template_id);
                    if sigma_active {
                        detect(&engine, &correlations, &detectors, &event, &alerts, &outputs).await;
                    }
                    index.add(&event)?;
                    metrics::counter!("sigil_events_indexed_total").increment(1);
                    dirty += 1;
                    buffer.push(event);
                    if buffer.len() >= ROLL_MAX {
                        roll(&columnar, &mut buffer)?;
                    }
                }
            }
            _ = commit.tick() => {
                if dirty > 0 {
                    index.commit()?;
                    tracing::debug!(committed = dirty, "flushed to hot index");
                    dirty = 0;
                }
            }
            _ = rollover.tick() => {
                roll(&columnar, &mut buffer)?;
            }
            _ = retention.tick() => {
                if let Some(max_age) = retention_micros {
                    let dropped = columnar.enforce_retention(max_age).await?;
                    if dropped > 0 {
                        tracing::info!(segments = dropped, "retention dropped expired cold segments");
                    }
                }
                if let Some(warm_age) = warm_micros {
                    match columnar.migrate_warm(warm_age).await {
                        Ok(0) => {}
                        Ok(n) => tracing::info!(segments = n, "migrated warm segments to cold archive"),
                        Err(e) => tracing::warn!(error = %e, "warm→cold migration failed"),
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown signal received");
                interrupted = true;
                break;
            }
        }
    }

    index.commit()?;
    roll(&columnar, &mut buffer)?;

    // Inputs drained (e.g. none configured) but a query node should keep
    // serving the API until interrupted.
    if !interrupted && run_query {
        tracing::info!("inputs drained; serving query API until Ctrl-C");
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!(
        events = index.count()?,
        alerts = alerts.len(),
        segments = columnar.segment_count(),
        "stopped"
    );
    Ok(())
}

/// Flush the cold-tier buffer into a Parquet segment (no-op if empty).
fn roll(store: &ColumnarStore, buffer: &mut Vec<Event>) -> Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }
    let rows = buffer.len();
    store.write_segment(buffer)?;
    buffer.clear();
    tracing::debug!(rows, "rolled cold segment");
    Ok(())
}

/// Run the Sigma engine + correlation rules + custom detectors over one
/// event, recording + emitting any alerts. The engine is read-locked briefly
/// (rule edits via the API take the write lock). Base alerts referenced by a
/// non-`generate` correlation rule are suppressed in favor of the aggregate
/// alert (Sigma meta-rule semantics).
async fn detect(
    engine: &Arc<RwLock<SigmaEngine>>,
    correlations: &Mutex<CorrelationEngine>,
    detectors: &DetectorChain,
    event: &Event,
    store: &AlertStore,
    outputs: &Outputs,
) {
    let base = engine.read().unwrap().eval(event);
    let mut alerts = {
        let mut corr = correlations.lock().unwrap();
        let fired = corr.process(event, &base);
        let mut kept: Vec<Alert> = base
            .into_iter()
            .filter(|a| !corr.suppressed(&a.rule_id))
            .collect();
        kept.extend(fired);
        kept
    };
    alerts.extend(detectors.eval(event));
    for alert in alerts {
        tracing::info!(
            rule = %alert.rule_id,
            technique = alert.technique.as_deref().unwrap_or("-"),
            severity = ?alert.severity,
            "ALERT"
        );
        metrics::counter!("sigil_alerts_total").increment(1);
        store.push(alert.clone());
        outputs.emit(&alert).await;
    }
}

/// Decode + normalize + enrich one frame into events. Enrichment runs on the
/// hot path after normalize and before index/Sigma (DESIGN §5).
fn decode_normalize(
    codecs: &mut CodecCache,
    normalizer: &Normalizer,
    chain: &EnrichChain,
    frame: &RawFrame,
) -> Result<Vec<Event>> {
    let codec = codecs.get(&frame.codec_kind);
    let records = codec.decode(&frame.bytes)?;
    Ok(records
        .into_iter()
        .map(|r| {
            let mut event = normalizer.normalize(r, &frame.codec_kind);
            chain.apply(&mut event);
            event
        })
        .collect())
}

/// Build the enrichment chain from the config's pipeline `enrich:` steps.
///
/// Capabilities are enforced deny-by-default: the policy grants the
/// `enrich:`/`read:field:` capabilities the configured enrichers request but
/// **never `net:egress`**, so an enricher that wants to phone out from the hot
/// path is refused unless that's deliberately granted (Phase D+).
fn build_enrich_chain(cfg: &Config) -> EnrichChain {
    let mut built: Vec<Box<dyn Enricher>> = Vec::new();
    for (name, settings) in cfg.enrich_steps() {
        if let Some(enricher) = build_enricher(&name, &settings) {
            built.push(enricher);
        }
    }
    if built.is_empty() {
        return EnrichChain::default();
    }

    let mut granted: Vec<Capability> = Vec::new();
    for e in &built {
        for c in e.capabilities() {
            if c != Capability::NetEgress && !granted.contains(&c) {
                granted.push(c);
            }
        }
    }
    let policy = CapabilityPolicy::new(granted);
    let allowed: Vec<Box<dyn Enricher>> = built
        .into_iter()
        .filter(|e| match policy.check(&e.capabilities()) {
            Ok(()) => true,
            Err(denied) => {
                tracing::warn!(enricher = e.name(), denied = ?denied, "enricher denied capabilities; skipping");
                false
            }
        })
        .collect();

    let chain = EnrichChain::new(allowed);
    if !chain.is_empty() {
        tracing::info!(enrichers = ?chain.names(), "enrichment chain active");
    }
    chain
}

/// Build the custom-detector chain from the config's top-level `detectors:`.
fn build_detector_chain(cfg: &Config) -> DetectorChain {
    let built = cfg
        .detector_steps()
        .into_iter()
        .filter_map(|(name, settings)| build_detector(&name, &settings))
        .collect::<Vec<_>>();
    let chain = DetectorChain::new(built);
    if !chain.is_empty() {
        tracing::info!(detectors = ?chain.names(), "custom detector chain active");
    }
    chain
}

/// Build the Sigma engine from config (loads `sigma.rules_dir` if set).
fn build_engine(cfg: &Config) -> Result<SigmaEngine> {
    if !cfg.sigma.enabled {
        tracing::info!("sigma disabled in config");
        return Ok(SigmaEngine::default());
    }
    let Some(dir) = &cfg.sigma.rules_dir else {
        if !cfg.sigma.rulepacks.is_empty() {
            tracing::warn!("sigma.rulepacks are not resolvable yet; set sigma.rules_dir");
        }
        return Ok(SigmaEngine::default());
    };
    let (engine, report) = SigmaEngine::load_dir(dir)?;
    tracing::info!(loaded = report.loaded, failed = report.failed.len(), dir = %dir, "loaded Sigma rules");
    for (path, err) in &report.failed {
        tracing::warn!(rule = %path.display(), error = %err, "skipped rule");
    }
    Ok(engine)
}

/// Build the Sigma *correlation* engine from the same rules dir (correlation
/// docs are the ones `SigmaEngine::load_dir` skips).
fn build_correlations(cfg: &Config) -> Result<CorrelationEngine> {
    let dir = match (&cfg.sigma.enabled, &cfg.sigma.rules_dir) {
        (true, Some(dir)) => dir,
        _ => return Ok(CorrelationEngine::default()),
    };
    let (correlations, report) = CorrelationEngine::load_dir(dir)?;
    if report.loaded > 0 {
        tracing::info!(loaded = report.loaded, dir = %dir, "loaded Sigma correlation rules");
    }
    for (path, err) in &report.failed {
        tracing::warn!(rule = %path.display(), error = %err, "skipped correlation rule");
    }
    Ok(correlations)
}

/// Load the EDR gateway's TLS cert+key from config, if both are set. Returns
/// `None` (plaintext) when unconfigured; a read failure disables TLS with a
/// warning rather than aborting the node.
fn load_edr_tls(cfg: &Config) -> Option<(Vec<u8>, Vec<u8>)> {
    let (cert_path, key_path) = match (&cfg.edr.tls_cert, &cfg.edr.tls_key) {
        (Some(c), Some(k)) => (c, k),
        _ => return None,
    };
    match (std::fs::read(cert_path), std::fs::read(key_path)) {
        (Ok(cert), Ok(key)) => Some((cert, key)),
        _ => {
            tracing::warn!(
                cert = %cert_path,
                key = %key_path,
                "could not read edr TLS cert/key; gateway will run plaintext"
            );
            None
        }
    }
}

/// Outcome of a `replay` run.
pub struct ReplayOutcome {
    pub events: usize,
    pub alerts: Vec<Alert>,
}

/// Replay a file through the pipeline deterministically (no sockets): index
/// every decoded line into the hot tier, roll the batch into a cold Parquet
/// segment, and evaluate Sigma over it. Returns counts + alerts.
pub fn replay_file(
    index: &EventIndex,
    columnar: &ColumnarStore,
    normalizer: &Normalizer,
    engine: &SigmaEngine,
    path: &str,
    codec_kind: &str,
) -> Result<ReplayOutcome> {
    let mut miner = TemplateMiner::default();
    let events = decode_file(path, codec_kind, normalizer, &mut miner)?;
    let alerts: Vec<Alert> = events.iter().flat_map(|e| engine.eval(e)).collect();
    let n = events.len();
    index.index_events(&events)?;
    columnar.write_segment(&events)?;
    Ok(ReplayOutcome { events: n, alerts })
}

/// Decode + normalize + template-mine every line of a file into events.
fn decode_file(
    path: &str,
    codec_kind: &str,
    normalizer: &Normalizer,
    miner: &mut TemplateMiner,
) -> Result<Vec<Event>> {
    let codec = build_codec(codec_kind);
    let content =
        std::fs::read(path).map_err(|e| sigil_core::Error::Io(format!("reading {path}: {e}")))?;
    let mut events = Vec::new();
    for line in content.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        for record in codec.decode(line)? {
            let mut event = normalizer.normalize(record, codec_kind);
            event.template_id = Some(miner.mine(&event.message).template_id);
            events.push(event);
        }
    }
    Ok(events)
}

/// Full correlation analysis of a file (DESIGN §9): campaign candidates plus
/// reconstructed incidents (kill-chains mapped to ATT&CK). The Sigma `engine`
/// supplies technique tags for chain nodes.
pub struct Analysis {
    pub candidates: Vec<CampaignCandidate>,
    pub incidents: Vec<Incident>,
}

pub fn analyze_file(
    engine: &SigmaEngine,
    normalizer: &Normalizer,
    path: &str,
    codec_kind: &str,
    campaign_cfg: &CampaignConfig,
    causal_cfg: &CausalConfig,
) -> Result<Analysis> {
    let mut miner = TemplateMiner::default();
    let events = decode_file(path, codec_kind, normalizer, &mut miner)?;

    // Technique tags from Sigma matches, keyed by event id.
    let mut techniques: HashMap<String, String> = HashMap::new();
    for e in &events {
        for alert in engine.eval(e) {
            if let Some(t) = alert.technique {
                techniques.entry(e.id.clone()).or_insert(t);
            }
        }
    }

    let candidates = build_campaigns(&events, campaign_cfg, &HashingEmbedder::default());
    let selector = BeamSearchSelector::default();
    let incidents = candidates
        .iter()
        .enumerate()
        .map(|(i, c)| build_incident(i, c, &events, &techniques, &selector, causal_cfg))
        .collect();

    Ok(Analysis {
        candidates,
        incidents,
    })
}

/// Caches one codec instance per kind for the consumer loop.
#[derive(Default)]
struct CodecCache {
    map: std::collections::HashMap<String, Box<dyn Codec + Send + Sync>>,
}

impl CodecCache {
    fn get(&mut self, kind: &str) -> &(dyn Codec + Send + Sync) {
        let boxed = self
            .map
            .entry(kind.to_string())
            .or_insert_with(|| build_codec(kind));
        &**boxed
    }
}

fn sources_routed_to(cfg: &Config, sink: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for p in &cfg.pipelines {
        if p.route.iter().any(|r| r.to == sink) {
            for from in &p.from {
                set.insert(from.clone());
            }
        }
    }
    set
}

/// Build the static node/config info surfaced at `GET /system`.
fn build_system_info(cfg: &Config, roles: &[&str], rule_count: usize) -> sigil_api::SystemInfo {
    sigil_api::SystemInfo {
        roles: roles.iter().map(|s| s.to_string()).collect(),
        transport: cfg
            .cluster
            .transport_kind()
            .unwrap_or_else(|| "inproc".into()),
        nodes: if cfg.cluster.nodes.is_empty() {
            vec!["local".into()]
        } else {
            cfg.cluster.nodes.clone()
        },
        shards: cfg.cluster.shards.unwrap_or(8),
        replication: cfg.cluster.replication.unwrap_or(1),
        sources: cfg
            .inputs
            .iter()
            .map(|i| sigil_api::SourceInfo {
                id: i.id.clone(),
                kind: i.kind.clone(),
                codec: i.codec.kind.clone(),
            })
            .collect(),
        pipelines: cfg
            .pipelines
            .iter()
            .map(|p| sigil_api::PipelineInfo {
                id: p.id.clone(),
                from: p.from.clone(),
                route: p.route.iter().map(|r| r.to.clone()).collect(),
            })
            .collect(),
        retention_hot: cfg.index.retention.hot.clone(),
        retention_warm: cfg.index.retention.warm.clone(),
        retention_cold: cfg.index.retention.cold.clone(),
        index_path: cfg.index.resolved_path(),
        cold_path: cfg.index.resolved_cold_path(),
        rule_count,
        ..Default::default()
    }
}

fn spawn_file_input(
    input: &InputConfig,
    should_index: bool,
    should_sigma: bool,
    tx: mpsc::Sender<RawFrame>,
) {
    let id = input.id.clone();
    let codec_kind = input.codec.kind.clone();
    let Some(path) = input.setting_str("path") else {
        tracing::error!(input = %id, "file input missing `path`; skipping");
        return;
    };
    tokio::spawn(async move {
        let mut tailer = match FileTailer::open(&path) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(input = %id, error = %e, "cannot open file input");
                return;
            }
        };
        tracing::info!(input = %id, %path, "file input started");
        loop {
            match tailer.poll_lines() {
                Ok(lines) => {
                    for bytes in lines {
                        let frame = RawFrame {
                            codec_kind: codec_kind.clone(),
                            should_index,
                            should_sigma,
                            bytes,
                        };
                        if tx.send(frame).await.is_err() {
                            return; // pipeline gone
                        }
                    }
                }
                Err(e) => tracing::warn!(input = %id, error = %e, "file poll error"),
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
}

fn spawn_syslog_input(
    input: &InputConfig,
    should_index: bool,
    should_sigma: bool,
    tx: mpsc::Sender<RawFrame>,
) {
    let id = input.id.clone();
    let codec_kind = input.codec.kind.clone();
    let Some(listen) = input.setting_str("listen") else {
        tracing::error!(input = %id, "syslog input missing `listen`; skipping");
        return;
    };

    // Inner channel carries raw datagrams/lines; a forwarder wraps them.
    let (raw_tx, mut raw_rx) = mpsc::channel::<Vec<u8>>(4096);

    {
        let listen = listen.clone();
        let raw_tx = raw_tx.clone();
        let id = id.clone();
        tokio::spawn(async move {
            if let Err(e) = spawn_syslog_udp(&listen, raw_tx).await {
                tracing::error!(input = %id, error = %e, "udp listener failed");
            }
        });
    }
    {
        let listen = listen.clone();
        let id = id.clone();
        tokio::spawn(async move {
            if let Err(e) = spawn_syslog_tcp(&listen, raw_tx).await {
                tracing::error!(input = %id, error = %e, "tcp listener failed");
            }
        });
    }

    tokio::spawn(async move {
        while let Some(bytes) = raw_rx.recv().await {
            let frame = RawFrame {
                codec_kind: codec_kind.clone(),
                should_index,
                should_sigma,
                bytes,
            };
            if tx.send(frame).await.is_err() {
                return;
            }
        }
    });

    tracing::info!(input = %id, %listen, "syslog input started (udp+tcp)");
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_index::SearchQuery;

    const AUTH_LINES: &str =
        "<34>Oct 11 22:14:15 web01 sshd: Failed password for invalid user admin from 10.0.0.9\n\
         <38>Oct 11 22:14:20 web01 sshd: Accepted password for alice from 10.0.0.5\n";

    fn store(dir: &std::path::Path) -> ColumnarStore {
        ColumnarStore::open(dir.join("cold"), dir.join("catalog.json")).unwrap()
    }

    #[test]
    fn enrich_chain_from_config_applies_in_order() {
        let cfg = Config::parse(
            r#"
version: 1
inputs:
  - id: a
    type: file
    path: /tmp/x
    codec: { type: json }
pipelines:
  - id: p
    from: [a]
    steps:
      - normalize: { schema: ocsf }
      - enrich: [redact, entropy]
    route:
      - to: index
"#,
        )
        .unwrap();
        let chain = build_enrich_chain(&cfg);
        assert_eq!(chain.names(), vec!["redact", "entropy"]);

        let mut event = Event::new("default");
        event.message = "user alice@corp.com logged in".into();
        chain.apply(&mut event);
        assert_eq!(event.message, "user ***@corp.com logged in");
    }

    #[test]
    fn enrich_then_detect_flags_dga_domain() {
        let cfg = Config::parse(
            r#"
version: 1
inputs:
  - id: a
    type: file
    path: /tmp/x
    codec: { type: json }
pipelines:
  - id: p
    from: [a]
    steps:
      - enrich: [entropy]
    route:
      - to: sigma
detectors: [dga]
"#,
        )
        .unwrap();
        let enrich = build_enrich_chain(&cfg);
        let detectors = build_detector_chain(&cfg);
        assert_eq!(detectors.names(), vec!["dga"]);

        let mut event = Event::new("default");
        event.target = Some(sigil_core::EntityRef::new(
            "domain",
            "a8f3kq9zx2m7wp1r.example.com",
        ));
        enrich.apply(&mut event); // stamps dga.score
        let alerts = detectors.eval(&event);
        assert!(alerts.iter().any(|a| a.rule_id == "dga-domain"));
    }

    #[test]
    fn replay_indexes_and_is_searchable() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("auth.log");
        std::fs::write(&log, AUTH_LINES).unwrap();

        let index = EventIndex::in_memory().unwrap();
        let columnar = store(dir.path());
        let normalizer = Normalizer::new("default");
        let outcome = replay_file(
            &index,
            &columnar,
            &normalizer,
            &SigmaEngine::default(),
            log.to_str().unwrap(),
            "syslog",
        )
        .unwrap();
        assert_eq!(outcome.events, 2);
        assert!(outcome.alerts.is_empty()); // no rules loaded

        let hits = index.search(&SearchQuery::new("admin", 10)).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].actor.as_ref().unwrap().id, "admin");
        // The same events landed in a cold segment.
        assert_eq!(columnar.total_rows(), 2);
    }

    #[tokio::test]
    async fn replay_then_analytics_sql() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("auth.log");
        std::fs::write(&log, AUTH_LINES).unwrap();

        let index = EventIndex::in_memory().unwrap();
        let columnar = store(dir.path());
        let normalizer = Normalizer::new("default");
        replay_file(
            &index,
            &columnar,
            &normalizer,
            &SigmaEngine::default(),
            log.to_str().unwrap(),
            "syslog",
        )
        .unwrap();

        // Analytical query over the cold tier.
        let res = columnar
            .sql("SELECT ocsf_class_name, count(*) AS n FROM events GROUP BY ocsf_class_name")
            .await
            .unwrap();
        let total: i64 = res.rows.iter().map(|r| r["n"].as_i64().unwrap()).sum();
        assert_eq!(total, 2);
    }

    #[test]
    fn replay_with_engine_produces_alerts() {
        let (engine, report) = SigmaEngine::load_dir("../../configs/rules").unwrap();
        assert!(report.loaded >= 1, "expected bundled rules to load");

        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("auth.log");
        std::fs::write(&log, AUTH_LINES).unwrap();

        let index = EventIndex::in_memory().unwrap();
        let columnar = store(dir.path());
        let normalizer = Normalizer::new("default");
        let outcome = replay_file(
            &index,
            &columnar,
            &normalizer,
            &engine,
            log.to_str().unwrap(),
            "syslog",
        )
        .unwrap();

        // The failed-password line should trip the SSH brute-force rule.
        assert!(outcome
            .alerts
            .iter()
            .any(|a| a.technique.as_deref() == Some("T1110.001")));
    }
}
