//! `sigil` — command-line entrypoint for Sigil SIEM.
//!
//! Phase 0 wires real `run`, `replay`, and `config validate` subcommands; the
//! remaining `config` verbs (plan/apply/diff) are still stubs (DESIGN §13.2).

mod output;
mod run;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sigil_api::dsl;
use sigil_cluster::{NodeId, RoleSet, ShardMap};
use sigil_config::Config;
use sigil_correlate::{CampaignConfig, CausalConfig};
use sigil_eval::{run_eval, synthetic};
use sigil_index::{parse_duration_micros, Analytics, ColumnarStore, EventIndex};
use sigil_normalize::Normalizer;
use sigil_plugin_wasm::{CapabilityPolicy, WasmManifest};
use sigil_sigma::SigmaEngine;

const DEFAULT_CONFIG: &str = "configs/sigil.yaml";
const DEFAULT_API_ADDR: &str = "127.0.0.1:8080";

#[derive(Parser)]
#[command(name = "sigil", version, about = "Declarative, plugin-extensible SIEM")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the node (inputs + index + query API) from config.
    Run {
        /// Path to the declarative config.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
        /// Address the query API listens on.
        #[arg(long, default_value = DEFAULT_API_ADDR)]
        api_addr: String,
    },
    /// Replay events from a file through the pipeline into the index.
    Replay {
        /// File of newline-delimited records to replay.
        file: String,
        /// Codec to decode each line with.
        #[arg(long, default_value = "syslog")]
        codec: String,
        /// Config (used to resolve the index path).
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Correlate a file of events into cross-domain campaign candidates.
    Correlate {
        /// File of newline-delimited records to correlate.
        file: String,
        /// Codec to decode each line with.
        #[arg(long, default_value = "syslog")]
        codec: String,
        /// Link window (e.g. `30m`, `1h`). Defaults to 30m.
        #[arg(long)]
        window: Option<String>,
        /// Keep single-domain groups too (don't require cross-domain).
        #[arg(long, default_value_t = false)]
        all_domains: bool,
        /// Config (used to load Sigma rules for ATT&CK technique tags).
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Run an analytical query over the cold tier (SQL or pipe-DSL).
    Query {
        /// The query text. SQL, or pipe-DSL like `search x | stats count() by host`.
        query: String,
        /// Force the language instead of auto-detecting (`sql` or `dsl`).
        #[arg(long)]
        lang: Option<String>,
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Show resolved roles, transport, and the shard map (DESIGN §4).
    Cluster {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// WASM plugin management (DESIGN §12).
    Plugin {
        #[command(subcommand)]
        action: PluginAction,
    },
    /// Evaluate correlation/attribution on a synthetic scenario (DESIGN §11).
    Eval {
        /// Seed for the deterministic synthetic scenario.
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
    /// Configuration management (DESIGN §13.2).
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum PluginAction {
    /// Verify a plugin manifest's requested capabilities against a grant list.
    Verify {
        /// Path to the plugin manifest (JSON).
        manifest: String,
        /// Granted capability (repeatable), e.g. `--allow read:field:message`.
        #[arg(long = "allow")]
        allow: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Validate a config against the schema and semantic rules.
    Validate {
        #[arg(default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Show the diff between desired and running state (not implemented).
    Plan {
        #[arg(default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Apply configuration (not implemented).
    Apply {
        #[arg(default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Show runtime drift vs declared config (not implemented).
    Diff,
}

fn main() -> ExitCode {
    init_tracing();
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> sigil_core::Result<ExitCode> {
    match cli.command {
        Command::Run { config, api_addr } => {
            tokio_runtime()?.block_on(run::run(&config, api_addr))?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Replay {
            file,
            codec,
            config,
        } => cmd_replay(&file, &codec, &config),
        Command::Correlate {
            file,
            codec,
            window,
            all_domains,
            config,
        } => cmd_correlate(&file, &codec, window.as_deref(), all_domains, &config),
        Command::Query {
            query,
            lang,
            config,
        } => cmd_query(&query, lang.as_deref(), &config),
        Command::Cluster { config } => cmd_cluster(&config),
        Command::Plugin { action } => cmd_plugin(action),
        Command::Eval { seed } => {
            print!("{}", run_eval(&synthetic(seed)));
            Ok(ExitCode::SUCCESS)
        }
        Command::Config { action } => cmd_config(action),
    }
}

fn cmd_cluster(config: &str) -> sigil_core::Result<ExitCode> {
    let cfg = Config::load(config)?;
    let (roles, unknown) = RoleSet::from_targets(&cfg.cluster.targets);

    let active: Vec<&str> = roles.roles().iter().map(|r| r.as_str()).collect();
    println!(
        "roles:       {}{}",
        active.join(", "),
        if roles.is_monolith() {
            " (monolith)"
        } else {
            ""
        }
    );
    for u in &unknown {
        println!("  warning: unknown target `{u}`");
    }
    println!(
        "transport:   {}",
        cfg.cluster
            .transport_kind()
            .unwrap_or_else(|| "inproc".into())
    );

    let nodes: Vec<NodeId> = if cfg.cluster.nodes.is_empty() {
        vec![NodeId("local".into())]
    } else {
        cfg.cluster
            .nodes
            .iter()
            .map(|n| NodeId(n.clone()))
            .collect()
    };
    let shards = cfg.cluster.shards.unwrap_or(8);
    let replication = cfg.cluster.replication.unwrap_or(1);
    let map = ShardMap::new(shards, replication, nodes.clone());
    println!(
        "nodes:       {} | shards: {shards} | replication: {replication}",
        nodes.len()
    );

    let key = "tenant=default";
    let shard = map.shard_for(key, 0);
    let placement: Vec<&str> = map.nodes_for(shard).iter().map(|n| n.0.as_str()).collect();
    println!(
        "example:     key '{key}' → shard {shard} → [{}]",
        placement.join(", ")
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_plugin(action: PluginAction) -> sigil_core::Result<ExitCode> {
    match action {
        PluginAction::Verify { manifest, allow } => {
            let m = WasmManifest::load(&manifest)?;
            let requested = m.requested_capabilities()?;
            let policy = CapabilityPolicy::from_strings(&allow)?;
            println!("plugin:   {} v{} ({})", m.name, m.version, m.kind);
            let caps = if m.capabilities.is_empty() {
                "(none)".to_string()
            } else {
                m.capabilities.join(", ")
            };
            println!("requests: {caps}");
            println!(
                "granted:  {}",
                if allow.is_empty() {
                    "(none)".to_string()
                } else {
                    allow.join(", ")
                }
            );
            match policy.check(&requested) {
                Ok(()) => {
                    println!("result:   OK — all requested capabilities granted");
                    Ok(ExitCode::SUCCESS)
                }
                Err(denied) => {
                    println!("result:   DENIED — {}", denied.join(", "));
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}

fn cmd_replay(file: &str, codec: &str, config: &str) -> sigil_core::Result<ExitCode> {
    let cfg = Config::load(config)?;
    let index = EventIndex::open(cfg.index.resolved_path())?;
    let columnar = ColumnarStore::open(
        cfg.index.resolved_cold_path(),
        cfg.index.resolved_catalog_path(),
    )?;
    let normalizer = Normalizer::new("default");

    let engine = match (cfg.sigma.enabled, &cfg.sigma.rules_dir) {
        (true, Some(dir)) => {
            let (engine, report) = SigmaEngine::load_dir(dir)?;
            println!("loaded {} Sigma rule(s) from {dir}", report.loaded);
            engine
        }
        _ => SigmaEngine::default(),
    };

    let outcome = run::replay_file(&index, &columnar, &normalizer, &engine, file, codec)?;
    println!(
        "replayed {} event(s) into {}",
        outcome.events,
        cfg.index.resolved_path()
    );
    println!(
        "total indexed: {} | cold segments: {} ({} rows)",
        index.count()?,
        columnar.segment_count(),
        columnar.total_rows()
    );

    if !outcome.alerts.is_empty() {
        let outputs = output::Outputs::new(&cfg.sigma.outputs);
        println!("{} alert(s):", outcome.alerts.len());
        for a in &outcome.alerts {
            println!(
                "  [{}] {} (technique {})",
                a.rule_id,
                a.title,
                a.technique.as_deref().unwrap_or("-")
            );
        }
        if !outputs.is_empty() {
            tokio_runtime()?.block_on(async {
                for a in &outcome.alerts {
                    outputs.emit(a).await;
                }
            });
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_correlate(
    file: &str,
    codec: &str,
    window: Option<&str>,
    all_domains: bool,
    config: &str,
) -> sigil_core::Result<ExitCode> {
    let cfg_file = Config::load(config)?;
    let engine = match (cfg_file.sigma.enabled, &cfg_file.sigma.rules_dir) {
        (true, Some(dir)) => SigmaEngine::load_dir(dir)?.0,
        _ => SigmaEngine::default(),
    };
    let normalizer = Normalizer::new("default");

    let mut campaign_cfg = CampaignConfig::default();
    if let Some(w) = window {
        campaign_cfg.window_micros = parse_duration_micros(w)
            .ok_or_else(|| sigil_core::Error::Config(format!("bad --window `{w}`")))?;
    }
    if all_domains {
        campaign_cfg.require_cross_domain = false;
    }
    let causal_cfg = CausalConfig {
        window_micros: campaign_cfg.window_micros,
        ..Default::default()
    };

    let analysis = run::analyze_file(
        &engine,
        &normalizer,
        file,
        codec,
        &campaign_cfg,
        &causal_cfg,
    )?;

    if analysis.candidates.is_empty() {
        println!("no campaign candidates found");
        return Ok(ExitCode::SUCCESS);
    }

    println!("{} campaign candidate(s):", analysis.candidates.len());
    for c in &analysis.candidates {
        println!(
            "  #{} score={:.2} domains=[{}] links={} ({} events)",
            c.id,
            c.score,
            c.domains.join(", "),
            c.links,
            c.events.len()
        );
    }

    println!("\nreconstructed incident(s):");
    for inc in &analysis.incidents {
        println!(
            "  incident #{} confidence={:.2} kill-chain: {}",
            inc.id,
            inc.confidence,
            inc.tactics.join(" → ")
        );
        for (k, step) in inc.chain.iter().enumerate() {
            let technique = step
                .technique
                .as_deref()
                .map(|t| format!(" ({t})"))
                .unwrap_or_default();
            println!(
                "     {}. [{}] {}{}",
                k + 1,
                step.tactic.as_deref().unwrap_or("-"),
                step.label,
                technique
            );
        }
        if !inc.explanation.is_empty() {
            println!("     why: {}", inc.explanation.join(" | "));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_query(query: &str, lang: Option<&str>, config: &str) -> sigil_core::Result<ExitCode> {
    let cfg = Config::load(config)?;
    let analytics = Analytics::new(cfg.index.resolved_cold_path());

    let is_dsl = match lang {
        Some("dsl") => true,
        Some("sql") => false,
        Some(other) => {
            return Err(sigil_core::Error::Config(format!(
                "unknown --lang `{other}` (sql|dsl)"
            )))
        }
        None => looks_like_dsl(query),
    };
    let sql = if is_dsl {
        dsl::lower(query)?
    } else {
        query.to_string()
    };
    if is_dsl {
        println!("-- lowered to SQL: {sql}");
    }

    let res = tokio_runtime()?.block_on(analytics.sql(&sql))?;
    println!("{}", res.table);
    Ok(ExitCode::SUCCESS)
}

/// Heuristic: treat input as pipe-DSL if it pipes or starts with a DSL verb.
fn looks_like_dsl(q: &str) -> bool {
    if q.contains('|') {
        return true;
    }
    let first = q
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        first.as_str(),
        "search" | "where" | "stats" | "fields" | "sort" | "head"
    )
}

fn cmd_config(action: ConfigAction) -> sigil_core::Result<ExitCode> {
    match action {
        ConfigAction::Validate { config } => {
            let (_, report) = Config::load_and_validate(&config)?;
            println!("{report}");
            Ok(if report.ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        ConfigAction::Plan { config } | ConfigAction::Apply { config } => {
            // Load + validate so at least obvious errors surface today.
            let (_, report) = Config::load_and_validate(&config)?;
            if !report.ok() {
                println!("{report}");
                return Ok(ExitCode::FAILURE);
            }
            eprintln!(
                "[scaffold] `config plan/apply` not implemented yet — see docs/DESIGN.md §13.2"
            );
            Ok(ExitCode::from(2))
        }
        ConfigAction::Diff => {
            eprintln!(
                "[scaffold] `config diff` (drift) not implemented yet — see docs/DESIGN.md §13.2"
            );
            Ok(ExitCode::from(2))
        }
    }
}

fn tokio_runtime() -> sigil_core::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| sigil_core::Error::Other(format!("tokio runtime: {e}")))
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    // Sigil at info; quiet Tantivy's verbose commit/GC chatter by default.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,tantivy=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
