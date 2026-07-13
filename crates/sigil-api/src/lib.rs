//! `sigil-api` — query + control API (DESIGN §16/§17, §14).
//!
//! The read surface (search / alerts / incidents / analytics) is joined by a
//! **versioned, authenticated** control surface under `/api/v1`: JWT login +
//! RBAC, durable alert triage, rule CRUD + test, saved objects, ATT&CK coverage,
//! search helpers, and an SSE alert stream. Everything under `/api/v1` is gated
//! by [`auth::require_auth`]; the legacy unversioned read routes + embedded demo
//! UI are mounted **only when auth is disabled** (the Svelte console is the
//! authenticated UI).
//!
//! Several internal helpers return `Result<_, Response>` to short-circuit a
//! handler with a ready-made error response; axum's `Response` is a large type,
//! so we allow `result_large_err` crate-wide rather than box every error.
#![allow(clippy::result_large_err)]

pub mod auth;
pub mod dsl;

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::{Extension, Json, Router};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use sigil_core::{now_micros, Alert, Event};
use sigil_correlate::{
    build_campaigns, build_incident, tactic_for, BeamSearchSelector, CampaignConfig, CausalConfig,
    HashingEmbedder, Incident,
};
use sigil_index::columnar::event_schema;
use sigil_index::{parse_duration_micros, Analytics, EventIndex, SearchQuery};
use sigil_sigma::{event_from_fields, run_cases, CompiledRule, RuleInfo, SigmaEngine, TestCase};
use sigil_store::{AlertPatch, AlertRecord, Note, SavedObject, Store, TriageStatus};

use crate::auth::{AuthState, AuthUser, Role};

/// A bounded, in-memory ring of recent alerts plus a durable write-through to
/// the [`Store`] (when configured) and a broadcast for the SSE stream.
#[derive(Clone)]
pub struct AlertStore {
    inner: Arc<Mutex<VecDeque<Alert>>>,
    cap: usize,
    store: Option<Arc<Store>>,
    tx: broadcast::Sender<AlertRecord>,
}

impl AlertStore {
    pub fn new(cap: usize) -> Self {
        let (tx, _) = broadcast::channel(256);
        AlertStore {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            cap: cap.max(1),
            store: None,
            tx,
        }
    }

    /// Attach a durable store: pushes become write-through (preserving triage)
    /// and the API serves persisted [`AlertRecord`]s.
    pub fn with_store(mut self, store: Arc<Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Subscribe to the live alert stream (for SSE).
    pub fn subscribe(&self) -> broadcast::Receiver<AlertRecord> {
        self.tx.subscribe()
    }

    /// Load persisted alerts into the in-memory ring at startup.
    pub fn hydrate(&self) {
        if let Some(s) = &self.store {
            if let Ok(recs) = s.list_alerts(self.cap, None) {
                let mut q = self.inner.lock().unwrap();
                for r in recs.into_iter().rev() {
                    if q.len() == self.cap {
                        q.pop_front();
                    }
                    q.push_back(r.alert);
                }
            }
        }
    }

    /// Record an alert: ring (evicting oldest), durable upsert, broadcast.
    pub fn push(&self, alert: Alert) {
        {
            let mut q = self.inner.lock().unwrap();
            if q.len() == self.cap {
                q.pop_front();
            }
            q.push_back(alert.clone());
        }
        let rec = match &self.store {
            Some(s) => s.upsert_alert(alert.clone()).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "alert persist failed");
                AlertRecord::new(alert)
            }),
            None => AlertRecord::new(alert),
        };
        let _ = self.tx.send(rec);
    }

    /// Total alerts retained (durable count when a store is attached).
    pub fn len(&self) -> usize {
        match &self.store {
            Some(s) => s
                .alert_count()
                .unwrap_or_else(|_| self.inner.lock().unwrap().len()),
            None => self.inner.lock().unwrap().len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Most recent alerts (newest first) as plain [`Alert`]s — kept for the
    /// detection path and tests.
    pub fn recent(&self, limit: usize, technique: Option<&str>) -> Vec<Alert> {
        let q = self.inner.lock().unwrap();
        q.iter()
            .rev()
            .filter(|a| match technique {
                Some(t) => a.technique.as_deref() == Some(t),
                None => true,
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// Most recent alert *records* (with triage), from the store when present.
    pub fn records(&self, limit: usize, technique: Option<&str>) -> Vec<AlertRecord> {
        match &self.store {
            Some(s) => s.list_alerts(limit, technique).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "list alerts failed");
                Vec::new()
            }),
            None => self
                .recent(limit, technique)
                .into_iter()
                .map(AlertRecord::new)
                .collect(),
        }
    }
}

impl Default for AlertStore {
    fn default() -> Self {
        AlertStore::new(10_000)
    }
}

/// A configured input source (for the Data screen).
#[derive(Debug, Clone, Serialize)]
pub struct SourceInfo {
    pub id: String,
    pub kind: String,
    pub codec: String,
}

/// A configured pipeline (for the Data screen).
#[derive(Debug, Clone, Serialize)]
pub struct PipelineInfo {
    pub id: String,
    pub from: Vec<String>,
    pub route: Vec<String>,
}

/// Static node/cluster/config info surfaced to the Data & Cluster screens.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SystemInfo {
    pub roles: Vec<String>,
    pub transport: String,
    pub nodes: Vec<String>,
    pub shards: u32,
    pub replication: u32,
    pub sources: Vec<SourceInfo>,
    pub pipelines: Vec<PipelineInfo>,
    pub retention_hot: String,
    pub retention_warm: String,
    pub retention_cold: String,
    pub index_path: String,
    pub cold_path: String,
    pub rule_count: usize,
    /// Whether authentication is enabled (the UI shows/hides login accordingly).
    #[serde(default)]
    pub auth_enabled: bool,
    /// Whether a durable store is attached (mutations available).
    #[serde(default)]
    pub persistence: bool,
}

/// Shared application state handed to every handler.
#[derive(Clone)]
pub struct ApiState {
    pub index: Arc<EventIndex>,
    pub alerts: AlertStore,
    pub analytics: Analytics,
    /// The live detection engine, shared with the run loop; rule edits swap it.
    pub engine: Arc<RwLock<SigmaEngine>>,
    /// Directory rule CRUD writes to (from `sigma.rules_dir`).
    pub rules_dir: Option<PathBuf>,
    /// Durable store for triage + saved objects (mutations require it).
    pub store: Option<Arc<Store>>,
    pub auth: Arc<AuthState>,
    pub system: Arc<SystemInfo>,
    /// Prometheus render handle (for `GET /metrics`).
    pub metrics: Option<Arc<PrometheusHandle>>,
    /// EDR fleet state (agents / commands / enrollment tokens), when the EDR
    /// module is enabled. Powers the `/edr/*` control routes.
    pub edr: Option<Arc<sigil_edr::EdrState>>,
}

/// Build the API router over the shared application state.
pub fn router(state: ApiState) -> Router {
    let auth = state.auth.clone();
    let auth_enabled = state.auth.enabled;

    // Public (no token): login + health (so the UI can discover whether auth is on).
    let public = Router::new()
        .route("/auth/login", post(login_handler))
        .route("/health", get(health));

    // Protected: everything else under /api/v1.
    let protected = Router::new()
        .route("/me", get(me_handler))
        .route("/count", get(count))
        .route("/search", get(search))
        .route("/search/fields", get(search_fields))
        .route("/search/histogram", get(search_histogram))
        .route("/alerts", get(alerts_handler).patch(alerts_bulk_patch))
        .route("/alerts/:fp", patch(alert_patch))
        .route("/incidents", get(incidents_handler))
        .route("/rules", get(rules_handler).post(rule_create))
        .route("/rules/:id", put(rule_update).delete(rule_delete))
        .route("/rules/:id/test", post(rule_test))
        .route("/attack/coverage", get(attack_coverage))
        .route("/saved/:kind", get(saved_list).post(saved_create))
        .route("/saved/:kind/:id", put(saved_update).delete(saved_delete))
        .route("/edr/agents", get(edr_agents))
        .route("/edr/agents/:id", get(edr_agent))
        .route("/edr/agents/:id/actions", post(edr_action))
        .route("/edr/commands", get(edr_commands))
        .route("/edr/enroll-tokens", get(edr_tokens).post(edr_token_create))
        .route("/edr/stream/agents", get(edr_stream_agents))
        .route("/system", get(system_handler))
        .route("/eval", get(eval_handler))
        .route("/sql", get(sql_handler))
        .route("/query", get(query_handler))
        .route("/stream/alerts", get(stream_alerts))
        .route("/openapi.json", get(openapi_handler))
        .route_layer(axum::middleware::from_fn_with_state(
            auth,
            auth::require_auth,
        ));

    let v1 = public.merge(protected);

    let mut app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        .nest("/api/v1", v1);

    // Legacy unauthenticated read surface + embedded demo UI.
    if !auth_enabled {
        app = app
            .route("/", get(ui))
            .route("/ui", get(ui))
            .route("/count", get(count))
            .route("/search", get(search))
            .route("/alerts", get(alerts_handler))
            .route("/incidents", get(incidents_handler))
            .route("/rules", get(rules_handler))
            .route("/system", get(system_handler))
            .route("/eval", get(eval_handler))
            .route("/sql", get(sql_handler))
            .route("/query", get(query_handler));
    }

    app.layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Bind `addr` and serve the API until the process exits.
pub async fn serve(addr: &str, state: ApiState) -> sigil_core::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| sigil_core::Error::Io(format!("bind api {addr}: {e}")))?;
    tracing::info!(%addr, "query API listening");
    axum::serve(listener, router(state))
        .await
        .map_err(|e| sigil_core::Error::Io(format!("api serve: {e}")))
}

// --- auth handlers ---------------------------------------------------------

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login_handler(
    State(state): State<ApiState>,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    match state.auth.authenticate(&body.username, &body.password) {
        Some(user) => match state.auth.issue(&user) {
            Ok(token) => Json(serde_json::json!({
                "token": token,
                "token_type": "Bearer",
                "expires_in": state.auth.ttl(),
                "user": { "username": user.username, "roles": role_strs(&user) },
            }))
            .into_response(),
            Err(resp) => resp,
        },
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid credentials" })),
        )
            .into_response(),
    }
}

async fn me_handler(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    Json(serde_json::json!({ "username": user.username, "roles": role_strs(&user) }))
}

fn role_strs(user: &AuthUser) -> Vec<&'static str> {
    user.roles.iter().map(|r| r.as_str()).collect()
}

// --- system / eval / health ------------------------------------------------

async fn system_handler(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.system.as_ref().clone())
}

async fn eval_handler(Query(params): Query<EvalParams>) -> impl IntoResponse {
    let seed = params.seed.unwrap_or(1);
    let report = sigil_eval::run_eval(&sigil_eval::synthetic(seed));
    Json(report).into_response()
}

#[derive(Debug, Deserialize)]
pub struct EvalParams {
    #[serde(default)]
    pub seed: Option<u64>,
}

async fn ui() -> Html<&'static str> {
    Html(UI_HTML)
}

const UI_HTML: &str = include_str!("ui.html");

async fn health(State(state): State<ApiState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "auth_enabled": state.auth.enabled,
        "persistence": state.store.is_some(),
    }))
}

async fn metrics_handler(State(state): State<ApiState>) -> Response {
    match &state.metrics {
        Some(h) => (
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            h.render(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "metrics not enabled").into_response(),
    }
}

async fn count(State(state): State<ApiState>) -> impl IntoResponse {
    match state.index.count() {
        Ok(n) => {
            Json(serde_json::json!({ "events": n, "alerts": state.alerts.len() })).into_response()
        }
        Err(e) => error_response(e),
    }
}

// --- search ----------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub count: usize,
    pub events: Vec<Event>,
}

async fn search(
    State(state): State<ApiState>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).clamp(1, 1000);
    let query = SearchQuery::new(params.q.unwrap_or_default(), limit);
    match state.index.search(&query) {
        Ok(events) => Json(SearchResponse {
            count: events.len(),
            events,
        })
        .into_response(),
        Err(e) => error_response(e),
    }
}

/// `GET /search/fields` — the analytical event schema (for query builders).
async fn search_fields() -> impl IntoResponse {
    let schema = event_schema();
    let fields: Vec<serde_json::Value> = schema
        .fields()
        .iter()
        .map(|f| {
            serde_json::json!({
                "name": f.name(),
                "type": format!("{:?}", f.data_type()),
                "nullable": f.is_nullable(),
            })
        })
        .collect();
    Json(serde_json::json!({ "fields": fields }))
}

#[derive(Debug, Deserialize)]
pub struct HistogramParams {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub interval: Option<String>,
}

/// `GET /search/histogram` — event counts bucketed by time over the cold tier.
async fn search_histogram(
    State(state): State<ApiState>,
    Query(params): Query<HistogramParams>,
) -> impl IntoResponse {
    let interval = params.interval.unwrap_or_else(|| "1h".into());
    let width = parse_duration_micros(&interval)
        .unwrap_or(3_600_000_000)
        .max(1);
    let mut sql = format!("SELECT (ts / {width}) * {width} AS bucket, count(*) AS n FROM events");
    if let Some(q) = params.q.filter(|q| !q.trim().is_empty()) {
        let safe = q.replace('\'', "''");
        sql.push_str(&format!(" WHERE message LIKE '%{safe}%'"));
    }
    sql.push_str(" GROUP BY bucket ORDER BY bucket");
    run_analytics(&state, &sql, format!("histogram interval={interval}")).await
}

// --- alerts ----------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AlertParams {
    #[serde(default)]
    pub technique: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct AlertsResponse {
    pub count: usize,
    pub alerts: Vec<AlertRecord>,
}

async fn alerts_handler(
    State(state): State<ApiState>,
    Query(params): Query<AlertParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).clamp(1, 1000);
    let alerts = state.alerts.records(limit, params.technique.as_deref());
    Json(AlertsResponse {
        count: alerts.len(),
        alerts,
    })
}

#[derive(Debug, Deserialize)]
struct AlertPatchBody {
    #[serde(default)]
    status: Option<String>,
    /// `Some("")` clears the assignee; `Some(name)` sets it; absent leaves it.
    #[serde(default)]
    assignee: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

fn to_patch(body: &AlertPatchBody, user: &AuthUser) -> Result<AlertPatch, Response> {
    let status = match &body.status {
        Some(s) => Some(TriageStatus::parse(s).ok_or_else(|| bad_request("invalid status"))?),
        None => None,
    };
    let assignee = body
        .assignee
        .as_ref()
        .map(|s| if s.is_empty() { None } else { Some(s.clone()) });
    let note = body
        .note
        .as_ref()
        .filter(|t| !t.trim().is_empty())
        .map(|t| Note {
            ts: now_micros(),
            author: user.username.clone(),
            text: t.clone(),
        });
    Ok(AlertPatch {
        status,
        assignee,
        note,
    })
}

async fn alert_patch(
    State(state): State<ApiState>,
    Extension(user): Extension<AuthUser>,
    Path(fp): Path<String>,
    Json(body): Json<AlertPatchBody>,
) -> Response {
    if let Err(r) = auth::require(&user, Role::Analyst) {
        return r;
    }
    let Some(store) = &state.store else {
        return conflict("persistence not enabled (set `data_dir`)");
    };
    let patch = match to_patch(&body, &user) {
        Ok(p) => p,
        Err(r) => return r,
    };
    match store.patch_alert(&fp, &patch) {
        Ok(Some(rec)) => Json(rec).into_response(),
        Ok(None) => not_found("no alert with that fingerprint"),
        Err(e) => error_response(e),
    }
}

#[derive(Debug, Deserialize)]
struct BulkPatchBody {
    fingerprints: Vec<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    assignee: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

async fn alerts_bulk_patch(
    State(state): State<ApiState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<BulkPatchBody>,
) -> Response {
    if let Err(r) = auth::require(&user, Role::Analyst) {
        return r;
    }
    let Some(store) = &state.store else {
        return conflict("persistence not enabled (set `data_dir`)");
    };
    let patch = match to_patch(
        &AlertPatchBody {
            status: body.status,
            assignee: body.assignee,
            note: body.note,
        },
        &user,
    ) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let mut updated = Vec::new();
    for fp in &body.fingerprints {
        if let Ok(Some(rec)) = store.patch_alert(fp, &patch) {
            updated.push(rec);
        }
    }
    Json(serde_json::json!({ "updated": updated.len(), "alerts": updated })).into_response()
}

// --- incidents -------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct IncidentsResponse {
    pub count: usize,
    pub incidents: Vec<Incident>,
}

async fn incidents_handler(State(state): State<ApiState>) -> impl IntoResponse {
    let events = match state.index.search(&SearchQuery::new("", 5000)) {
        Ok(e) => e,
        Err(e) => return error_response(e),
    };

    let mut techniques = std::collections::HashMap::new();
    for rec in state.alerts.records(100_000, None) {
        if let Some(t) = rec.alert.technique {
            for ev in rec.alert.events {
                techniques.entry(ev).or_insert_with(|| t.clone());
            }
        }
    }

    let cfg = CampaignConfig {
        window_micros: 24 * 60 * 60 * 1_000_000,
        ..Default::default()
    };
    let candidates = build_campaigns(&events, &cfg, &HashingEmbedder::default());
    let selector = BeamSearchSelector::default();
    let causal = CausalConfig {
        window_micros: cfg.window_micros,
        ..Default::default()
    };
    let incidents: Vec<Incident> = candidates
        .iter()
        .enumerate()
        .map(|(i, c)| build_incident(i, c, &events, &techniques, &selector, &causal))
        .collect();

    Json(IncidentsResponse {
        count: incidents.len(),
        incidents,
    })
    .into_response()
}

// --- rules -----------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct RulesResponse {
    pub count: usize,
    pub rules: Vec<RuleInfo>,
}

async fn rules_handler(State(state): State<ApiState>) -> impl IntoResponse {
    let rules = state.engine.read().unwrap().rule_infos();
    Json(RulesResponse {
        count: rules.len(),
        rules,
    })
}

#[derive(Debug, Deserialize)]
struct RuleBody {
    yaml: String,
}

async fn rule_create(
    State(state): State<ApiState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<RuleBody>,
) -> Response {
    if let Err(r) = auth::require(&user, Role::Analyst) {
        return r;
    }
    let compiled = match CompiledRule::compile(&body.yaml) {
        Ok(c) => c,
        Err(e) => return bad_request(&e.to_string()),
    };
    if let Err(r) = write_rule_file(&state, &compiled.rule_id, &body.yaml) {
        return r;
    }
    match reload_engine(&state) {
        Ok(n) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "rule_id": compiled.rule_id, "rules": n })),
        )
            .into_response(),
        Err(r) => r,
    }
}

async fn rule_update(
    State(state): State<ApiState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<RuleBody>,
) -> Response {
    if let Err(r) = auth::require(&user, Role::Analyst) {
        return r;
    }
    if let Err(e) = CompiledRule::compile(&body.yaml) {
        return bad_request(&e.to_string());
    }
    if let Err(r) = write_rule_file(&state, &id, &body.yaml) {
        return r;
    }
    match reload_engine(&state) {
        Ok(n) => Json(serde_json::json!({ "rule_id": id, "rules": n })).into_response(),
        Err(r) => r,
    }
}

async fn rule_delete(
    State(state): State<ApiState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = auth::require(&user, Role::Analyst) {
        return r;
    }
    match delete_rule_file(&state, &id) {
        Ok(true) => match reload_engine(&state) {
            Ok(n) => Json(serde_json::json!({ "deleted": id, "rules": n })).into_response(),
            Err(r) => r,
        },
        Ok(false) => not_found("rule not found"),
        Err(r) => r,
    }
}

#[derive(Debug, Deserialize)]
struct RuleTestCaseBody {
    name: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    fields: BTreeMap<String, String>,
    expect_match: bool,
}

#[derive(Debug, Deserialize)]
struct RuleTestBody {
    /// Inline YAML to test a draft; if absent the rule `:id` is loaded.
    #[serde(default)]
    yaml: Option<String>,
    cases: Vec<RuleTestCaseBody>,
}

async fn rule_test(
    State(state): State<ApiState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<RuleTestBody>,
) -> Response {
    if let Err(r) = auth::require(&user, Role::Analyst) {
        return r;
    }
    let compiled = if let Some(yaml) = &body.yaml {
        match CompiledRule::compile(yaml) {
            Ok(c) => c,
            Err(e) => return bad_request(&e.to_string()),
        }
    } else {
        match load_rule_by_id(&state, &id) {
            Some(c) => c,
            None => return not_found("rule not found"),
        }
    };
    let cases: Vec<TestCase> = body
        .cases
        .iter()
        .map(|c| {
            let pairs: Vec<(&str, &str)> = c
                .fields
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            TestCase::new(
                c.name.clone(),
                event_from_fields(&c.message, &pairs),
                c.expect_match,
            )
        })
        .collect();
    let failures = run_cases(&compiled, &cases);
    Json(serde_json::json!({
        "passed": failures.is_empty(),
        "cases": body.cases.len(),
        "failures": failures,
    }))
    .into_response()
}

// --- ATT&CK coverage -------------------------------------------------------

async fn attack_coverage(State(state): State<ApiState>) -> impl IntoResponse {
    let rules = state.engine.read().unwrap().rule_infos();
    let covered: HashSet<String> = rules.iter().filter_map(|r| r.technique.clone()).collect();
    let observed: HashSet<String> = state
        .alerts
        .records(100_000, None)
        .iter()
        .filter_map(|r| r.alert.technique.clone())
        .collect();
    let mut all: Vec<String> = covered.union(&observed).cloned().collect();
    all.sort();
    let techniques: Vec<serde_json::Value> = all
        .iter()
        .map(|t| {
            serde_json::json!({
                "technique": t,
                "tactic": tactic_for(Some(t), &sigil_core::OcsfClass::Other(0)),
                "covered": covered.contains(t),
                "observed": observed.contains(t),
            })
        })
        .collect();
    Json(serde_json::json!({
        "covered": covered.len(),
        "observed": observed.len(),
        "techniques": techniques,
    }))
}

// --- saved objects ---------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SavedBody {
    #[serde(default)]
    name: Option<String>,
    body: serde_json::Value,
}

async fn saved_list(
    State(state): State<ApiState>,
    Extension(_user): Extension<AuthUser>,
    Path(kind): Path<String>,
) -> Response {
    let Some(store) = &state.store else {
        return Json(serde_json::json!({ "kind": kind, "objects": [] })).into_response();
    };
    match store.list_saved(&kind) {
        Ok(objects) => {
            Json(serde_json::json!({ "kind": kind, "objects": objects })).into_response()
        }
        Err(e) => error_response(e),
    }
}

async fn saved_create(
    State(state): State<ApiState>,
    Extension(user): Extension<AuthUser>,
    Path(kind): Path<String>,
    Json(body): Json<SavedBody>,
) -> Response {
    if let Err(r) = auth::require(&user, Role::Analyst) {
        return r;
    }
    let Some(store) = &state.store else {
        return conflict("persistence not enabled (set `data_dir`)");
    };
    let obj = SavedObject {
        kind,
        id: ulid::Ulid::new().to_string(),
        name: body.name.unwrap_or_default(),
        owner: Some(user.username),
        updated_ts: now_micros(),
        body: body.body,
    };
    match store.put_saved(&obj) {
        Ok(()) => (StatusCode::CREATED, Json(obj)).into_response(),
        Err(e) => error_response(e),
    }
}

async fn saved_update(
    State(state): State<ApiState>,
    Extension(user): Extension<AuthUser>,
    Path((kind, id)): Path<(String, String)>,
    Json(body): Json<SavedBody>,
) -> Response {
    if let Err(r) = auth::require(&user, Role::Analyst) {
        return r;
    }
    let Some(store) = &state.store else {
        return conflict("persistence not enabled (set `data_dir`)");
    };
    let obj = SavedObject {
        kind,
        id,
        name: body.name.unwrap_or_default(),
        owner: Some(user.username),
        updated_ts: now_micros(),
        body: body.body,
    };
    match store.put_saved(&obj) {
        Ok(()) => Json(obj).into_response(),
        Err(e) => error_response(e),
    }
}

async fn saved_delete(
    State(state): State<ApiState>,
    Extension(user): Extension<AuthUser>,
    Path((kind, id)): Path<(String, String)>,
) -> Response {
    if let Err(r) = auth::require(&user, Role::Analyst) {
        return r;
    }
    let Some(store) = &state.store else {
        return conflict("persistence not enabled (set `data_dir`)");
    };
    match store.delete_saved(&kind, &id) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found("saved object not found"),
        Err(e) => error_response(e),
    }
}

// --- analytics (SQL + DSL) -------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct QueryParams {
    #[serde(default)]
    pub q: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AnalyticsResponse {
    pub sql: String,
    pub columns: Vec<String>,
    pub count: usize,
    pub rows: Vec<serde_json::Value>,
}

async fn sql_handler(
    State(state): State<ApiState>,
    Query(params): Query<QueryParams>,
) -> impl IntoResponse {
    let Some(sql) = params.q.filter(|q| !q.trim().is_empty()) else {
        return bad_request("missing `q` (SQL query)");
    };
    run_analytics(&state, &sql, sql.clone()).await
}

async fn query_handler(
    State(state): State<ApiState>,
    Query(params): Query<QueryParams>,
) -> impl IntoResponse {
    let Some(dsl) = params.q.filter(|q| !q.trim().is_empty()) else {
        return bad_request("missing `q` (pipe-DSL query)");
    };
    match dsl::lower(&dsl) {
        Ok(sql) => run_analytics(&state, &sql.clone(), sql).await,
        Err(e) => bad_request(&e.to_string()),
    }
}

async fn run_analytics(state: &ApiState, sql: &str, shown: String) -> Response {
    match state.analytics.sql(sql).await {
        Ok(res) => Json(AnalyticsResponse {
            sql: shown,
            columns: res.columns,
            count: res.rows.len(),
            rows: res.rows,
        })
        .into_response(),
        Err(e) => error_response(e),
    }
}

// --- SSE -------------------------------------------------------------------

async fn stream_alerts(
    State(state): State<ApiState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, std::convert::Infallible>>> {
    let rx = state.alerts.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|r| match r {
        Ok(rec) => Some(Ok(SseEvent::default()
            .json_data(&rec)
            .unwrap_or_else(|_| SseEvent::default().data("{}")))),
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// --- EDR fleet (agents / commands / enrollment tokens) ---------------------

#[derive(Debug, Deserialize)]
struct EdrActionBody {
    #[serde(rename = "type")]
    action: String,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    hash_sha256: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    max_bytes: Option<u64>,
    #[serde(default)]
    allowlist_cidrs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct EdrTokenBody {
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EdrCommandsParams {
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// List enrolled agents + live status (any authenticated role).
async fn edr_agents(State(state): State<ApiState>) -> Response {
    let Some(edr) = &state.edr else {
        return conflict("EDR is not enabled");
    };
    match edr.registry.list() {
        Ok(agents) => Json(serde_json::json!({ "agents": agents })).into_response(),
        Err(e) => error_response(e),
    }
}

/// One agent's detail plus its recent command history.
async fn edr_agent(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    let Some(edr) = &state.edr else {
        return conflict("EDR is not enabled");
    };
    let agent = match edr.registry.get(&id) {
        Ok(Some(a)) => a,
        Ok(None) => return not_found("agent not found"),
        Err(e) => return error_response(e),
    };
    let commands = edr.queue.list(50, Some(&id)).unwrap_or_default();
    Json(serde_json::json!({ "agent": agent, "commands": commands })).into_response()
}

/// Enqueue a response action for an agent (analyst+). Delivered over the live
/// stream if connected, else queued until the agent reconnects.
async fn edr_action(
    State(state): State<ApiState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<EdrActionBody>,
) -> Response {
    if let Err(r) = auth::require(&user, Role::Analyst) {
        return r;
    }
    let Some(edr) = &state.edr else {
        return conflict("EDR is not enabled");
    };
    match edr.registry.get(&id) {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("agent not found"),
        Err(e) => return error_response(e),
    }
    let params = sigil_edr::CommandParams {
        pid: body.pid,
        hash_sha256: body.hash_sha256,
        path: body.path,
        max_bytes: body.max_bytes,
        allowlist_cidrs: body.allowlist_cidrs,
    };
    match edr
        .queue
        .enqueue(&id, &body.action, params, &user.username)
        .await
    {
        Ok(rec) => {
            tracing::info!(agent = %id, action = %body.action, by = %user.username, "EDR action queued");
            (StatusCode::ACCEPTED, Json(rec)).into_response()
        }
        Err(sigil_core::Error::Config(m)) => bad_request(&m),
        Err(e) => error_response(e),
    }
}

/// List command audit records (any authenticated role).
async fn edr_commands(
    State(state): State<ApiState>,
    Query(params): Query<EdrCommandsParams>,
) -> Response {
    let Some(edr) = &state.edr else {
        return conflict("EDR is not enabled");
    };
    let limit = params.limit.unwrap_or(100).min(1000);
    match edr.queue.list(limit, params.agent.as_deref()) {
        Ok(commands) => Json(serde_json::json!({ "commands": commands })).into_response(),
        Err(e) => error_response(e),
    }
}

/// List issued enrollment tokens (prefixes only; admin).
async fn edr_tokens(
    State(state): State<ApiState>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    if let Err(r) = auth::require(&user, Role::Admin) {
        return r;
    }
    let Some(edr) = &state.edr else {
        return conflict("EDR is not enabled");
    };
    match edr.tokens.list() {
        Ok(tokens) => Json(serde_json::json!({ "tokens": tokens })).into_response(),
        Err(e) => error_response(e),
    }
}

/// Issue a new enrollment token, returning the raw value once (admin).
async fn edr_token_create(
    State(state): State<ApiState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<EdrTokenBody>,
) -> Response {
    if let Err(r) = auth::require(&user, Role::Admin) {
        return r;
    }
    let Some(edr) = &state.edr else {
        return conflict("EDR is not enabled");
    };
    let label = body.label.unwrap_or_else(|| "api".into());
    match edr.tokens.issue(&label, Some(user.username.clone())) {
        Ok(token) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "token": token, "label": label })),
        )
            .into_response(),
        Err(e) => error_response(e),
    }
}

/// SSE stream of the agent fleet, refreshed periodically for live status.
async fn edr_stream_agents(
    State(state): State<ApiState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, std::convert::Infallible>>> {
    let edr = state.edr.clone();
    let interval = tokio::time::interval(std::time::Duration::from_secs(3));
    let stream = tokio_stream::wrappers::IntervalStream::new(interval).map(move |_| {
        let agents = edr
            .as_ref()
            .and_then(|e| e.registry.list().ok())
            .unwrap_or_default();
        Ok(SseEvent::default()
            .json_data(&agents)
            .unwrap_or_else(|_| SseEvent::default().data("[]")))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// --- OpenAPI ---------------------------------------------------------------

async fn openapi_handler() -> impl IntoResponse {
    Json(openapi_doc())
}

// --- rule-file helpers -----------------------------------------------------

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn write_rule_file(state: &ApiState, rule_id: &str, yaml: &str) -> Result<(), Response> {
    let Some(dir) = &state.rules_dir else {
        return Err(conflict("rule editing requires `sigma.rules_dir`"));
    };
    std::fs::create_dir_all(dir).map_err(|e| conflict(&format!("cannot create rules dir: {e}")))?;
    let path = dir.join(format!("{}.yml", sanitize(rule_id)));
    std::fs::write(&path, yaml).map_err(|e| conflict(&format!("cannot write rule: {e}")))?;
    Ok(())
}

fn delete_rule_file(state: &ApiState, id: &str) -> Result<bool, Response> {
    let Some(dir) = &state.rules_dir else {
        return Err(conflict("rule editing requires `sigma.rules_dir`"));
    };
    let direct = dir.join(format!("{}.yml", sanitize(id)));
    if direct.exists() {
        std::fs::remove_file(&direct).map_err(|e| conflict(&format!("cannot delete rule: {e}")))?;
        return Ok(true);
    }
    if let Some(path) = find_rule_path(dir, id) {
        std::fs::remove_file(&path).map_err(|e| conflict(&format!("cannot delete rule: {e}")))?;
        return Ok(true);
    }
    Ok(false)
}

/// Scan a rules dir for the file whose compiled `rule_id` equals `id`.
fn find_rule_path(dir: &FsPath, id: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let p = entry.path();
        if matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")) {
            if let Ok(text) = std::fs::read_to_string(&p) {
                if let Ok(c) = CompiledRule::compile(&text) {
                    if c.rule_id == id {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

fn load_rule_by_id(state: &ApiState, id: &str) -> Option<CompiledRule> {
    let dir = state.rules_dir.as_ref()?;
    let path = find_rule_path(dir, id)?;
    let text = std::fs::read_to_string(path).ok()?;
    CompiledRule::compile(&text).ok()
}

fn reload_engine(state: &ApiState) -> Result<usize, Response> {
    let Some(dir) = &state.rules_dir else {
        return Err(conflict("rule editing requires `sigma.rules_dir`"));
    };
    let (engine, report) = SigmaEngine::load_dir(dir).map_err(error_response)?;
    let n = engine.len();
    if !report.failed.is_empty() {
        tracing::warn!(failed = report.failed.len(), "some rules failed to reload");
    }
    *state.engine.write().unwrap() = engine;
    Ok(n)
}

// --- response helpers ------------------------------------------------------

fn bad_request(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

fn not_found(msg: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

fn conflict(msg: &str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

fn error_response(e: sigil_core::Error) -> Response {
    tracing::warn!(error = %e, "request failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": e.to_string() })),
    )
        .into_response()
}

/// A curated OpenAPI 3.0 description of the control surface.
fn openapi_doc() -> serde_json::Value {
    serde_json::json!({
        "openapi": "3.0.3",
        "info": { "title": "Sigil SIEM API", "version": "1" },
        "servers": [{ "url": "/api/v1" }],
        "components": {
            "securitySchemes": {
                "bearerAuth": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT" }
            }
        },
        "security": [{ "bearerAuth": [] }],
        "paths": {
            "/auth/login": { "post": { "summary": "Exchange credentials for a JWT", "security": [] } },
            "/me": { "get": { "summary": "Current user + roles" } },
            "/count": { "get": { "summary": "Event + alert counts" } },
            "/search": { "get": { "summary": "Full-text search over the hot index" } },
            "/search/fields": { "get": { "summary": "Analytical event schema" } },
            "/search/histogram": { "get": { "summary": "Time-bucketed event counts" } },
            "/alerts": {
                "get": { "summary": "Recent alert records (with triage)" },
                "patch": { "summary": "Bulk triage update (analyst)" }
            },
            "/alerts/{fp}": { "patch": { "summary": "Triage one alert (analyst)" } },
            "/incidents": { "get": { "summary": "Reconstructed incidents" } },
            "/rules": {
                "get": { "summary": "List detection rules" },
                "post": { "summary": "Create a rule (analyst)" }
            },
            "/rules/{id}": {
                "put": { "summary": "Update a rule (analyst)" },
                "delete": { "summary": "Delete a rule (analyst)" }
            },
            "/rules/{id}/test": { "post": { "summary": "Run rule test cases (analyst)" } },
            "/attack/coverage": { "get": { "summary": "ATT&CK technique coverage" } },
            "/saved/{kind}": {
                "get": { "summary": "List saved objects" },
                "post": { "summary": "Create a saved object (analyst)" }
            },
            "/saved/{kind}/{id}": {
                "put": { "summary": "Replace a saved object (analyst)" },
                "delete": { "summary": "Delete a saved object (analyst)" }
            },
            "/system": { "get": { "summary": "Node / cluster info" } },
            "/eval": { "get": { "summary": "Run the evaluation harness" } },
            "/sql": { "get": { "summary": "SQL query over the cold tier" } },
            "/query": { "get": { "summary": "Pipe-DSL query" } },
            "/stream/alerts": { "get": { "summary": "SSE stream of new alerts" } },
            "/edr/agents": { "get": { "summary": "List enrolled EDR agents + status" } },
            "/edr/agents/{id}": { "get": { "summary": "Agent detail + recent commands" } },
            "/edr/agents/{id}/actions": { "post": { "summary": "Enqueue a response action (analyst)" } },
            "/edr/commands": { "get": { "summary": "Response-command audit trail" } },
            "/edr/enroll-tokens": {
                "get": { "summary": "List enrollment tokens (admin)" },
                "post": { "summary": "Issue an enrollment token (admin)" }
            },
            "/edr/stream/agents": { "get": { "summary": "SSE stream of agent fleet status" } },
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_config::AuthConfig;

    fn test_state() -> ApiState {
        ApiState {
            index: Arc::new(EventIndex::in_memory().unwrap()),
            alerts: AlertStore::default(),
            analytics: Analytics::new("/tmp/sigil-test-cold"),
            engine: Arc::new(RwLock::new(SigmaEngine::default())),
            rules_dir: None,
            store: None,
            auth: Arc::new(AuthState::from_config(&AuthConfig::default())),
            system: Arc::new(SystemInfo::default()),
            metrics: None,
            edr: None,
        }
    }

    #[test]
    fn alert_store_caps_and_orders() {
        let store = AlertStore::new(2);
        for i in 0..3 {
            store.push(Alert {
                rule_id: format!("r{i}"),
                ..Default::default()
            });
        }
        assert_eq!(store.len(), 2); // oldest evicted
        let recent = store.recent(10, None);
        assert_eq!(recent[0].rule_id, "r2"); // newest first
        assert_eq!(recent[1].rule_id, "r1");
    }

    #[test]
    fn alert_store_filters_by_technique() {
        let store = AlertStore::new(10);
        store.push(Alert {
            rule_id: "a".into(),
            technique: Some("T1110".into()),
            ..Default::default()
        });
        store.push(Alert {
            rule_id: "b".into(),
            technique: Some("T1003".into()),
            ..Default::default()
        });
        let only = store.records(10, Some("T1110"));
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].alert.rule_id, "a");
    }

    #[tokio::test]
    async fn router_builds() {
        let _router = router(test_state());
    }

    #[test]
    fn openapi_lists_login() {
        let doc = openapi_doc();
        assert!(doc["paths"]["/auth/login"].is_object());
    }

    #[test]
    fn ui_html_is_embedded() {
        assert!(UI_HTML.contains("Sigil SIEM"));
        assert!(UI_HTML.contains("<svg"));
    }
}
