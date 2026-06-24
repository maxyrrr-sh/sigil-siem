//! `sigil-api` — query API (DESIGN §16/§17).
//!
//! Phase 0 exposed read-only search over the hot index. Phase 1 adds an alert
//! surface: a shared [`AlertStore`] that the Sigma path writes to and a
//! `GET /alerts` endpoint. The richer query language (SQL + pipe-DSL) arrives
//! in Phase 2.

pub mod dsl;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sigil_core::{Alert, Event};
use sigil_correlate::{
    build_campaigns, build_incident, BeamSearchSelector, CampaignConfig, CausalConfig,
    HashingEmbedder, Incident,
};
use sigil_index::{Analytics, EventIndex, SearchQuery};

/// A bounded, in-memory ring of recent alerts, shared between the detection
/// path (writer) and the API (reader). Newest alerts are returned first.
#[derive(Clone)]
pub struct AlertStore {
    inner: Arc<Mutex<VecDeque<Alert>>>,
    cap: usize,
}

impl AlertStore {
    pub fn new(cap: usize) -> Self {
        AlertStore {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            cap: cap.max(1),
        }
    }

    /// Record an alert, evicting the oldest if at capacity.
    pub fn push(&self, alert: Alert) {
        let mut q = self.inner.lock().unwrap();
        if q.len() == self.cap {
            q.pop_front();
        }
        q.push_back(alert);
    }

    /// Total alerts currently retained.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Most recent alerts (newest first), optionally filtered by technique.
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
}

impl Default for AlertStore {
    fn default() -> Self {
        AlertStore::new(10_000)
    }
}

/// Shared application state handed to every handler.
#[derive(Clone)]
pub struct ApiState {
    pub index: Arc<EventIndex>,
    pub alerts: AlertStore,
    pub analytics: Analytics,
}

/// Build the API router over a shared index, alert store, and analytics engine.
pub fn router(index: Arc<EventIndex>, alerts: AlertStore, analytics: Analytics) -> Router {
    Router::new()
        .route("/", get(ui))
        .route("/ui", get(ui))
        .route("/health", get(health))
        .route("/count", get(count))
        .route("/search", get(search))
        .route("/alerts", get(alerts_handler))
        .route("/incidents", get(incidents_handler))
        .route("/sql", get(sql_handler))
        .route("/query", get(query_handler))
        .with_state(ApiState {
            index,
            alerts,
            analytics,
        })
}

/// Bind `addr` and serve the API until the process exits.
pub async fn serve(
    addr: &str,
    index: Arc<EventIndex>,
    alerts: AlertStore,
    analytics: Analytics,
) -> sigil_core::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| sigil_core::Error::Io(format!("bind api {addr}: {e}")))?;
    tracing::info!(%addr, "query API listening");
    axum::serve(listener, router(index, alerts, analytics))
        .await
        .map_err(|e| sigil_core::Error::Io(format!("api serve: {e}")))
}

/// The single-page triage + attack-graph UI (DESIGN §6 Phase 6). A thin,
/// dependency-free scaffold: live alert/event counts + alert list from the API,
/// plus an SVG attack-graph rendering.
async fn ui() -> Html<&'static str> {
    Html(UI_HTML)
}

const UI_HTML: &str = include_str!("ui.html");

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn count(State(state): State<ApiState>) -> impl IntoResponse {
    match state.index.count() {
        Ok(n) => {
            Json(serde_json::json!({ "events": n, "alerts": state.alerts.len() })).into_response()
        }
        Err(e) => error_response(e),
    }
}

/// `GET /search` query parameters.
#[derive(Debug, Deserialize)]
pub struct SearchParams {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `GET /search` response body.
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

/// `GET /alerts` query parameters.
#[derive(Debug, Deserialize)]
pub struct AlertParams {
    #[serde(default)]
    pub technique: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `GET /alerts` response body.
#[derive(Debug, Serialize)]
pub struct AlertsResponse {
    pub count: usize,
    pub alerts: Vec<Alert>,
}

async fn alerts_handler(
    State(state): State<ApiState>,
    Query(params): Query<AlertParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).clamp(1, 1000);
    let alerts = state.alerts.recent(limit, params.technique.as_deref());
    Json(AlertsResponse {
        count: alerts.len(),
        alerts,
    })
}

/// `GET /incidents` response body.
#[derive(Debug, Serialize)]
pub struct IncidentsResponse {
    pub count: usize,
    pub incidents: Vec<Incident>,
}

/// Reconstruct incidents on demand: pull recent events from the hot index, run
/// cross-domain correlation (DESIGN §9), and enrich the kill-chain with ATT&CK
/// techniques from the alert store. (A persisted incident store is future work.)
async fn incidents_handler(State(state): State<ApiState>) -> impl IntoResponse {
    let events = match state.index.search(&SearchQuery::new("", 5000)) {
        Ok(e) => e,
        Err(e) => return error_response(e),
    };

    // event_id → ATT&CK technique, from any alert that fired on it.
    let mut techniques = std::collections::HashMap::new();
    for alert in state.alerts.recent(100_000, None) {
        if let Some(t) = alert.technique {
            for ev in alert.events {
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

/// `GET /sql` and `GET /query` parameters.
#[derive(Debug, Deserialize)]
pub struct QueryParams {
    #[serde(default)]
    pub q: Option<String>,
}

/// Response body for analytical queries.
#[derive(Debug, Serialize)]
pub struct AnalyticsResponse {
    /// The SQL actually executed (after DSL lowering, if any).
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

async fn run_analytics(state: &ApiState, sql: &str, shown: String) -> axum::response::Response {
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

fn bad_request(msg: &str) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

fn error_response(e: sigil_core::Error) -> axum::response::Response {
    tracing::warn!(error = %e, "request failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": e.to_string() })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let only = store.recent(10, Some("T1110"));
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].rule_id, "a");
    }

    #[tokio::test]
    async fn router_builds() {
        let idx = Arc::new(EventIndex::in_memory().unwrap());
        let _router = router(
            idx,
            AlertStore::default(),
            Analytics::new("/tmp/sigil-test-cold"),
        );
    }

    #[test]
    fn ui_html_is_embedded() {
        assert!(UI_HTML.contains("Sigil SIEM"));
        assert!(UI_HTML.contains("<svg"));
    }
}
