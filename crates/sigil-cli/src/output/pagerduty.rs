//! PagerDuty Events API v2 alert sink (DESIGN §8).

use sigil_config::PagerDutyOutput;
use sigil_core::{Alert, Severity};

use super::{alert_title, log_result, OutputSink};

const DEFAULT_URL: &str = "https://events.pagerduty.com/v2/enqueue";

/// Triggers a PagerDuty incident per alert, deduplicated by rule id.
pub struct PagerDutySink {
    routing_key: String,
    url: String,
}

impl PagerDutySink {
    pub fn new(cfg: PagerDutyOutput) -> Self {
        PagerDutySink {
            routing_key: cfg.routing_key,
            url: cfg.url.unwrap_or_else(|| DEFAULT_URL.to_string()),
        }
    }
}

#[async_trait::async_trait]
impl OutputSink for PagerDutySink {
    fn name(&self) -> &'static str {
        "pagerduty"
    }

    async fn emit(&self, alert: &Alert, http: &reqwest::Client) {
        let body = body(&self.routing_key, alert);
        log_result(self.name(), http.post(&self.url).json(&body).send().await);
    }
}

/// Map Sigil severity onto PagerDuty's `critical|error|warning|info`.
fn pd_severity(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::Fatal => "critical",
        Severity::High => "error",
        Severity::Medium => "warning",
        _ => "info",
    }
}

/// Build the Events API v2 enqueue payload (pure; unit-tested).
fn body(routing_key: &str, alert: &Alert) -> serde_json::Value {
    serde_json::json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": alert.rule_id,
        "payload": {
            "summary": alert_title(alert),
            "severity": pd_severity(alert.severity),
            "source": "sigil",
            "custom_details": {
                "rule_id": alert.rule_id,
                "technique": alert.technique,
                "events": alert.events,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_severity_and_sets_dedup_key() {
        let alert = Alert {
            rule_id: "sudo_to_root".into(),
            title: "Sudo to root".into(),
            severity: Severity::Critical,
            ..Default::default()
        };
        let b = body("RK", &alert);
        assert_eq!(b["routing_key"], "RK");
        assert_eq!(b["event_action"], "trigger");
        assert_eq!(b["dedup_key"], "sudo_to_root");
        assert_eq!(b["payload"]["severity"], "critical");
        assert_eq!(b["payload"]["summary"], "Sudo to root");
    }

    #[test]
    fn low_severity_maps_to_info() {
        assert_eq!(pd_severity(Severity::Low), "info");
        assert_eq!(pd_severity(Severity::High), "error");
        assert_eq!(pd_severity(Severity::Medium), "warning");
    }
}
