//! MISP event-push alert sink (DESIGN §8): share alerts (and any IOCs the
//! enrichment chain stamped on them) back to a MISP instance.

use sigil_config::MispOutput;
use sigil_core::Alert;

use super::{alert_title, log_result, OutputSink};

pub struct MispSink {
    cfg: MispOutput,
}

impl MispSink {
    pub fn new(cfg: MispOutput) -> Self {
        MispSink { cfg }
    }
}

#[async_trait::async_trait]
impl OutputSink for MispSink {
    fn name(&self) -> &'static str {
        "misp"
    }

    async fn emit(&self, alert: &Alert, http: &reqwest::Client) {
        let url = format!("{}/events/add", self.cfg.url.trim_end_matches('/'));
        let body = body(alert);
        log_result(
            self.name(),
            http.post(&url)
                .header("Authorization", &self.cfg.api_key)
                .header("Accept", "application/json")
                .json(&body)
                .send()
                .await,
        );
    }
}

/// Build a minimal MISP Event payload. ATT&CK technique becomes a galaxy-style
/// tag; the triggering event ids become `comment` attributes (pure; tested).
fn body(alert: &Alert) -> serde_json::Value {
    let mut tags = vec![serde_json::json!({ "name": format!("sigil:rule=\"{}\"", alert.rule_id) })];
    if let Some(t) = &alert.technique {
        tags.push(serde_json::json!({
            "name": format!("misp-galaxy:mitre-attack-pattern=\"{t}\"")
        }));
    }
    let attributes: Vec<serde_json::Value> = alert
        .events
        .iter()
        .map(|e| {
            serde_json::json!({
                "type": "comment",
                "category": "Other",
                "value": e,
            })
        })
        .collect();
    serde_json::json!({
        "Event": {
            "info": format!("[Sigil] {}", alert_title(alert)),
            "Tag": tags,
            "Attribute": attributes,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_tags_rule_and_technique() {
        let alert = Alert {
            rule_id: "shadow_access".into(),
            title: "Shadow file access".into(),
            technique: Some("T1003.008".into()),
            events: vec!["01H".into(), "01J".into()],
            ..Default::default()
        };
        let b = body(&alert);
        assert_eq!(b["Event"]["info"], "[Sigil] Shadow file access");
        let tags = b["Event"]["Tag"].as_array().unwrap();
        assert!(tags
            .iter()
            .any(|t| t["name"].as_str().unwrap().contains("sigil:rule")));
        assert!(tags
            .iter()
            .any(|t| t["name"].as_str().unwrap().contains("T1003.008")));
        assert_eq!(b["Event"]["Attribute"].as_array().unwrap().len(), 2);
    }
}
