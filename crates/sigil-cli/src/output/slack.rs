//! Slack / Mattermost incoming-webhook alert sink (DESIGN §8).

use sigil_core::Alert;

use super::{alert_title, log_result, severity_label, OutputSink};

/// Posts a compact one-line alert to a Slack-compatible incoming webhook.
pub struct SlackSink {
    url: String,
}

impl SlackSink {
    pub fn new(url: String) -> Self {
        SlackSink { url }
    }
}

#[async_trait::async_trait]
impl OutputSink for SlackSink {
    fn name(&self) -> &'static str {
        "slack"
    }

    async fn emit(&self, alert: &Alert, http: &reqwest::Client) {
        let body = body(alert);
        log_result(self.name(), http.post(&self.url).json(&body).send().await);
    }
}

/// Build the Slack message payload for an alert (pure; unit-tested).
fn body(alert: &Alert) -> serde_json::Value {
    let technique = alert
        .technique
        .as_deref()
        .map(|t| format!(" · ATT&CK {t}"))
        .unwrap_or_default();
    let text = format!(
        ":rotating_light: *{}* [{}] — rule `{}`{}",
        alert_title(alert),
        severity_label(alert.severity),
        alert.rule_id,
        technique,
    );
    serde_json::json!({ "text": text })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::Severity;

    #[test]
    fn body_includes_title_severity_and_technique() {
        let alert = Alert {
            rule_id: "ssh_bruteforce".into(),
            title: "SSH brute force".into(),
            severity: Severity::High,
            technique: Some("T1110.001".into()),
            ..Default::default()
        };
        let text = body(&alert)["text"].as_str().unwrap().to_string();
        assert!(text.contains("SSH brute force"));
        assert!(text.contains("[high]"));
        assert!(text.contains("ssh_bruteforce"));
        assert!(text.contains("T1110.001"));
    }

    #[test]
    fn body_falls_back_to_rule_id_when_title_empty() {
        let alert = Alert {
            rule_id: "r1".into(),
            ..Default::default()
        };
        let text = body(&alert)["text"].as_str().unwrap().to_string();
        assert!(text.contains("*r1*"));
    }
}
