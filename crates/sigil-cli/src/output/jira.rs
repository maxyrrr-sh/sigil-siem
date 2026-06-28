//! Jira issue-creation alert sink (DESIGN §8).
//!
//! Creates one issue per *rule* (deduplicated in-process by `rule_id`) so a
//! noisy detector doesn't open a ticket per event.

use std::collections::HashSet;
use std::sync::Mutex;

use sigil_config::JiraOutput;
use sigil_core::Alert;

use super::{alert_title, log_result, severity_label, OutputSink};

const DEFAULT_ISSUE_TYPE: &str = "Task";

pub struct JiraSink {
    cfg: JiraOutput,
    issue_type: String,
    seen: Mutex<HashSet<String>>,
}

impl JiraSink {
    pub fn new(cfg: JiraOutput) -> Self {
        let issue_type = cfg
            .issue_type
            .clone()
            .unwrap_or_else(|| DEFAULT_ISSUE_TYPE.to_string());
        JiraSink {
            cfg,
            issue_type,
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// `true` the first time a rule id is seen; suppresses later duplicates.
    fn first_for_rule(&self, rule_id: &str) -> bool {
        let mut seen = self.seen.lock().unwrap();
        seen.insert(rule_id.to_string())
    }
}

#[async_trait::async_trait]
impl OutputSink for JiraSink {
    fn name(&self) -> &'static str {
        "jira"
    }

    async fn emit(&self, alert: &Alert, http: &reqwest::Client) {
        if !self.first_for_rule(&alert.rule_id) {
            return; // already ticketed this rule
        }
        let url = format!("{}/rest/api/2/issue", self.cfg.url.trim_end_matches('/'));
        let body = body(&self.cfg.project, &self.issue_type, alert);
        log_result(
            self.name(),
            http.post(&url)
                .basic_auth(&self.cfg.user, Some(&self.cfg.token))
                .json(&body)
                .send()
                .await,
        );
    }
}

/// Build the Jira issue-creation payload (pure; unit-tested).
fn body(project: &str, issue_type: &str, alert: &Alert) -> serde_json::Value {
    let description = format!(
        "Sigil alert from rule `{}` (severity {}){}.\nEvents: {}",
        alert.rule_id,
        severity_label(alert.severity),
        alert
            .technique
            .as_deref()
            .map(|t| format!(", ATT&CK {t}"))
            .unwrap_or_default(),
        alert.events.join(", "),
    );
    serde_json::json!({
        "fields": {
            "project": { "key": project },
            "summary": format!("[Sigil] {}", alert_title(alert)),
            "description": description,
            "issuetype": { "name": issue_type }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::Severity;

    fn cfg() -> JiraOutput {
        JiraOutput {
            url: "https://org.atlassian.net".into(),
            project: "SEC".into(),
            user: "bot@org".into(),
            token: "t".into(),
            issue_type: None,
        }
    }

    #[test]
    fn body_targets_project_and_issue_type() {
        let alert = Alert {
            rule_id: "r1".into(),
            title: "Bad thing".into(),
            severity: Severity::High,
            ..Default::default()
        };
        let b = body("SEC", "Task", &alert);
        assert_eq!(b["fields"]["project"]["key"], "SEC");
        assert_eq!(b["fields"]["issuetype"]["name"], "Task");
        assert_eq!(b["fields"]["summary"], "[Sigil] Bad thing");
    }

    #[test]
    fn dedups_by_rule_id() {
        let sink = JiraSink::new(cfg());
        assert!(sink.first_for_rule("r1"));
        assert!(!sink.first_for_rule("r1"));
        assert!(sink.first_for_rule("r2"));
    }
}
