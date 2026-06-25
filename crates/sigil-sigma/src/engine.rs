//! Compile Sigma rules into evaluable predicates and run them over events
//! (DESIGN §8 streaming backend). Each match yields an [`Alert`] carrying the
//! rule's severity and ATT&CK technique tag.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sigil_core::{now_micros, Alert, Error, Event, Result, Severity};

use crate::condition::{self, Expr};
use crate::matcher::{event_haystack, FieldCond, Modifiers, Selection, StringPredicate};
use crate::rule::SigmaRule;

/// Lightweight, serializable metadata about a loaded rule (API/UI surface).
#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub technique: Option<String>,
    pub tags: Vec<String>,
}

/// A compiled, ready-to-evaluate Sigma rule.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    /// First ATT&CK technique from `tags` (e.g. `T1110`), if any.
    pub technique: Option<String>,
    pub tags: Vec<String>,
    selections: HashMap<String, Selection>,
    names: Vec<String>,
    condition: Expr,
}

impl CompiledRule {
    /// Compile a single rule from YAML text.
    pub fn compile(yaml: &str) -> Result<CompiledRule> {
        let rule: SigmaRule = serde_yaml::from_str(yaml)
            .map_err(|e| Error::Config(format!("parsing Sigma rule: {e}")))?;
        Self::from_rule(rule)
    }

    /// Compile from an already-parsed [`SigmaRule`].
    pub fn from_rule(rule: SigmaRule) -> Result<CompiledRule> {
        let mut selections = HashMap::new();
        let mut condition_str: Option<String> = None;

        for (k, v) in &rule.detection {
            let key = k
                .as_str()
                .ok_or_else(|| Error::Config("detection key must be a string".into()))?;
            if key == "condition" {
                condition_str = Some(condition_to_string(v)?);
                continue;
            }
            selections.insert(key.to_string(), compile_selection(v)?);
        }

        let condition_str = condition_str
            .ok_or_else(|| Error::Config(format!("rule `{}` has no condition", rule.title)))?;
        let condition = condition::parse(&condition_str)?;
        let names: Vec<String> = selections.keys().cloned().collect();

        let rule_id = rule.id.clone().unwrap_or_else(|| rule.title.clone());
        Ok(CompiledRule {
            severity: level_to_severity(rule.level.as_deref()),
            technique: technique_from_tags(&rule.tags),
            tags: rule.tags,
            rule_id,
            title: rule.title,
            selections,
            names,
            condition,
        })
    }

    /// Does this rule match the event?
    pub fn matches(&self, event: &Event) -> bool {
        let haystack = event_haystack(event);
        let results: HashMap<String, bool> = self
            .selections
            .iter()
            .map(|(name, sel)| (name.clone(), sel.eval(event, &haystack)))
            .collect();
        condition::eval(&self.condition, &results, &self.names)
    }

    /// Produce an alert for a matching event.
    pub fn to_alert(&self, event: &Event) -> Alert {
        Alert {
            rule_id: self.rule_id.clone(),
            title: self.title.clone(),
            severity: self.severity,
            technique: self.technique.clone(),
            events: vec![event.id.clone()],
            ts: if event.ts != 0 {
                event.ts
            } else {
                now_micros()
            },
        }
    }
}

/// Outcome of loading a rulepack directory.
#[derive(Debug, Default)]
pub struct LoadReport {
    pub loaded: usize,
    /// `(path, error message)` for rules that failed to compile.
    pub failed: Vec<(PathBuf, String)>,
}

/// A set of compiled rules evaluated as a unit (DESIGN §8 rulepack).
#[derive(Debug, Default, Clone)]
pub struct SigmaEngine {
    rules: Vec<CompiledRule>,
}

impl SigmaEngine {
    pub fn new(rules: Vec<CompiledRule>) -> Self {
        SigmaEngine { rules }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Lightweight metadata for every loaded rule (for the API / UI).
    pub fn rule_infos(&self) -> Vec<RuleInfo> {
        self.rules
            .iter()
            .map(|r| RuleInfo {
                rule_id: r.rule_id.clone(),
                title: r.title.clone(),
                severity: r.severity,
                technique: r.technique.clone(),
                tags: r.tags.clone(),
            })
            .collect()
    }

    /// Load every `*.yml` / `*.yaml` rule under `dir` (recursively). Individual
    /// failures are collected in the report rather than aborting the load.
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<(SigmaEngine, LoadReport)> {
        let dir = dir.as_ref();
        let mut rules = Vec::new();
        let mut report = LoadReport::default();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(path) = stack.pop() {
            let entries = std::fs::read_dir(&path)
                .map_err(|e| Error::Io(format!("reading rules dir {}: {e}", path.display())))?;
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")) {
                    match std::fs::read_to_string(&p)
                        .map_err(|e| Error::Io(e.to_string()))
                        .and_then(|t| CompiledRule::compile(&t))
                    {
                        Ok(rule) => {
                            rules.push(rule);
                            report.loaded += 1;
                        }
                        Err(e) => report.failed.push((p, e.to_string())),
                    }
                }
            }
        }
        Ok((SigmaEngine::new(rules), report))
    }

    /// Evaluate every rule against one event, returning all alerts.
    pub fn eval(&self, event: &Event) -> Vec<Alert> {
        self.rules
            .iter()
            .filter(|r| r.matches(event))
            .map(|r| r.to_alert(event))
            .collect()
    }
}

// --- compilation helpers ---------------------------------------------------

fn compile_selection(value: &serde_yaml::Value) -> Result<Selection> {
    use serde_yaml::Value;
    match value {
        Value::Mapping(map) => compile_field_map(map),
        Value::Sequence(seq) => {
            if seq.iter().any(|v| v.is_mapping()) {
                let items = seq
                    .iter()
                    .map(|v| match v {
                        Value::Mapping(m) => compile_field_map(m),
                        other => Ok(Selection::Keywords(vec![keyword_pred(other)?])),
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(Selection::AnyOf(items))
            } else {
                let preds = seq.iter().map(keyword_pred).collect::<Result<Vec<_>>>()?;
                Ok(Selection::Keywords(preds))
            }
        }
        other => Ok(Selection::Keywords(vec![keyword_pred(other)?])),
    }
}

fn compile_field_map(map: &serde_yaml::Mapping) -> Result<Selection> {
    let mut conds = Vec::new();
    for (k, v) in map {
        let key = k
            .as_str()
            .ok_or_else(|| Error::Config("field key must be a string".into()))?;
        let (field, mods) = Modifiers::parse(key)?;
        let preds = build_preds(v, &mods)?;
        conds.push(FieldCond {
            field,
            all: mods.all,
            preds,
        });
    }
    Ok(Selection::Fields(conds))
}

fn build_preds(value: &serde_yaml::Value, mods: &Modifiers) -> Result<Vec<StringPredicate>> {
    use serde_yaml::Value;
    match value {
        Value::Sequence(seq) => seq
            .iter()
            .map(|v| StringPredicate::build(scalar_str(v).as_deref(), mods))
            .collect(),
        Value::Null => Ok(vec![StringPredicate::IsNull]),
        other => Ok(vec![StringPredicate::build(
            scalar_str(other).as_deref(),
            mods,
        )?]),
    }
}

fn keyword_pred(value: &serde_yaml::Value) -> Result<StringPredicate> {
    let s = scalar_str(value).unwrap_or_default();
    Ok(StringPredicate::Contains(s.to_lowercase()))
}

/// Render a YAML scalar as a string; `None` for null.
fn scalar_str(v: &serde_yaml::Value) -> Option<String> {
    use serde_yaml::Value;
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        other => serde_yaml::to_string(other)
            .ok()
            .map(|s| s.trim().to_string()),
    }
}

fn condition_to_string(v: &serde_yaml::Value) -> Result<String> {
    use serde_yaml::Value;
    match v {
        Value::String(s) => Ok(s.clone()),
        // A list of conditions: OR them together (each must be a string).
        Value::Sequence(seq) => {
            let parts: Vec<String> = seq
                .iter()
                .filter_map(|x| x.as_str().map(|s| format!("({s})")))
                .collect();
            if parts.is_empty() {
                Err(Error::Config(
                    "condition list is empty or non-string".into(),
                ))
            } else {
                Ok(parts.join(" or "))
            }
        }
        _ => Err(Error::Config(
            "condition must be a string or list of strings".into(),
        )),
    }
}

fn level_to_severity(level: Option<&str>) -> Severity {
    match level.map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("informational") => Severity::Informational,
        Some("low") => Severity::Low,
        Some("medium") => Severity::Medium,
        Some("high") => Severity::High,
        Some("critical") => Severity::Critical,
        _ => Severity::Medium,
    }
}

/// Extract the first ATT&CK technique tag (`attack.t1110` → `T1110`).
fn technique_from_tags(tags: &[String]) -> Option<String> {
    for tag in tags {
        let lower = tag.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("attack.t") {
            if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return Some(format!("T{}", rest.to_uppercase()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::{EntityRef, OcsfClass};

    fn ssh_event(message: &str) -> Event {
        let mut ev = Event::new("acme");
        ev.message = message.into();
        ev.ocsf_class = OcsfClass::Authentication;
        ev.actor = Some(EntityRef::new("user", "admin"));
        ev.fields.insert("app".into(), "sshd".into());
        ev
    }

    const SSH_RULE: &str = r#"
title: SSH Failed Password
id: rule-ssh-failed
level: medium
logsource: { product: linux, service: sshd }
detection:
  selection:
    app: sshd
    message|contains: 'Failed password'
  condition: selection
tags:
  - attack.credential_access
  - attack.t1110
"#;

    #[test]
    fn compiles_and_matches() {
        let rule = CompiledRule::compile(SSH_RULE).unwrap();
        assert_eq!(rule.technique.as_deref(), Some("T1110"));
        assert_eq!(rule.severity, Severity::Medium);
        assert!(rule.matches(&ssh_event(
            "Failed password for invalid user admin from 10.0.0.9"
        )));
        assert!(!rule.matches(&ssh_event("Accepted password for alice")));
    }

    #[test]
    fn alert_carries_technique_and_event_id() {
        let rule = CompiledRule::compile(SSH_RULE).unwrap();
        let ev = ssh_event("Failed password for root");
        let alert = rule.to_alert(&ev);
        assert_eq!(alert.rule_id, "rule-ssh-failed");
        assert_eq!(alert.technique.as_deref(), Some("T1110"));
        assert_eq!(alert.events, vec![ev.id]);
    }

    #[test]
    fn keyword_selection_matches_message() {
        let yaml = r#"
title: Shadow read
detection:
  keywords:
    - '/etc/shadow'
  condition: keywords
tags: [attack.t1003]
"#;
        let rule = CompiledRule::compile(yaml).unwrap();
        let mut ev = Event::new("acme");
        ev.message = "USER=root ; COMMAND=/bin/cat /etc/shadow".into();
        assert!(rule.matches(&ev));
    }

    #[test]
    fn condition_and_not() {
        let yaml = r#"
title: Failed but not from allowlisted host
detection:
  selection:
    message|contains: 'Failed password'
  filter:
    host: trusted01
  condition: selection and not filter
"#;
        let rule = CompiledRule::compile(yaml).unwrap();
        let mut ev = ssh_event("Failed password for x");
        ev.host = Some(EntityRef::new("host", "web01"));
        assert!(rule.matches(&ev));
        ev.host = Some(EntityRef::new("host", "trusted01"));
        assert!(!rule.matches(&ev));
    }
}
