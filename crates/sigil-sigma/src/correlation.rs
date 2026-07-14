//! Sigma *correlation* rules (DESIGN §8, Sigma meta-rules v2).
//!
//! A correlation rule aggregates matches of base detection rules over a
//! sliding time window instead of matching single events:
//!
//! ```yaml
//! title: Many failed logins per user
//! correlation:
//!   type: event_count            # event_count | value_count | temporal | temporal_ordered
//!   rules: [rule-ssh-failed]     # base rule ids (or titles)
//!   group-by: [actor.name]
//!   timespan: 10m
//!   condition: { gte: 10 }
//! ```
//!
//! `value_count` counts *distinct* values of `condition.field` per group;
//! `temporal` fires when every referenced rule matched within the window for
//! the same group; `temporal_ordered` additionally requires the listed order.
//! Per the Sigma spec, base alerts of referenced rules are suppressed unless
//! the correlation rule sets `generate: true` — callers filter via
//! [`CorrelationEngine::suppressed`]. After a group fires, its window is
//! cleared so one burst yields one alert instead of one per further event.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sigil_core::{Alert, Error, Event, Result, Severity, Timestamp};

use crate::engine::LoadReport;
use crate::matcher::resolve_field;

/// A correlation rule as parsed from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct CorrelationRule {
    pub title: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub correlation: CorrelationSpec,
}

/// The `correlation:` block.
#[derive(Debug, Clone, Deserialize)]
pub struct CorrelationSpec {
    #[serde(rename = "type")]
    pub kind: CorrelationKind,
    /// Base rule ids (or titles) whose alerts feed this correlation.
    pub rules: Vec<String>,
    /// Fields whose values partition the stream (empty = one global group).
    #[serde(default, alias = "group_by", rename = "group-by")]
    pub group_by: Vec<String>,
    /// Window length, e.g. `30s`, `10m`, `1h`, `7d`.
    pub timespan: String,
    /// Threshold for count kinds; ignored for temporal kinds.
    #[serde(default)]
    pub condition: Option<CountCondition>,
    /// Emit base-rule alerts too (default: suppress them).
    #[serde(default)]
    pub generate: bool,
}

/// Correlation kinds from the Sigma meta-rule spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationKind {
    EventCount,
    ValueCount,
    Temporal,
    TemporalOrdered,
}

/// `condition:` of a count correlation — one or more comparisons, all of which
/// must hold, plus the distinct-value `field` for `value_count`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CountCondition {
    /// Field whose distinct values are counted (`value_count` only).
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub gt: Option<u64>,
    #[serde(default)]
    pub gte: Option<u64>,
    #[serde(default)]
    pub lt: Option<u64>,
    #[serde(default)]
    pub lte: Option<u64>,
    #[serde(default)]
    pub eq: Option<u64>,
}

impl CountCondition {
    /// Does `n` satisfy every present comparison?
    // `map_or(true, ..)` not `is_none_or` (1.82): MSRV 1.75.
    #[allow(clippy::unnecessary_map_or)]
    pub fn satisfied(&self, n: u64) -> bool {
        self.gt.map_or(true, |v| n > v)
            && self.gte.map_or(true, |v| n >= v)
            && self.lt.map_or(true, |v| n < v)
            && self.lte.map_or(true, |v| n <= v)
            && self.eq.map_or(true, |v| n == v)
    }

    fn is_vacuous(&self) -> bool {
        self.gt.is_none()
            && self.gte.is_none()
            && self.lt.is_none()
            && self.lte.is_none()
            && self.eq.is_none()
    }
}

/// Parse a Sigma timespan (`30s`, `10m`, `6h`, `7d`) into micros.
pub fn parse_timespan(s: &str) -> Result<i64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i64 = num
        .parse()
        .map_err(|_| Error::Config(format!("invalid timespan `{s}`")))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return Err(Error::Config(format!("invalid timespan unit in `{s}`"))),
    };
    if secs <= 0 {
        return Err(Error::Config(format!("timespan `{s}` must be positive")));
    }
    Ok(secs * 1_000_000)
}

/// A compiled, ready-to-evaluate correlation rule.
#[derive(Debug, Clone)]
pub struct CompiledCorrelation {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub technique: Option<String>,
    pub tags: Vec<String>,
    kind: CorrelationKind,
    rules: Vec<String>,
    group_by: Vec<String>,
    timespan: i64,
    condition: CountCondition,
    generate: bool,
}

impl CompiledCorrelation {
    /// Compile a single correlation rule from YAML text.
    pub fn compile(yaml: &str) -> Result<CompiledCorrelation> {
        let rule: CorrelationRule = serde_yaml::from_str(yaml)
            .map_err(|e| Error::Config(format!("parsing correlation rule: {e}")))?;
        Self::from_rule(rule)
    }

    /// Compile from an already-parsed [`CorrelationRule`].
    pub fn from_rule(rule: CorrelationRule) -> Result<CompiledCorrelation> {
        let spec = rule.correlation;
        if spec.rules.is_empty() {
            return Err(Error::Config(format!(
                "correlation `{}` references no rules",
                rule.title
            )));
        }
        let condition = spec.condition.unwrap_or_default();
        match spec.kind {
            CorrelationKind::EventCount if condition.is_vacuous() => {
                return Err(Error::Config(format!(
                    "event_count correlation `{}` needs a condition (gt/gte/lt/lte/eq)",
                    rule.title
                )));
            }
            CorrelationKind::ValueCount if condition.field.is_none() => {
                return Err(Error::Config(format!(
                    "value_count correlation `{}` needs condition.field",
                    rule.title
                )));
            }
            _ => {}
        }
        let timespan = parse_timespan(&spec.timespan)?;
        let rule_id = rule.id.clone().unwrap_or_else(|| rule.title.clone());
        Ok(CompiledCorrelation {
            severity: crate::engine::level_to_severity(rule.level.as_deref()),
            technique: crate::engine::technique_from_tags(&rule.tags),
            tags: rule.tags,
            rule_id,
            title: rule.title,
            kind: spec.kind,
            rules: spec.rules,
            group_by: spec.group_by,
            timespan,
            condition,
            generate: spec.generate,
        })
    }

    /// The group key for an event: group-by field values joined stably.
    fn group_key(&self, event: &Event) -> String {
        self.group_by
            .iter()
            .map(|f| {
                let mut vals = resolve_field(event, f);
                vals.sort();
                vals.join(",")
            })
            .collect::<Vec<_>>()
            .join("\u{1f}")
    }
}

/// One base-rule match remembered inside a sliding window.
#[derive(Debug, Clone)]
struct WindowEntry {
    ts: Timestamp,
    rule_id: String,
    event_id: String,
    /// The `condition.field` value (`value_count` only).
    value: Option<String>,
}

/// Evaluates a set of correlation rules over the live alert stream.
#[derive(Debug, Default)]
pub struct CorrelationEngine {
    rules: Vec<CompiledCorrelation>,
    /// Per-rule sliding windows, keyed by group.
    windows: Vec<HashMap<String, VecDeque<WindowEntry>>>,
    /// Base rule ids referenced by a non-`generate` correlation.
    suppressed: HashSet<String>,
}

impl CorrelationEngine {
    pub fn new(rules: Vec<CompiledCorrelation>) -> Self {
        let suppressed = rules
            .iter()
            .filter(|r| !r.generate)
            .flat_map(|r| r.rules.iter().cloned())
            .collect();
        let windows = rules.iter().map(|_| HashMap::new()).collect();
        CorrelationEngine {
            rules,
            windows,
            suppressed,
        }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Should this base alert be dropped from the outputs? True when a
    /// correlation references its rule without `generate: true`.
    pub fn suppressed(&self, base_rule_id: &str) -> bool {
        self.suppressed.contains(base_rule_id)
    }

    /// Load every correlation rule (`correlation:` docs) under `dir`,
    /// recursively; plain detection rules are ignored here (and vice versa in
    /// [`crate::SigmaEngine::load_dir`]).
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<(CorrelationEngine, LoadReport)> {
        let mut rules = Vec::new();
        let mut report = LoadReport::default();
        for (path, text) in yaml_files(dir.as_ref())? {
            if !is_correlation_doc(&text) {
                continue;
            }
            match CompiledCorrelation::compile(&text) {
                Ok(rule) => {
                    rules.push(rule);
                    report.loaded += 1;
                }
                Err(e) => report.failed.push((path, e.to_string())),
            }
        }
        Ok((CorrelationEngine::new(rules), report))
    }

    /// Feed one event's base alerts through every correlation rule, returning
    /// any correlation alerts fired.
    pub fn process(&mut self, event: &Event, base_alerts: &[Alert]) -> Vec<Alert> {
        let mut fired = Vec::new();
        for (rule, windows) in self.rules.iter().zip(self.windows.iter_mut()) {
            let matched: Vec<&Alert> = base_alerts
                .iter()
                .filter(|a| rule.rules.contains(&a.rule_id))
                .collect();
            if matched.is_empty() {
                continue;
            }
            let key = rule.group_key(event);
            let window = windows.entry(key).or_default();
            let now = if event.ts != 0 {
                event.ts
            } else {
                sigil_core::now_micros()
            };
            for alert in &matched {
                window.push_back(WindowEntry {
                    ts: now,
                    rule_id: alert.rule_id.clone(),
                    event_id: event.id.clone(),
                    value: rule
                        .condition
                        .field
                        .as_deref()
                        .and_then(|f| resolve_field(event, f).into_iter().next()),
                });
            }
            while window.front().is_some_and(|e| e.ts < now - rule.timespan) {
                window.pop_front();
            }
            if !evaluate(rule, window) {
                continue;
            }
            let mut events: Vec<String> = window.iter().map(|e| e.event_id.clone()).collect();
            events.dedup();
            fired.push(Alert {
                rule_id: rule.rule_id.clone(),
                title: rule.title.clone(),
                severity: rule.severity,
                technique: rule.technique.clone(),
                events,
                ts: now,
            });
            window.clear();
        }
        fired
    }
}

/// Does the window satisfy the rule's aggregate condition?
fn evaluate(rule: &CompiledCorrelation, window: &VecDeque<WindowEntry>) -> bool {
    match rule.kind {
        CorrelationKind::EventCount => rule.condition.satisfied(window.len() as u64),
        CorrelationKind::ValueCount => {
            let distinct: HashSet<&str> =
                window.iter().filter_map(|e| e.value.as_deref()).collect();
            rule.condition.satisfied(distinct.len() as u64)
        }
        CorrelationKind::Temporal => rule
            .rules
            .iter()
            .all(|r| window.iter().any(|e| e.rule_id == *r)),
        CorrelationKind::TemporalOrdered => {
            // Every referenced rule must appear, in listed order (subsequence).
            let mut want = rule.rules.iter();
            let mut next = want.next();
            for entry in window {
                if next.is_some_and(|r| *r == entry.rule_id) {
                    next = want.next();
                }
            }
            next.is_none()
        }
    }
}

/// Is this YAML doc a correlation rule (top-level `correlation:` key)?
pub fn is_correlation_doc(text: &str) -> bool {
    serde_yaml::from_str::<serde_yaml::Mapping>(text)
        .map(|m| m.contains_key(serde_yaml::Value::String("correlation".into())))
        .unwrap_or(false)
}

/// Every `*.yml`/`*.yaml` file under `dir`, recursively, as `(path, text)`.
pub(crate) fn yaml_files(dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = std::fs::read_dir(&path)
            .map_err(|e| Error::Io(format!("reading rules dir {}: {e}", path.display())))?;
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")) {
                let text = std::fs::read_to_string(&p).map_err(|e| Error::Io(e.to_string()))?;
                out.push((p, text));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::EntityRef;

    fn login_event(user: &str, target: &str, ts: i64) -> Event {
        let mut ev = Event::new("acme");
        ev.ts = ts;
        ev.actor = Some(EntityRef::new("user", user));
        ev.target = Some(EntityRef::new("host", target));
        ev
    }

    fn base_alert(rule_id: &str, ev: &Event) -> Alert {
        Alert {
            rule_id: rule_id.into(),
            title: rule_id.into(),
            severity: Severity::Medium,
            technique: None,
            events: vec![ev.id.clone()],
            ts: ev.ts,
        }
    }

    const BRUTE: &str = r#"
title: Brute force per user
id: corr-brute
level: high
tags: [attack.t1110]
correlation:
  type: event_count
  rules: [rule-ssh-failed]
  group-by: [actor.name]
  timespan: 10m
  condition: { gte: 3 }
"#;

    #[test]
    fn event_count_fires_at_threshold_per_group() {
        let rule = CompiledCorrelation::compile(BRUTE).unwrap();
        let mut engine = CorrelationEngine::new(vec![rule]);
        let minute = 60 * 1_000_000;
        for i in 0..2 {
            let ev = login_event("mallory", "web01", (i + 1) * minute);
            let alerts = engine.process(&ev, &[base_alert("rule-ssh-failed", &ev)]);
            assert!(alerts.is_empty(), "should not fire below threshold");
        }
        // A different user does not contribute to mallory's group.
        let other = login_event("alice", "web01", 3 * minute);
        assert!(engine
            .process(&other, &[base_alert("rule-ssh-failed", &other)])
            .is_empty());

        let ev = login_event("mallory", "web01", 3 * minute);
        let alerts = engine.process(&ev, &[base_alert("rule-ssh-failed", &ev)]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "corr-brute");
        assert_eq!(alerts[0].severity, Severity::High);
        assert_eq!(alerts[0].technique.as_deref(), Some("T1110"));
        assert_eq!(alerts[0].events.len(), 3);
        // Window cleared after firing: next match starts a fresh count.
        let ev = login_event("mallory", "web01", 3 * minute + 1);
        assert!(engine
            .process(&ev, &[base_alert("rule-ssh-failed", &ev)])
            .is_empty());
    }

    #[test]
    fn event_count_window_slides() {
        let rule = CompiledCorrelation::compile(BRUTE).unwrap();
        let mut engine = CorrelationEngine::new(vec![rule]);
        let minute = 60 * 1_000_000;
        // Two old hits, then one 20 minutes later: window only holds the last.
        for ts in [minute, 2 * minute, 22 * minute] {
            let ev = login_event("mallory", "web01", ts);
            assert!(engine
                .process(&ev, &[base_alert("rule-ssh-failed", &ev)])
                .is_empty());
        }
    }

    #[test]
    fn value_count_counts_distinct_targets() {
        let yaml = r#"
title: Password spraying
correlation:
  type: value_count
  rules: [rule-ssh-failed]
  group-by: [actor.name]
  timespan: 1h
  condition: { field: target.name, gte: 3 }
"#;
        let rule = CompiledCorrelation::compile(yaml).unwrap();
        let mut engine = CorrelationEngine::new(vec![rule]);
        let minute = 60 * 1_000_000;
        // Same target repeatedly: distinct count stays 1.
        for i in 0..4 {
            let ev = login_event("mallory", "web01", (i + 1) * minute);
            assert!(engine
                .process(&ev, &[base_alert("rule-ssh-failed", &ev)])
                .is_empty());
        }
        let ev = login_event("mallory", "web02", 6 * minute);
        assert!(engine
            .process(&ev, &[base_alert("rule-ssh-failed", &ev)])
            .is_empty());
        let ev = login_event("mallory", "web03", 7 * minute);
        let alerts = engine.process(&ev, &[base_alert("rule-ssh-failed", &ev)]);
        assert_eq!(alerts.len(), 1, "3 distinct targets should fire");
    }

    #[test]
    fn temporal_ordered_requires_sequence() {
        let yaml = r#"
title: Recon then exfil
correlation:
  type: temporal_ordered
  rules: [rule-recon, rule-exfil]
  group-by: [host.name]
  timespan: 1h
"#;
        let rule = CompiledCorrelation::compile(yaml).unwrap();
        let mut engine = CorrelationEngine::new(vec![rule]);
        let minute = 60 * 1_000_000;

        let host_event = |ts: i64| {
            let mut ev = Event::new("acme");
            ev.ts = ts;
            ev.host = Some(EntityRef::new("host", "db01"));
            ev
        };
        // Exfil before recon: unordered `temporal` would fire, ordered must not.
        let ev = host_event(minute);
        assert!(engine
            .process(&ev, &[base_alert("rule-exfil", &ev)])
            .is_empty());
        let ev = host_event(2 * minute);
        assert!(engine
            .process(&ev, &[base_alert("rule-recon", &ev)])
            .is_empty());
        // Now exfil after recon completes the sequence.
        let ev = host_event(3 * minute);
        let alerts = engine.process(&ev, &[base_alert("rule-exfil", &ev)]);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn temporal_unordered_fires_either_way() {
        let yaml = r#"
title: Recon and exfil
correlation:
  type: temporal
  rules: [rule-recon, rule-exfil]
  timespan: 1h
"#;
        let rule = CompiledCorrelation::compile(yaml).unwrap();
        let mut engine = CorrelationEngine::new(vec![rule]);
        let ev = login_event("x", "y", 1_000_000);
        assert!(engine
            .process(&ev, &[base_alert("rule-exfil", &ev)])
            .is_empty());
        let ev2 = login_event("x", "y", 2_000_000);
        let alerts = engine.process(&ev2, &[base_alert("rule-recon", &ev2)]);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn suppresses_referenced_rules_unless_generate() {
        let engine = CorrelationEngine::new(vec![CompiledCorrelation::compile(BRUTE).unwrap()]);
        assert!(engine.suppressed("rule-ssh-failed"));
        assert!(!engine.suppressed("rule-other"));

        let generating = r#"
title: Also keep base alerts
correlation:
  type: event_count
  rules: [rule-a]
  timespan: 5m
  condition: { gte: 2 }
  generate: true
"#;
        let engine =
            CorrelationEngine::new(vec![CompiledCorrelation::compile(generating).unwrap()]);
        assert!(!engine.suppressed("rule-a"));
    }

    #[test]
    fn rejects_invalid_specs() {
        assert!(CompiledCorrelation::compile(
            "title: x\ncorrelation: { type: event_count, rules: [r], timespan: 5m }"
        )
        .is_err());
        assert!(CompiledCorrelation::compile(
            "title: x\ncorrelation: { type: value_count, rules: [r], timespan: 5m, condition: { gte: 2 } }"
        )
        .is_err());
        assert!(parse_timespan("10x").is_err());
        assert!(parse_timespan("-5m").is_err());
        assert_eq!(parse_timespan("2m").unwrap(), 120 * 1_000_000);
    }

    #[test]
    fn correlation_doc_detection() {
        assert!(is_correlation_doc(BRUTE));
        assert!(!is_correlation_doc(
            "title: x\ndetection:\n  sel: {a: b}\n  condition: sel"
        ));
    }
}
