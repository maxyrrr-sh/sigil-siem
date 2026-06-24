//! Per-rule test harness (DESIGN §8): assert that sample events produce the
//! expected verdict. Used by rule authors' unit tests and CI over a rulepack.

use std::collections::BTreeMap;

use sigil_core::Event;

use crate::engine::CompiledRule;

/// One test case: an event and whether the rule should fire on it.
pub struct TestCase {
    pub name: String,
    pub event: Event,
    pub expect_match: bool,
}

impl TestCase {
    pub fn new(name: impl Into<String>, event: Event, expect_match: bool) -> Self {
        TestCase {
            name: name.into(),
            event,
            expect_match,
        }
    }
}

/// Run cases against a rule; returns a human-readable failure per mismatch
/// (empty vec = all passed).
pub fn run_cases(rule: &CompiledRule, cases: &[TestCase]) -> Vec<String> {
    let mut failures = Vec::new();
    for case in cases {
        let got = rule.matches(&case.event);
        if got != case.expect_match {
            failures.push(format!(
                "rule `{}` case `{}`: expected match={}, got {}",
                rule.rule_id, case.name, case.expect_match, got
            ));
        }
    }
    failures
}

/// Convenience: build an [`Event`] from a flat set of string fields (plus an
/// optional message), for terse test definitions.
pub fn event_from_fields(message: &str, fields: &[(&str, &str)]) -> Event {
    let mut ev = Event::new("test");
    ev.message = message.to_string();
    let map: BTreeMap<String, serde_json::Value> = fields
        .iter()
        .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
        .collect();
    ev.fields = map;
    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_reports_mismatches() {
        let rule = CompiledRule::compile(
            r#"
title: t
detection:
  sel:
    message|contains: boom
  condition: sel
"#,
        )
        .unwrap();
        let cases = vec![
            TestCase::new("hit", event_from_fields("a boom here", &[]), true),
            TestCase::new("miss", event_from_fields("nothing", &[]), false),
            TestCase::new("wrong", event_from_fields("no match", &[]), true),
        ];
        let failures = run_cases(&rule, &cases);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("wrong"));
    }
}
