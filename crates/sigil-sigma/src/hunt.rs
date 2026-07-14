//! Retro-hunt (DESIGN §8): run Sigma detection + correlation rules over
//! *historical* events instead of the live stream.
//!
//! This module is backend-agnostic — callers pull events out of the hot
//! (Tantivy) or cold (Parquet) tier and hand them here; `sigil hunt` wires the
//! index-backed path. Events are replayed in ascending timestamp order so
//! sliding-window correlation behaves exactly like the live stream, and base
//! alerts referenced by a non-`generate` correlation are suppressed the same
//! way.

use sigil_core::{Alert, Event};

use crate::correlation::CorrelationEngine;
use crate::engine::SigmaEngine;

/// Result of a retro-hunt pass.
#[derive(Debug, Default)]
pub struct HuntOutcome {
    /// Events evaluated.
    pub scanned: usize,
    /// Base detection-rule alerts (post correlation suppression).
    pub alerts: Vec<Alert>,
    /// Alerts fired by correlation rules.
    pub correlation_alerts: Vec<Alert>,
}

impl HuntOutcome {
    /// All alerts, base then correlation.
    pub fn all_alerts(&self) -> Vec<Alert> {
        let mut out = self.alerts.clone();
        out.extend(self.correlation_alerts.iter().cloned());
        out
    }
}

/// Replay `events` through the rule engines in timestamp order.
pub fn retro_hunt(
    engine: &SigmaEngine,
    correlations: &mut CorrelationEngine,
    mut events: Vec<Event>,
) -> HuntOutcome {
    events.sort_by_key(|e| e.ts);
    let mut outcome = HuntOutcome {
        scanned: events.len(),
        ..Default::default()
    };
    for event in &events {
        let base = engine.eval(event);
        outcome
            .correlation_alerts
            .extend(correlations.process(event, &base));
        outcome.alerts.extend(
            base.into_iter()
                .filter(|a| !correlations.suppressed(&a.rule_id)),
        );
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlation::CompiledCorrelation;
    use crate::engine::CompiledRule;
    use sigil_core::EntityRef;

    const FAILED: &str = r#"
title: SSH Failed Password
id: rule-ssh-failed
detection:
  selection:
    message|contains: 'Failed password'
  condition: selection
"#;

    const BRUTE: &str = r#"
title: Brute force
id: corr-brute
correlation:
  type: event_count
  rules: [rule-ssh-failed]
  group-by: [user.name]
  timespan: 10m
  condition: { gte: 3 }
"#;

    fn failed_login(user: &str, ts: i64) -> Event {
        let mut ev = Event::new("acme");
        ev.ts = ts;
        ev.message = format!("Failed password for {user}");
        ev.actor = Some(EntityRef::new("user", user));
        ev
    }

    #[test]
    fn hunts_out_of_order_history_and_correlates() {
        let engine = SigmaEngine::new(vec![CompiledRule::compile(FAILED).unwrap()]);
        let mut correlations =
            CorrelationEngine::new(vec![CompiledCorrelation::compile(BRUTE).unwrap()]);
        let minute = 60 * 1_000_000;
        // Deliberately shuffled: retro_hunt must sort by ts before replay.
        let events = vec![
            failed_login("mallory", 3 * minute),
            failed_login("mallory", minute),
            failed_login("alice", 2 * minute),
            failed_login("mallory", 2 * minute),
        ];
        let outcome = retro_hunt(&engine, &mut correlations, events);
        assert_eq!(outcome.scanned, 4);
        assert_eq!(outcome.correlation_alerts.len(), 1);
        assert_eq!(outcome.correlation_alerts[0].rule_id, "corr-brute");
        // Base alerts are suppressed (correlation without `generate: true`).
        assert!(outcome.alerts.is_empty());
        assert_eq!(outcome.all_alerts().len(), 1);
    }

    #[test]
    fn base_alerts_survive_without_correlations() {
        let engine = SigmaEngine::new(vec![CompiledRule::compile(FAILED).unwrap()]);
        let mut correlations = CorrelationEngine::default();
        let outcome = retro_hunt(&engine, &mut correlations, vec![failed_login("m", 1)]);
        assert_eq!(outcome.alerts.len(), 1);
        assert!(outcome.correlation_alerts.is_empty());
    }
}
