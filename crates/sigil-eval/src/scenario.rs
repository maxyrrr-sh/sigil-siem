//! Labelled scenarios with ground truth (DESIGN §11.1). Phase 6 ships a
//! deterministic `synthetic` generator (pinned seed → reproducible) so the
//! correlation feature can be measured offline. Real dataset loaders (DARPA
//! TC/OpTC, ATLAS) slot in behind the same [`Scenario`] shape.

use sigil_core::{EntityRef, Event, OcsfClass, Severity};

/// An event plus its ground-truth labels.
pub struct LabeledEvent {
    pub event: Event,
    /// Campaign id this event belongs to (`None` = benign noise).
    pub campaign: Option<u32>,
    pub malicious: bool,
    /// ATT&CK technique (stands in for the detection layer's output).
    pub technique: Option<String>,
}

/// A labelled scenario: events + the ground-truth attack chain.
pub struct Scenario {
    pub name: String,
    pub events: Vec<LabeledEvent>,
    /// Ground-truth kill-chain (ordered event ids).
    pub truth_chain: Vec<String>,
    /// Ground-truth ATT&CK techniques, in order.
    pub truth_techniques: Vec<String>,
}

/// Tiny deterministic LCG so noise placement is reproducible per seed.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 16
    }
    fn pick<'a>(&mut self, xs: &'a [&'a str]) -> &'a str {
        xs[(self.next() as usize) % xs.len()]
    }
}

const BASE_TS: i64 = 1_700_000_000_000_000; // arbitrary fixed epoch micros
const STEP: i64 = 30_000_000; // 30s between attack stages

/// Build a synthetic multi-stage intrusion on `web01` (one campaign) plus
/// benign noise on other hosts. Deterministic for a given `seed`.
pub fn synthetic(seed: u64) -> Scenario {
    let mut events = Vec::new();

    // --- The attack: auth → priv-esc → cred-access → exfil on web01/mallory ---
    let stages = [
        (
            "atk-1",
            OcsfClass::Authentication,
            "T1110.001",
            "Failed password for mallory",
            None,
        ),
        (
            "atk-2",
            OcsfClass::ProcessActivity,
            "T1548.003",
            "sudo USER=root COMMAND=/bin/bash",
            None,
        ),
        (
            "atk-3",
            OcsfClass::FileSystemActivity,
            "T1003.008",
            "read /etc/shadow",
            Some(("file", "/etc/shadow")),
        ),
        (
            "atk-4",
            OcsfClass::NetworkActivity,
            "T1041",
            "exfil to 9.9.9.9",
            Some(("ip", "9.9.9.9")),
        ),
    ];
    let mut truth_chain = Vec::new();
    let mut truth_techniques = Vec::new();
    for (i, (id, class, technique, msg, target)) in stages.iter().enumerate() {
        let mut ev = Event::new("acme");
        ev.id = (*id).to_string();
        ev.ts = BASE_TS + i as i64 * STEP;
        ev.ocsf_class = *class;
        ev.host = Some(EntityRef::new("host", "web01"));
        ev.actor = Some(EntityRef::new("user", "mallory"));
        ev.target = target.map(|(k, v)| EntityRef::new(k, v));
        ev.message = (*msg).to_string();
        ev.severity = Severity::High;
        events.push(LabeledEvent {
            event: ev,
            campaign: Some(1),
            malicious: true,
            technique: Some((*technique).to_string()),
        });
        truth_chain.push((*id).to_string());
        truth_techniques.push((*technique).to_string());
    }

    // --- Benign noise on unrelated hosts (no shared entities with the attack) ---
    let mut rng = Lcg(seed ^ 0x5eed);
    let hosts = ["db01", "app02", "mail03", "ci04"];
    let msgs = [
        "nightly backup ok",
        "health check passed",
        "cron job finished",
        "cache warmed",
    ];
    for k in 0..12 {
        let mut ev = Event::new("acme");
        ev.id = format!("bng-{k}");
        ev.ts = BASE_TS + (rng.next() as i64 % (8 * STEP));
        ev.ocsf_class = OcsfClass::Other(1008);
        ev.host = Some(EntityRef::new("host", rng.pick(&hosts)));
        ev.message = rng.pick(&msgs).to_string();
        ev.severity = Severity::Informational;
        events.push(LabeledEvent {
            event: ev,
            campaign: None,
            malicious: false,
            technique: None,
        });
    }

    Scenario {
        name: format!("synthetic@{seed}"),
        events,
        truth_chain,
        truth_techniques,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_is_deterministic() {
        let a = synthetic(42);
        let b = synthetic(42);
        assert_eq!(a.events.len(), b.events.len());
        assert_eq!(a.truth_chain, vec!["atk-1", "atk-2", "atk-3", "atk-4"]);
        // Same seed → identical benign host placement.
        let ha: Vec<_> = a.events.iter().map(|e| e.event.host.clone()).collect();
        let hb: Vec<_> = b.events.iter().map(|e| e.event.host.clone()).collect();
        assert_eq!(ha, hb);
    }

    #[test]
    fn has_four_malicious_stages_and_noise() {
        let s = synthetic(1);
        assert_eq!(s.events.iter().filter(|e| e.malicious).count(), 4);
        assert!(s.events.iter().any(|e| !e.malicious));
    }
}
