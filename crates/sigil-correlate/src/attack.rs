//! ATT&CK tactic mapping (DESIGN §9.6): map a technique id (or, failing that,
//! the event's OCSF class) to a tactic, so a chain of events becomes a
//! tactic→technique kill-chain. This is the honest, campaign-level attribution
//! of §9.7 — not named-actor attribution.

use sigil_core::OcsfClass;

/// Tactic for a technique id (e.g. `T1110.001` → `credential-access`), falling
/// back to a class-based default when the technique is unknown.
pub fn tactic_for(technique: Option<&str>, class: &OcsfClass) -> &'static str {
    if let Some(t) = technique {
        let t = t.to_ascii_uppercase();
        let by_technique =
            if t.starts_with("T1110") || t.starts_with("T1003") || t.starts_with("T1552") {
                Some("credential-access")
            } else if t.starts_with("T1548") || t.starts_with("T1068") || t.starts_with("T1078") {
                Some("privilege-escalation")
            } else if t.starts_with("T1059") || t.starts_with("T1203") {
                Some("execution")
            } else if t.starts_with("T1071") || t.starts_with("T1572") || t.starts_with("T1105") {
                Some("command-and-control")
            } else if t.starts_with("T1041") || t.starts_with("T1048") {
                Some("exfiltration")
            } else if t.starts_with("T1021") || t.starts_with("T1210") {
                Some("lateral-movement")
            } else {
                None
            };
        if let Some(tac) = by_technique {
            return tac;
        }
    }
    tactic_for_class(class)
}

/// Coarse tactic guess from the OCSF class alone.
pub fn tactic_for_class(class: &OcsfClass) -> &'static str {
    match class {
        OcsfClass::Authentication => "credential-access",
        OcsfClass::ProcessActivity => "execution",
        OcsfClass::NetworkActivity => "command-and-control",
        OcsfClass::FileSystemActivity => "collection",
        OcsfClass::HttpActivity => "command-and-control",
        OcsfClass::ApiActivity => "execution",
        OcsfClass::DnsActivity => "command-and-control",
        OcsfClass::ModuleActivity => "defense-evasion",
        OcsfClass::ScheduledJobActivity => "persistence",
        OcsfClass::RegistryKeyActivity => "persistence",
        OcsfClass::Other(_) => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn technique_maps_to_tactic() {
        assert_eq!(
            tactic_for(Some("T1110.001"), &OcsfClass::Authentication),
            "credential-access"
        );
        assert_eq!(
            tactic_for(Some("T1548.003"), &OcsfClass::ProcessActivity),
            "privilege-escalation"
        );
    }

    #[test]
    fn falls_back_to_class() {
        assert_eq!(
            tactic_for(None, &OcsfClass::NetworkActivity),
            "command-and-control"
        );
        assert_eq!(
            tactic_for(Some("T9999"), &OcsfClass::ProcessActivity),
            "execution"
        );
    }
}
