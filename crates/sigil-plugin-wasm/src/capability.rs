//! Capability-based plugin permissions (DESIGN §12.2). A plugin only gets what
//! the config grants it — `net:egress`, `read:field:<name>`, `enrich:<name>`.
//! Anything not granted is denied (deny-by-default).

use sigil_core::{Capability, Error, Result};

/// Parse a capability string into a [`Capability`].
pub fn parse_capability(s: &str) -> Result<Capability> {
    let s = s.trim();
    if let Some(field) = s.strip_prefix("read:field:") {
        return Ok(Capability::ReadField(field.to_string()));
    }
    if let Some(name) = s.strip_prefix("enrich:") {
        return Ok(Capability::Enrich(name.to_string()));
    }
    match s {
        "net:egress" => Ok(Capability::NetEgress),
        other => Err(Error::Config(format!("unknown capability `{other}`"))),
    }
}

/// Render a capability back to its string form.
pub fn capability_str(c: &Capability) -> String {
    match c {
        Capability::NetEgress => "net:egress".to_string(),
        Capability::ReadField(f) => format!("read:field:{f}"),
        Capability::Enrich(e) => format!("enrich:{e}"),
    }
}

/// The set of capabilities the host is willing to grant a plugin.
#[derive(Debug, Clone, Default)]
pub struct CapabilityPolicy {
    allowed: Vec<Capability>,
}

impl CapabilityPolicy {
    pub fn new(allowed: Vec<Capability>) -> Self {
        CapabilityPolicy { allowed }
    }

    /// Build from capability strings (e.g. from config).
    pub fn from_strings(items: &[String]) -> Result<Self> {
        let allowed = items
            .iter()
            .map(|s| parse_capability(s))
            .collect::<Result<Vec<_>>>()?;
        Ok(CapabilityPolicy { allowed })
    }

    pub fn grants(&self, cap: &Capability) -> bool {
        self.allowed.contains(cap)
    }

    /// `Ok(())` if every requested capability is granted; otherwise the list of
    /// denied capabilities (as strings).
    pub fn check(&self, requested: &[Capability]) -> std::result::Result<(), Vec<String>> {
        let denied: Vec<String> = requested
            .iter()
            .filter(|c| !self.grants(c))
            .map(capability_str)
            .collect();
        if denied.is_empty() {
            Ok(())
        } else {
            Err(denied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_capability_forms() {
        assert_eq!(
            parse_capability("net:egress").unwrap(),
            Capability::NetEgress
        );
        assert_eq!(
            parse_capability("read:field:user.name").unwrap(),
            Capability::ReadField("user.name".into())
        );
        assert_eq!(
            parse_capability("enrich:geoip").unwrap(),
            Capability::Enrich("geoip".into())
        );
        assert!(parse_capability("do:whatever").is_err());
    }

    #[test]
    fn deny_by_default() {
        let policy = CapabilityPolicy::from_strings(&["read:field:message".into()]).unwrap();
        // Granted capability passes.
        assert!(policy
            .check(&[Capability::ReadField("message".into())])
            .is_ok());
        // Ungranted capability is denied.
        let denied = policy.check(&[Capability::NetEgress]).unwrap_err();
        assert_eq!(denied, vec!["net:egress"]);
    }
}
