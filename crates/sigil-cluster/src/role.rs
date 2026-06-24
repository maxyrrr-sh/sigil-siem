//! Runtime roles (DESIGN §4.1). One binary, multiple selectable roles: a
//! monolith runs them all in-process; scale-out assigns roles to nodes via
//! config (`cluster.targets`).

use serde::{Deserialize, Serialize};

/// A role a node can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Ingest,
    Index,
    Correlate,
    Query,
    Coordinator,
}

impl Role {
    pub const ALL: [Role; 5] = [
        Role::Ingest,
        Role::Index,
        Role::Correlate,
        Role::Query,
        Role::Coordinator,
    ];

    fn parse(s: &str) -> Option<Role> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ingest" => Some(Role::Ingest),
            "index" => Some(Role::Index),
            "correlate" | "correlation" => Some(Role::Correlate),
            "query" => Some(Role::Query),
            "coordinator" => Some(Role::Coordinator),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Ingest => "ingest",
            Role::Index => "index",
            Role::Correlate => "correlate",
            Role::Query => "query",
            Role::Coordinator => "coordinator",
        }
    }
}

/// The set of roles active on this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleSet {
    roles: Vec<Role>,
}

impl RoleSet {
    /// All roles (monolith default).
    pub fn all() -> Self {
        RoleSet {
            roles: Role::ALL.to_vec(),
        }
    }

    /// Resolve from config `cluster.targets`. `["all"]` (or empty) → all roles.
    /// Unknown entries are ignored. Returns the set plus any unknown tokens.
    pub fn from_targets(targets: &[String]) -> (RoleSet, Vec<String>) {
        if targets.is_empty() || targets.iter().any(|t| t.eq_ignore_ascii_case("all")) {
            return (RoleSet::all(), Vec::new());
        }
        let mut roles = Vec::new();
        let mut unknown = Vec::new();
        for t in targets {
            match Role::parse(t) {
                Some(r) if !roles.contains(&r) => roles.push(r),
                Some(_) => {}
                None => unknown.push(t.clone()),
            }
        }
        (RoleSet { roles }, unknown)
    }

    pub fn runs(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }

    pub fn roles(&self) -> &[Role] {
        &self.roles
    }

    pub fn is_monolith(&self) -> bool {
        self.roles.len() == Role::ALL.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_when_empty_or_all() {
        assert!(RoleSet::from_targets(&[]).0.is_monolith());
        assert!(RoleSet::from_targets(&["all".into()]).0.is_monolith());
    }

    #[test]
    fn selects_named_roles() {
        let (set, unknown) = RoleSet::from_targets(&["ingest".into(), "index".into()]);
        assert!(set.runs(Role::Ingest));
        assert!(set.runs(Role::Index));
        assert!(!set.runs(Role::Query));
        assert!(unknown.is_empty());
        assert!(!set.is_monolith());
    }

    #[test]
    fn reports_unknown_targets() {
        let (_set, unknown) = RoleSet::from_targets(&["ingest".into(), "bogus".into()]);
        assert_eq!(unknown, vec!["bogus"]);
    }
}
