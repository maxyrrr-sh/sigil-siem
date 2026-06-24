//! Semantic validation of a loaded [`Config`] (DESIGN §13.2 `validate`).
//!
//! Schema validation is handled by serde at parse time; this layer checks
//! cross-references and surfaces unsupported-but-parseable settings as
//! warnings rather than hard errors.

use std::collections::BTreeSet;
use std::fmt;

use crate::{Config, IMPLEMENTED_INPUTS, KNOWN_CODECS, KNOWN_SINKS};

/// The outcome of [`Config::validate`]: hard `errors` (block apply) and
/// `warnings` (allowed, but worth flagging).
#[derive(Debug, Default, Clone)]
pub struct ValidationReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationReport {
    /// True when there are no hard errors.
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }

    fn error(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }

    fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for w in &self.warnings {
            writeln!(f, "warning: {w}")?;
        }
        for e in &self.errors {
            writeln!(f, "error: {e}")?;
        }
        if self.ok() {
            write!(f, "config valid ({} warning(s))", self.warnings.len())
        } else {
            write!(
                f,
                "config INVALID: {} error(s), {} warning(s)",
                self.errors.len(),
                self.warnings.len()
            )
        }
    }
}

impl Config {
    /// Run semantic validation: version, unique ids, cross-references, and
    /// support warnings.
    pub fn validate(&self) -> ValidationReport {
        let mut r = ValidationReport::default();

        if self.version != 1 {
            r.error(format!(
                "unsupported config version {} (expected 1)",
                self.version
            ));
        }

        // Inputs: non-empty unique ids; known/implemented kinds + codecs.
        let mut input_ids: BTreeSet<&str> = BTreeSet::new();
        for input in &self.inputs {
            if input.id.trim().is_empty() {
                r.error("input with empty id");
            }
            if !input_ids.insert(input.id.as_str()) {
                r.error(format!("duplicate input id `{}`", input.id));
            }
            if !IMPLEMENTED_INPUTS.contains(&input.kind.as_str()) {
                r.warn(format!(
                    "input `{}` uses kind `{}` which is not implemented yet (Phase 0 supports {:?})",
                    input.id, input.kind, IMPLEMENTED_INPUTS
                ));
            }
            if !KNOWN_CODECS.contains(&input.codec.kind.as_str()) {
                r.warn(format!(
                    "input `{}` uses codec `{}` which is not implemented yet (Phase 0 supports {:?})",
                    input.id, input.codec.kind, KNOWN_CODECS
                ));
            }
            // Kind-specific required settings.
            match input.kind.as_str() {
                "file" if input.setting_str("path").is_none() => {
                    r.error(format!("file input `{}` requires a `path`", input.id));
                }
                "syslog" if input.setting_str("listen").is_none() => {
                    r.error(format!(
                        "syslog input `{}` requires a `listen` address",
                        input.id
                    ));
                }
                _ => {}
            }
        }

        // Pipelines: unique ids; `from` references; valid `route` targets.
        let mut pipeline_ids: BTreeSet<&str> = BTreeSet::new();
        for p in &self.pipelines {
            if !pipeline_ids.insert(p.id.as_str()) {
                r.error(format!("duplicate pipeline id `{}`", p.id));
            }
            if p.from.is_empty() {
                r.warn(format!(
                    "pipeline `{}` has no `from` inputs; it will process nothing",
                    p.id
                ));
            }
            for src in &p.from {
                if !input_ids.contains(src.as_str()) {
                    r.error(format!(
                        "pipeline `{}` references unknown input `{}`",
                        p.id, src
                    ));
                }
            }
            if p.route.is_empty() {
                r.warn(format!(
                    "pipeline `{}` has no `route`; events will be dropped",
                    p.id
                ));
            }
            for target in &p.route {
                if !KNOWN_SINKS.contains(&target.to.as_str()) {
                    r.error(format!(
                        "pipeline `{}` routes to unknown sink `{}` (known: {:?})",
                        p.id, target.to, KNOWN_SINKS
                    ));
                } else if target.to == "correlation" {
                    r.warn(format!(
                        "pipeline `{}` routes to `correlation`, which is not wired yet (Phases 3+)",
                        p.id
                    ));
                }
            }
        }

        // Sigma: rulepacks aren't resolvable yet; rules_dir must exist if set.
        let routes_to_sigma = self
            .pipelines
            .iter()
            .any(|p| p.route.iter().any(|t| t.to == "sigma"));
        if self.sigma.enabled && routes_to_sigma {
            if !self.sigma.rulepacks.is_empty() && self.sigma.rules_dir.is_none() {
                r.warn(format!(
                    "sigma.rulepacks {:?} are not resolvable yet; set `sigma.rules_dir` to load rules",
                    self.sigma.rulepacks
                ));
            }
            if let Some(dir) = &self.sigma.rules_dir {
                if !std::path::Path::new(dir).is_dir() {
                    r.warn(format!(
                        "sigma.rules_dir `{dir}` not found at validate time (must exist when `run` starts)"
                    ));
                }
            } else if self.sigma.rulepacks.is_empty() {
                r.warn("a pipeline routes to `sigma` but no rules are configured (set `sigma.rules_dir`)".to_string());
            }
        }

        r
    }
}

#[cfg(test)]
mod tests {
    use crate::Config;

    #[test]
    fn flags_unknown_input_reference() {
        let cfg = Config::parse(
            r#"
version: 1
inputs:
  - id: a
    type: file
    path: /var/log/x
    codec: { type: json }
pipelines:
  - id: p
    from: [does_not_exist]
    route:
      - to: index
"#,
        )
        .unwrap();
        let r = cfg.validate();
        assert!(!r.ok());
        assert!(r.errors.iter().any(|e| e.contains("unknown input")));
    }

    #[test]
    fn flags_bad_version_and_unknown_sink() {
        let cfg = Config::parse(
            r#"
version: 2
inputs:
  - id: a
    type: file
    path: /tmp/x
    codec: { type: json }
pipelines:
  - id: p
    from: [a]
    route:
      - to: nowhere
"#,
        )
        .unwrap();
        let r = cfg.validate();
        assert!(r.errors.iter().any(|e| e.contains("version")));
        assert!(r.errors.iter().any(|e| e.contains("unknown sink")));
    }
}
