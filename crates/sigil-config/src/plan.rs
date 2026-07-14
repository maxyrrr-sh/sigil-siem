//! `plan` / `apply` / drift (DESIGN §13.2): the config file is the source of
//! truth, and **apply** records the currently-in-effect config as a snapshot
//! (`applied-config.yaml` in the data dir). **plan** diffs desired (file)
//! against that snapshot before you apply; **drift** is the same diff asked
//! the other way — has the applied state wandered from the declared file?

use std::fmt;
use std::path::{Path, PathBuf};

use crate::Config;
use sigil_core::{Error, Result};

/// One changed leaf in a config diff, keyed by dotted path.
#[derive(Debug, Clone, PartialEq)]
pub enum Change {
    /// Present in desired, absent in current: `+ path: value`.
    Added(String, String),
    /// Present in current, absent in desired: `- path: value`.
    Removed(String, String),
    /// Present in both with different values: `~ path: old -> new`.
    Changed(String, String, String),
}

/// A structural diff between two configs.
#[derive(Debug, Clone, Default)]
pub struct ConfigDiff {
    pub changes: Vec<Change>,
}

impl ConfigDiff {
    /// No differences?
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

impl fmt::Display for ConfigDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return writeln!(f, "no changes; state matches");
        }
        for c in &self.changes {
            match c {
                Change::Added(p, v) => writeln!(f, "  + {p}: {v}")?,
                Change::Removed(p, v) => writeln!(f, "  - {p}: {v}")?,
                Change::Changed(p, old, new) => writeln!(f, "  ~ {p}: {old} -> {new}")?,
            }
        }
        let (a, r, c) = self
            .changes
            .iter()
            .fold((0, 0, 0), |(a, r, c), ch| match ch {
                Change::Added(..) => (a + 1, r, c),
                Change::Removed(..) => (a, r + 1, c),
                Change::Changed(..) => (a, r, c + 1),
            });
        writeln!(f, "plan: {a} to add, {c} to change, {r} to remove")
    }
}

/// Diff two configs (leaf-level, dotted paths; list items indexed).
pub fn diff(current: &Config, desired: &Config) -> Result<ConfigDiff> {
    let cur = to_value(current)?;
    let des = to_value(desired)?;
    let mut out = ConfigDiff::default();
    walk("", &cur, &des, &mut out);
    Ok(out)
}

fn to_value(cfg: &Config) -> Result<serde_yaml::Value> {
    serde_yaml::to_value(cfg).map_err(|e| Error::Config(format!("serializing config: {e}")))
}

fn scalar(v: &serde_yaml::Value) -> String {
    serde_yaml::to_string(v)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into())
}

fn join(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}.{key}")
    }
}

fn walk(
    path: &str,
    current: &serde_yaml::Value,
    desired: &serde_yaml::Value,
    out: &mut ConfigDiff,
) {
    use serde_yaml::Value;
    match (current, desired) {
        (Value::Mapping(c), Value::Mapping(d)) => {
            for (k, cv) in c {
                let key = scalar(k);
                match d.get(k) {
                    Some(dv) => walk(&join(path, &key), cv, dv, out),
                    None => out
                        .changes
                        .push(Change::Removed(join(path, &key), scalar(cv))),
                }
            }
            for (k, dv) in d {
                if c.get(k).is_none() {
                    out.changes
                        .push(Change::Added(join(path, &scalar(k)), scalar(dv)));
                }
            }
        }
        (Value::Sequence(c), Value::Sequence(d)) => {
            for (i, pair) in c.iter().zip(d.iter()).enumerate() {
                walk(&join(path, &i.to_string()), pair.0, pair.1, out);
            }
            for (i, cv) in c.iter().enumerate().skip(d.len()) {
                out.changes
                    .push(Change::Removed(join(path, &i.to_string()), scalar(cv)));
            }
            for (i, dv) in d.iter().enumerate().skip(c.len()) {
                out.changes
                    .push(Change::Added(join(path, &i.to_string()), scalar(dv)));
            }
        }
        _ if current == desired => {}
        _ => out.changes.push(Change::Changed(
            path.to_string(),
            scalar(current),
            scalar(desired),
        )),
    }
}

/// Where the applied snapshot lives for a given data dir.
pub fn snapshot_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("applied-config.yaml")
}

/// The last-applied config, if any.
pub fn load_snapshot(data_dir: &str) -> Result<Option<Config>> {
    let path = snapshot_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(Some(Config::parse(&text)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(format!("reading {}: {e}", path.display()))),
    }
}

impl Config {
    /// The plan: what applying this config would change relative to the
    /// last-applied snapshot. With no snapshot everything is an addition
    /// (diffed against the default config).
    pub fn plan(&self, data_dir: &str) -> Result<ConfigDiff> {
        let current = load_snapshot(data_dir)?.unwrap_or_else(|| Config {
            version: self.version,
            ..empty_config()
        });
        diff(&current, self)
    }

    /// Apply: record this config as the in-effect snapshot, returning what
    /// changed. Validation is the caller's gate (CLI validates first).
    pub fn apply(&self, data_dir: &str) -> Result<ConfigDiff> {
        let plan = self.plan(data_dir)?;
        let path = snapshot_path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
        }
        let body = serde_yaml::to_string(self)
            .map_err(|e| Error::Config(format!("serializing config: {e}")))?;
        std::fs::write(&path, body)
            .map_err(|e| Error::Io(format!("writing {}: {e}", path.display())))?;
        Ok(plan)
    }

    /// Drift: how the declared file has moved away from the applied snapshot
    /// (empty diff = in sync). Errors if nothing was ever applied.
    pub fn drift(&self, data_dir: &str) -> Result<ConfigDiff> {
        let applied = load_snapshot(data_dir)?.ok_or_else(|| {
            Error::Config("no applied snapshot; run `sigil config apply` first".into())
        })?;
        diff(&applied, self)
    }
}

/// A minimal empty config used as the "before" of a first apply.
fn empty_config() -> Config {
    Config::parse("version: 1").expect("empty config parses")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
version: 1
inputs:
  - id: syslog_main
    type: syslog
    listen: 0.0.0.0:5514
index:
  path: ./data/index
"#;

    const CHANGED: &str = r#"
version: 1
inputs:
  - id: syslog_main
    type: syslog
    listen: 0.0.0.0:6601
  - id: authlog
    type: file
    path: /var/log/auth.log
index:
  path: ./data/index
"#;

    #[test]
    fn diff_reports_added_and_changed_paths() {
        let cur = Config::parse(BASE).unwrap();
        let des = Config::parse(CHANGED).unwrap();
        let d = diff(&cur, &des).unwrap();
        assert!(!d.is_empty());
        let text = d.to_string();
        assert!(
            text.contains("~ inputs.0.listen: 0.0.0.0:5514 -> 0.0.0.0:6601"),
            "{text}"
        );
        assert!(text.contains("+ inputs.1"), "{text}");
    }

    #[test]
    fn identical_configs_have_empty_diff() {
        let a = Config::parse(BASE).unwrap();
        let b = Config::parse(BASE).unwrap();
        assert!(diff(&a, &b).unwrap().is_empty());
    }

    #[test]
    fn apply_then_plan_is_clean_then_drift_after_edit() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_string_lossy().to_string();

        let cfg = Config::parse(BASE).unwrap();
        // First plan: everything relative to the empty baseline.
        assert!(!cfg.plan(&data_dir).unwrap().is_empty());
        cfg.apply(&data_dir).unwrap();
        // Re-planning the same config is clean.
        assert!(cfg.plan(&data_dir).unwrap().is_empty());
        assert!(cfg.drift(&data_dir).unwrap().is_empty());

        // The file changes: drift + plan both surface it.
        let edited = Config::parse(CHANGED).unwrap();
        assert!(!edited.drift(&data_dir).unwrap().is_empty());
        assert!(!edited.plan(&data_dir).unwrap().is_empty());
    }

    #[test]
    fn drift_without_apply_errors() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::parse(BASE).unwrap();
        assert!(cfg.drift(&dir.path().to_string_lossy()).is_err());
    }
}
