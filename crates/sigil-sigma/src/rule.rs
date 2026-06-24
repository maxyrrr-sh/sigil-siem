//! Sigma rule deserialization (the on-disk YAML shape).

use serde::Deserialize;

/// A Sigma rule as parsed from YAML. `detection` is kept as a raw mapping and
/// interpreted during compilation (see [`crate::engine`]).
#[derive(Debug, Clone, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub logsource: LogSource,
    pub detection: serde_yaml::Mapping,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Sigma `logsource` block (used for field-mapping/routing decisions).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct LogSource {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
}
