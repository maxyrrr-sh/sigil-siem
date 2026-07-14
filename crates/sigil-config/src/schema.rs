//! Generated JSON Schema for the config file (ADR-4: YAML + JSON Schema).
//!
//! `sigil config schema` prints this document; point an editor/CI validator at
//! it for completion and structural validation of `sigil.yaml`. It is built by
//! hand to mirror the [`crate::Config`] structs — permissive exactly where the
//! structs are permissive (`detectors`, `correlation`, `plugins`, input
//! settings), strict on the typed sections.

use serde_json::{json, Value};

/// The JSON Schema (draft 2020-12) describing a Sigil config file.
pub fn json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sigil-siem.dev/schemas/sigil-config.v1.json",
        "title": "Sigil SIEM configuration",
        "description": "Declared state of a Sigil node (DESIGN §13). The config file is the source of truth.",
        "type": "object",
        "required": ["version"],
        "properties": {
            "version": { "type": "integer", "const": 1, "description": "Config schema version." },
            "cluster": {
                "type": "object",
                "properties": {
                    "targets": { "type": "array", "items": { "type": "string", "enum": ["all", "ingest", "index", "correlate", "query", "coordinator"] } },
                    "nodes": { "type": "array", "items": { "type": "string" } },
                    "shards": { "type": "integer", "minimum": 1 },
                    "replication": { "type": "integer", "minimum": 1 },
                    "object_store": {
                        "type": "object",
                        "properties": {
                            "kind": { "type": "string", "enum": ["local", "s3"] },
                            "root": { "type": "string" },
                            "bucket": { "type": "string" },
                            "region": { "type": "string" },
                            "endpoint": { "type": "string" },
                            "prefix": { "type": "string" }
                        }
                    },
                    "transport": {
                        "type": "object",
                        "properties": { "kind": { "type": "string", "enum": ["inproc", "tcp", "redpanda", "nats"] } }
                    }
                },
                "additionalProperties": true
            },
            "inputs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "type"],
                    "properties": {
                        "id": { "type": "string" },
                        "type": { "type": "string" },
                        "codec": {
                            "type": "object",
                            "required": ["type"],
                            "properties": { "type": { "type": "string" } },
                            "additionalProperties": true
                        }
                    },
                    "additionalProperties": true
                }
            },
            "pipelines": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": { "type": "string" },
                        "from": { "type": "array", "items": { "type": "string" } },
                        "steps": { "type": "array" },
                        "route": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["to"],
                                "properties": { "to": { "type": "string" } }
                            }
                        }
                    },
                    "additionalProperties": true
                }
            },
            "index": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "cold_path": { "type": "string" },
                    "catalog_path": { "type": "string" },
                    "retention": {
                        "type": "object",
                        "properties": {
                            "hot": { "$ref": "#/$defs/duration" },
                            "warm": { "$ref": "#/$defs/duration" },
                            "cold": { "$ref": "#/$defs/duration" }
                        }
                    }
                },
                "additionalProperties": true
            },
            "sigma": {
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "rulepacks": { "type": "array", "items": { "type": "string" } },
                    "rules_dir": { "type": "string" },
                    "outputs": {
                        "type": "object",
                        "properties": {
                            "file": { "type": "string" },
                            "webhook": { "type": "string" },
                            "slack": { "type": "string" },
                            "pagerduty": {
                                "type": "object",
                                "required": ["routing_key"],
                                "properties": { "routing_key": { "type": "string" }, "url": { "type": "string" } }
                            },
                            "jira": {
                                "type": "object",
                                "required": ["url", "project", "user", "token"],
                                "properties": {
                                    "url": { "type": "string" },
                                    "project": { "type": "string" },
                                    "user": { "type": "string" },
                                    "token": { "type": "string" },
                                    "issue_type": { "type": "string" }
                                }
                            },
                            "misp": {
                                "type": "object",
                                "required": ["url", "api_key"],
                                "properties": { "url": { "type": "string" }, "api_key": { "type": "string" } }
                            }
                        },
                        "additionalProperties": false
                    }
                },
                "additionalProperties": true
            },
            "auth": {
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "jwt_secret": { "type": "string" },
                    "token_ttl_secs": { "type": "integer", "minimum": 1 },
                    "users": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["username"],
                            "properties": {
                                "username": { "type": "string" },
                                "password_hash": { "type": "string" },
                                "password": { "type": "string" },
                                "roles": { "type": "array", "items": { "type": "string", "enum": ["viewer", "analyst", "admin"] } }
                            }
                        }
                    }
                },
                "additionalProperties": true
            },
            "edr": {
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "listen": { "type": "string" },
                    "tls_cert": { "type": "string" },
                    "tls_key": { "type": "string" },
                    "enrollment_tokens": { "type": "array", "items": { "type": "string" } }
                },
                "additionalProperties": true
            },
            "data_dir": { "type": "string" },
            "ml_sidecar": { "type": "string" },
            "detectors": { "description": "Custom detectors: names or name→settings maps (permissive)." },
            "correlation": { "description": "Correlation tuning (permissive; Phases 3+)." },
            "plugins": { "type": "array", "description": "Plugin references (permissive)." }
        },
        "additionalProperties": false,
        "$defs": {
            "duration": {
                "type": "string",
                "pattern": "^[0-9]+[smhdw]$",
                "description": "Duration like 90m, 12h, 7d, 2w."
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_wellformed_and_names_all_config_sections() {
        let schema = json_schema();
        let props = schema["properties"].as_object().unwrap();
        // Every top-level field of `Config` appears in the schema.
        for key in [
            "version",
            "cluster",
            "inputs",
            "pipelines",
            "index",
            "sigma",
            "auth",
            "data_dir",
            "ml_sidecar",
            "detectors",
            "edr",
            "correlation",
            "plugins",
        ] {
            assert!(props.contains_key(key), "schema missing `{key}`");
        }
        assert_eq!(schema["required"], serde_json::json!(["version"]));
    }

    #[test]
    fn example_config_only_uses_schema_known_top_level_keys() {
        // `additionalProperties: false` at the root means the shipped example
        // must stay within the schema's vocabulary.
        let example: serde_yaml::Value =
            serde_yaml::from_str(include_str!("../../../configs/sigil.yaml")).unwrap();
        let props = json_schema()["properties"].as_object().unwrap().clone();
        let serde_yaml::Value::Mapping(map) = example else {
            panic!("example config must be a mapping");
        };
        for (k, _) in map {
            let key = k.as_str().unwrap().to_string();
            assert!(props.contains_key(&key), "example uses unknown key `{key}`");
        }
    }
}
