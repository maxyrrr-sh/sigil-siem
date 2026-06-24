//! Selection matching: compile Sigma field conditions / keywords into
//! predicates over a normalized [`Event`], with field resolution that bridges
//! Sigma field names to our OCSF model (DESIGN §8 field mapping).

use regex::Regex;
use sigil_core::{value_to_string, Error, Event, Result};

/// A single string predicate, evaluated case-insensitively.
#[derive(Debug, Clone)]
pub enum StringPredicate {
    Equals(String),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(Regex),
    /// Field is absent / empty (`field: null`).
    IsNull,
}

impl StringPredicate {
    /// Build a predicate from a raw value and the modifier set on the field.
    pub fn build(value: Option<&str>, mods: &Modifiers) -> Result<StringPredicate> {
        let Some(value) = value else {
            return Ok(StringPredicate::IsNull);
        };
        let has_wild = value.contains('*') || value.contains('?');
        let lower = value.to_lowercase();
        Ok(match mods.base {
            BaseMatch::Equals if has_wild => {
                StringPredicate::Regex(wildcard_regex(value, true, true)?)
            }
            BaseMatch::Equals => StringPredicate::Equals(lower),
            BaseMatch::Contains if has_wild => {
                StringPredicate::Regex(wildcard_regex(value, false, false)?)
            }
            BaseMatch::Contains => StringPredicate::Contains(lower),
            BaseMatch::StartsWith if has_wild => {
                StringPredicate::Regex(wildcard_regex(value, true, false)?)
            }
            BaseMatch::StartsWith => StringPredicate::StartsWith(lower),
            BaseMatch::EndsWith if has_wild => {
                StringPredicate::Regex(wildcard_regex(value, false, true)?)
            }
            BaseMatch::EndsWith => StringPredicate::EndsWith(lower),
            BaseMatch::Regex => StringPredicate::Regex(
                Regex::new(&format!("(?i){value}"))
                    .map_err(|e| Error::Config(format!("bad regex `{value}`: {e}")))?,
            ),
        })
    }

    /// Does this predicate match the given candidate value?
    pub fn matches(&self, candidate: &str) -> bool {
        let lc = candidate.to_lowercase();
        match self {
            StringPredicate::Equals(v) => &lc == v,
            StringPredicate::Contains(v) => lc.contains(v.as_str()),
            StringPredicate::StartsWith(v) => lc.starts_with(v.as_str()),
            StringPredicate::EndsWith(v) => lc.ends_with(v.as_str()),
            StringPredicate::Regex(re) => re.is_match(candidate),
            StringPredicate::IsNull => false,
        }
    }
}

/// Translate Sigma `*`/`?` wildcards into an (optionally anchored) regex.
fn wildcard_regex(pattern: &str, anchor_start: bool, anchor_end: bool) -> Result<Regex> {
    let mut re = String::from("(?i)");
    if anchor_start {
        re.push('^');
    }
    for ch in pattern.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
    }
    if anchor_end {
        re.push('$');
    }
    Regex::new(&re).map_err(|e| Error::Config(format!("bad wildcard `{pattern}`: {e}")))
}

/// Parsed Sigma field modifiers (the `|contains|all` suffixes).
#[derive(Debug, Clone)]
pub struct Modifiers {
    pub base: BaseMatch,
    /// `|all` — every value in a list must match (AND), not just one (OR).
    pub all: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseMatch {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
}

impl Modifiers {
    /// Parse the modifiers off a field key like `CommandLine|contains|all`.
    /// Returns the bare field name plus the modifier set.
    pub fn parse(field_key: &str) -> Result<(String, Modifiers)> {
        let mut parts = field_key.split('|');
        let field = parts.next().unwrap_or("").to_string();
        let mut base = BaseMatch::Equals;
        let mut all = false;
        for m in parts {
            match m {
                "contains" => base = BaseMatch::Contains,
                "startswith" => base = BaseMatch::StartsWith,
                "endswith" => base = BaseMatch::EndsWith,
                "re" => base = BaseMatch::Regex,
                "all" => all = true,
                // Case sensitivity is not modeled (we match case-insensitively).
                "cased" => {}
                other => {
                    return Err(Error::Config(format!(
                        "unsupported Sigma modifier `{other}` on field `{field}`"
                    )))
                }
            }
        }
        Ok((field, Modifiers { base, all }))
    }
}

/// A condition on one field: predicates combined OR (default) or AND (`|all`).
#[derive(Debug, Clone)]
pub struct FieldCond {
    pub field: String,
    pub all: bool,
    pub preds: Vec<StringPredicate>,
}

impl FieldCond {
    pub fn eval(&self, event: &Event) -> bool {
        let candidates = resolve_field(event, &self.field);
        let pred_hit = |p: &StringPredicate| match p {
            StringPredicate::IsNull => candidates.is_empty(),
            _ => candidates.iter().any(|c| p.matches(c)),
        };
        if self.all {
            self.preds.iter().all(pred_hit)
        } else {
            self.preds.iter().any(pred_hit)
        }
    }
}

/// A compiled selection (one named block under `detection`).
#[derive(Debug, Clone)]
pub enum Selection {
    /// Map of field conditions, combined with AND.
    Fields(Vec<FieldCond>),
    /// List of maps, combined with OR.
    AnyOf(Vec<Selection>),
    /// Bare-string keywords: OR of substring matches against the whole event.
    Keywords(Vec<StringPredicate>),
}

impl Selection {
    pub fn eval(&self, event: &Event, haystack: &str) -> bool {
        match self {
            Selection::Fields(conds) => conds.iter().all(|c| c.eval(event)),
            Selection::AnyOf(items) => items.iter().any(|s| s.eval(event, haystack)),
            Selection::Keywords(preds) => preds.iter().any(|p| p.matches(haystack)),
        }
    }
}

/// Resolve a Sigma field name to candidate string values on the event. Tries
/// exact, then case-insensitive `fields` keys, then a few OCSF/ECS aliases.
pub fn resolve_field(event: &Event, name: &str) -> Vec<String> {
    if let Some(v) = event.fields.get(name) {
        return vec![value_to_string(v)];
    }
    let mut hits: Vec<String> = event
        .fields
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| value_to_string(v))
        .collect();
    if !hits.is_empty() {
        return hits;
    }

    match name.to_ascii_lowercase().as_str() {
        "message" | "msg" => push_nonempty(&mut hits, &event.message),
        "user" | "username" | "user.name" | "targetusername" | "subjectusername" => {
            if let Some(a) = &event.actor {
                if a.kind == "user" {
                    push_nonempty(&mut hits, &a.id);
                }
            }
        }
        "host" | "hostname" | "computer" | "computername" | "host.name" => {
            if let Some(h) = &event.host {
                push_nonempty(&mut hits, &h.id);
            }
        }
        "image" | "process" | "process.name" | "processname" => {
            if let Some(a) = &event.actor {
                if a.kind == "process" {
                    push_nonempty(&mut hits, &a.id);
                }
            }
        }
        "commandline" | "command_line" | "cmd" => push_nonempty(&mut hits, &event.message),
        _ => {}
    }
    hits
}

fn push_nonempty(out: &mut Vec<String>, v: &str) {
    if !v.is_empty() {
        out.push(v.to_string());
    }
}

/// Build the lowercased whole-event haystack used by keyword selections.
pub fn event_haystack(event: &Event) -> String {
    let mut s = event.message.clone();
    for v in event.fields.values() {
        s.push(' ');
        s.push_str(&value_to_string(v));
    }
    for e in [&event.actor, &event.host, &event.target]
        .into_iter()
        .flatten()
    {
        s.push(' ');
        s.push_str(&e.id);
    }
    s.to_lowercase()
}
