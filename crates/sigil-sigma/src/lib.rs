//! `sigil-sigma` — native Sigma detection engine (DESIGN §8).
//!
//! Phase 1 implements the **streaming backend**: a Sigma rule (YAML) is parsed
//! into selections + a `condition` expression and compiled into a predicate
//! over the normalized [`sigil_core::Event`]. Each match yields an
//! [`sigil_core::Alert`] carrying severity and the rule's ATT&CK technique tag.
//!
//! Supported today: field selections with `contains`/`startswith`/`endswith`/
//! `re`/`all` modifiers and `*`/`?` wildcards; keyword selections; list (OR) and
//! `|all` (AND) values; the `and`/`or`/`not`, `( )`, and `N of <pattern>`
//! condition grammar; field mapping to OCSF aliases. Not yet: the index-backed
//! retro-hunt backend, Sigma *correlation* rules, and `base64`/`cidr`/numeric
//! modifiers (those rules are reported as load failures rather than mis-matched).

pub mod condition;
pub mod engine;
pub mod harness;
pub mod matcher;
pub mod rule;

pub use engine::{CompiledRule, LoadReport, RuleInfo, SigmaEngine};
pub use harness::{event_from_fields, run_cases, TestCase};
pub use rule::{LogSource, SigmaRule};
