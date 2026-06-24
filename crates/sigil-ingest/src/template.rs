//! Online log-template mining (DESIGN §5.3, §9.2): a Drain-style miner that
//! turns variable log lines into stable templates with `<*>` placeholders,
//! assigning each a persistent `template_id` and extracting the variable parts.
//!
//! The algorithm is a simplified [Drain]: bucket by token count, then find the
//! most similar existing template in that bucket; merge if similarity clears a
//! threshold (differing positions become wildcards), else start a new template.
//!
//! [Drain]: https://github.com/logpai/Drain3

use std::collections::HashMap;

const WILDCARD: &str = "<*>";

/// The result of mining one message.
#[derive(Debug, Clone, PartialEq)]
pub struct Mined {
    /// Stable id for the matched template cluster.
    pub template_id: u64,
    /// The template string with `<*>` for variable tokens.
    pub template: String,
    /// The concrete values that fell on wildcard positions.
    pub variables: Vec<String>,
}

struct Cluster {
    id: u64,
    tokens: Vec<String>,
}

/// A stateful online template miner. Cheap to call per event.
pub struct TemplateMiner {
    sim_threshold: f32,
    /// Buckets keyed by token count.
    buckets: HashMap<usize, Vec<Cluster>>,
    next_id: u64,
}

impl Default for TemplateMiner {
    fn default() -> Self {
        TemplateMiner::new(0.5)
    }
}

impl TemplateMiner {
    /// Create a miner with the given merge similarity threshold (0.0..=1.0).
    pub fn new(sim_threshold: f32) -> Self {
        TemplateMiner {
            sim_threshold,
            buckets: HashMap::new(),
            next_id: 1,
        }
    }

    /// Mine one message, updating internal state, returning its template.
    pub fn mine(&mut self, message: &str) -> Mined {
        let tokens: Vec<String> = message.split_whitespace().map(|s| s.to_string()).collect();
        let n = tokens.len();
        let id = self.next_id;
        let bucket = self.buckets.entry(n).or_default();

        // Find the most similar existing cluster.
        let best = bucket
            .iter()
            .enumerate()
            .map(|(i, c)| (i, similarity(&c.tokens, &tokens)))
            .max_by(|a, b| a.1.total_cmp(&b.1));

        match best {
            Some((i, sim)) if sim >= self.sim_threshold => {
                merge(&mut bucket[i].tokens, &tokens);
                let cluster = &bucket[i];
                Mined {
                    template_id: cluster.id,
                    template: cluster.tokens.join(" "),
                    variables: variables(&cluster.tokens, &tokens),
                }
            }
            _ => {
                self.next_id += 1;
                bucket.push(Cluster {
                    id,
                    tokens: tokens.clone(),
                });
                Mined {
                    template_id: id,
                    template: tokens.join(" "),
                    variables: Vec::new(),
                }
            }
        }
    }

    /// Number of distinct templates discovered so far.
    pub fn template_count(&self) -> usize {
        self.buckets.values().map(|b| b.len()).sum()
    }
}

/// Fraction of positions that match (a wildcard matches anything).
fn similarity(template: &[String], tokens: &[String]) -> f32 {
    if template.is_empty() {
        return 1.0;
    }
    let matches = template
        .iter()
        .zip(tokens)
        .filter(|(t, tok)| t.as_str() == WILDCARD || t == tok)
        .count();
    matches as f32 / template.len() as f32
}

/// Widen the template: positions that disagree become wildcards.
fn merge(template: &mut [String], tokens: &[String]) {
    for (t, tok) in template.iter_mut().zip(tokens) {
        if t.as_str() != WILDCARD && t != tok {
            *t = WILDCARD.to_string();
        }
    }
}

/// Collect the concrete tokens that sit on wildcard positions.
fn variables(template: &[String], tokens: &[String]) -> Vec<String> {
    template
        .iter()
        .zip(tokens)
        .filter(|(t, _)| t.as_str() == WILDCARD)
        .map(|(_, tok)| tok.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn similar_lines_share_a_template() {
        let mut m = TemplateMiner::default();
        let a = m.mine("Failed password for admin from 10.0.0.9");
        let b = m.mine("Failed password for bob from 10.0.0.5");
        assert_eq!(a.template_id, b.template_id);
        assert_eq!(b.template, "Failed password for <*> from <*>");
        assert_eq!(b.variables, vec!["bob", "10.0.0.5"]);
        assert_eq!(m.template_count(), 1);
    }

    #[test]
    fn different_shapes_get_different_templates() {
        let mut m = TemplateMiner::default();
        let a = m.mine("Failed password for admin from 10.0.0.9");
        let b = m.mine("Accepted publickey for alice"); // different token count
        assert_ne!(a.template_id, b.template_id);
        assert_eq!(m.template_count(), 2);
    }

    #[test]
    fn template_id_is_stable_across_calls() {
        let mut m = TemplateMiner::default();
        let first = m.mine("user root logged in from console").template_id;
        let again = m.mine("user mary logged in from console").template_id;
        assert_eq!(first, again);
    }
}
