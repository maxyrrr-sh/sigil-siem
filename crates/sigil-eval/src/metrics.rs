//! Evaluation metrics (DESIGN §11.2): detection (P/R/F1), correlation
//! (ARI / NMI / alert-reduction), and attribution (technique-chain P/R, graph
//! edit distance). Pure functions over label assignments and id sets.

use std::collections::HashMap;

/// Precision / recall / F1.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PrF1 {
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

/// P/R/F1 from confusion counts.
pub fn prf1(tp: usize, fp: usize, fn_: usize) -> PrF1 {
    let precision = ratio(tp, tp + fp);
    let recall = ratio(tp, tp + fn_);
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    PrF1 {
        precision,
        recall,
        f1,
    }
}

/// Set-based P/R/F1 over predicted vs truth string sets (order-insensitive).
pub fn set_prf1(predicted: &[String], truth: &[String]) -> PrF1 {
    let tset: std::collections::BTreeSet<&String> = truth.iter().collect();
    let pset: std::collections::BTreeSet<&String> = predicted.iter().collect();
    let tp = pset.intersection(&tset).count();
    let fp = pset.len() - tp;
    let fn_ = tset.len() - tp;
    prf1(tp, fp, fn_)
}

fn ratio(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

fn comb2(n: u64) -> u64 {
    n * n.saturating_sub(1) / 2
}

/// Joint contingency counts plus the two marginals.
#[derive(Default)]
struct Contingency {
    joint: HashMap<(u32, u32), u64>,
    ai: HashMap<u32, u64>,
    bj: HashMap<u32, u64>,
}

fn contingency(a: &[u32], b: &[u32]) -> Contingency {
    let mut c = Contingency::default();
    for (x, y) in a.iter().zip(b) {
        *c.joint.entry((*x, *y)).or_insert(0) += 1;
        *c.ai.entry(*x).or_insert(0) += 1;
        *c.bj.entry(*y).or_insert(0) += 1;
    }
    c
}

/// Adjusted Rand Index between two clusterings (label vectors of equal length).
/// 1.0 = identical clustering; ~0.0 = random agreement.
pub fn adjusted_rand_index(a: &[u32], b: &[u32]) -> f64 {
    assert_eq!(a.len(), b.len());
    let n = a.len() as u64;
    if n == 0 {
        return 1.0;
    }
    let c = contingency(a, b);
    let sum_ij: u64 = c.joint.values().map(|&v| comb2(v)).sum();
    let sum_ai: u64 = c.ai.values().map(|&v| comb2(v)).sum();
    let sum_bj: u64 = c.bj.values().map(|&v| comb2(v)).sum();
    let total = comb2(n) as f64;
    let expected = (sum_ai as f64 * sum_bj as f64) / total;
    let max_index = 0.5 * (sum_ai as f64 + sum_bj as f64);
    if (max_index - expected).abs() < 1e-12 {
        return 1.0;
    }
    (sum_ij as f64 - expected) / (max_index - expected)
}

/// Normalized Mutual Information in 0..=1 (1 = identical clustering).
pub fn normalized_mutual_info(a: &[u32], b: &[u32]) -> f64 {
    assert_eq!(a.len(), b.len());
    let n = a.len() as f64;
    if n == 0.0 {
        return 1.0;
    }
    let c = contingency(a, b);
    let mut mi = 0.0;
    for ((x, y), &nij) in &c.joint {
        let pij = nij as f64 / n;
        let pi = c.ai[x] as f64 / n;
        let pj = c.bj[y] as f64 / n;
        mi += pij * (pij / (pi * pj)).ln();
    }
    let entropy = |counts: &HashMap<u32, u64>| -> f64 {
        -counts
            .values()
            .map(|&v| (v as f64 / n) * (v as f64 / n).ln())
            .sum::<f64>()
    };
    let (ha, hb) = (entropy(&c.ai), entropy(&c.bj));
    if ha == 0.0 && hb == 0.0 {
        return 1.0;
    }
    if ha == 0.0 || hb == 0.0 {
        return 0.0;
    }
    (mi / (ha * hb).sqrt()).clamp(0.0, 1.0)
}

/// Alert-reduction ratio: fraction of alerts folded away into incidents
/// (`1 - incidents/alerts`). DESIGN §9.6 alert-fatigue reduction.
pub fn alert_reduction_ratio(alerts: usize, incidents: usize) -> f64 {
    if alerts == 0 {
        0.0
    } else {
        1.0 - (incidents as f64 / alerts as f64)
    }
}

/// Levenshtein edit distance between two id sequences (the kill-chain).
pub fn sequence_edit_distance(a: &[String], b: &[String]) -> usize {
    let (m, n) = (a.len(), b.len());
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for (i, row) in dp.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in dp[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }
    dp[m][n]
}

/// Chain similarity in 0..=1 from the normalized edit distance (1 = identical).
pub fn normalized_chain_similarity(a: &[String], b: &[String]) -> f64 {
    let max_len = a.len().max(b.len());
    if max_len == 0 {
        return 1.0;
    }
    1.0 - sequence_edit_distance(a, b) as f64 / max_len as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf1_basic() {
        let r = prf1(8, 2, 2);
        assert!((r.precision - 0.8).abs() < 1e-9);
        assert!((r.recall - 0.8).abs() < 1e-9);
        assert!((r.f1 - 0.8).abs() < 1e-9);
    }

    #[test]
    fn ari_identical_is_one() {
        let a = [0, 0, 1, 1, 2];
        assert!((adjusted_rand_index(&a, &a) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn ari_better_for_closer_clustering() {
        let truth = [0u32, 0, 0, 1, 1, 1];
        let good = [0u32, 0, 0, 1, 1, 1]; // perfect
        let bad = [0u32, 1, 2, 3, 4, 5]; // all singletons
        assert!(adjusted_rand_index(&good, &truth) > adjusted_rand_index(&bad, &truth));
    }

    #[test]
    fn nmi_identical_is_one() {
        let a = [0, 1, 1, 2, 2];
        assert!((normalized_mutual_info(&a, &a) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn alert_reduction() {
        assert!((alert_reduction_ratio(10, 1) - 0.9).abs() < 1e-9);
        assert_eq!(alert_reduction_ratio(0, 0), 0.0);
    }

    #[test]
    fn chain_similarity() {
        let truth = vec!["a".into(), "b".into(), "c".into()];
        assert!((normalized_chain_similarity(&truth, &truth) - 1.0).abs() < 1e-9);
        let partial = vec!["a".to_string(), "b".to_string()];
        assert!(normalized_chain_similarity(&partial, &truth) < 1.0);
    }

    #[test]
    fn set_prf1_intersection() {
        let pred = vec![
            "T1110".to_string(),
            "T1003".to_string(),
            "T9999".to_string(),
        ];
        let truth = vec!["T1110".to_string(), "T1003".to_string()];
        let r = set_prf1(&pred, &truth);
        assert!((r.recall - 1.0).abs() < 1e-9);
        assert!((r.precision - 2.0 / 3.0).abs() < 1e-9);
    }
}
