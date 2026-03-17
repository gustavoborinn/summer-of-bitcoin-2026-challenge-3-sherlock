// src/core/heuristics/round_number.rs

use crate::core::types::{HeuristicResult, RawTransaction};

/// Round Number Payment heuristic.
///
/// # What it detects
/// Outputs with values that are round BTC amounts (multiples of 10_000 sats,
/// ≥ 100_000 sats). Round-number outputs are more likely to be intentional
/// payments; non-round outputs are more likely to be change.
///
/// Note: `change_detection` also uses round-number analysis for 2-output txs.
/// This heuristic is complementary — it fires on ANY tx with a round output,
/// regardless of output count, and reports which indices are round.
///
/// # Detection logic
/// `detected = any output value is round`
/// Round = value >= 100_000 sats && value % 10_000 == 0
///
/// # Confidence model
/// Based on the "roundest" output found:
/// - any output is multiple of 1_000_000 sats (0.01 BTC) → "high"
/// - any output is multiple of 100_000 sats (0.001 BTC) → "medium"
///
/// # Known false positives
/// - Exchange batch withdrawals with standardized amounts.
/// - Consolidations of previously-received round-value UTXOs.
pub fn run(tx: &RawTransaction<'_>) -> HeuristicResult {
    let mut round_indices: Vec<u64> = Vec::new();
    let mut best_roundness: u8 = 0; // 0 = none, 1 = 100k multiple, 2 = 1M multiple

    for (i, out) in tx.outputs.iter().enumerate() {
        let v = out.value;
        if v >= 1_000_000 && v % 1_000_000 == 0 {
            round_indices.push(i as u64);
            best_roundness = best_roundness.max(2);
        } else if v >= 100_000 && v % 10_000 == 0 {
            round_indices.push(i as u64);
            best_roundness = best_roundness.max(1);
        }
    }

    if round_indices.is_empty() {
        return HeuristicResult::not_detected();
    }

    let confidence = if best_roundness >= 2 { "high" } else { "medium" };

    let round_output_count = round_indices.len() as u64;
    HeuristicResult::detected()
        .with("round_output_indices", serde_json::json!(round_indices))
        .with("round_output_count", round_output_count)
        .with("confidence", confidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_round(v: u64) -> bool {
        v >= 100_000 && v % 10_000 == 0
    }

    #[test]
    fn round_number_boundaries() {
        assert!(!is_round(0));
        assert!(!is_round(99_999));
        assert!(!is_round(100_001));
        assert!(is_round(100_000));
        assert!(is_round(1_000_000));
        assert!(is_round(100_000_000)); // 1 BTC
    }
}