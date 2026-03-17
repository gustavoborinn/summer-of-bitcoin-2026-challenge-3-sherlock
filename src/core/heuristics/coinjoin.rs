// src/core/heuristics/coinjoin.rs

use crate::core::types::{HeuristicResult, RawTransaction};
use std::collections::HashMap;

/// CoinJoin Detection heuristic.
///
/// # What it detects
/// CoinJoin transactions: multiple participants combine inputs and produce
/// equal-value outputs to break the transaction graph. The equal outputs
/// make it impossible to trace which input funded which output.
///
/// # Detection logic
/// Both conditions required:
/// 1. `input_count >= 2`
/// 2. At least one output value appears ≥ 2 times AND value ≥ 10_000 sats
///
/// The denomination is the most-repeated output value.
///
/// # Confidence model
/// Based on `equal_output_count` (how many outputs share the denomination)
/// and `input_count`:
/// - both >= 5 → "high"
/// - both >= 3 → "medium"
/// - both >= 2 → "low"
///
/// # Known false positives
/// - Exchange batch withdrawals with equal amounts.
/// - P2Pool coinbase outputs (equal miner payouts).
///
/// # Note
/// This heuristic does not verify that inputs come from different owners —
/// that would require cross-block UTXO tracking beyond the scope of this engine.
/// It relies on the structural signal of equal outputs alone.
pub fn run(tx: &RawTransaction<'_>) -> HeuristicResult {
    let input_count = tx.inputs.len();

    if input_count < 3 {
        return HeuristicResult::not_detected();
    }

    // Count frequency of each output value.
    let mut value_freq: HashMap<u64, u32> = HashMap::new();
    for out in &tx.outputs {
        *value_freq.entry(out.value).or_insert(0) += 1;
    }

    // Find the denomination: most-repeated value that meets the floor.
    // On ties, prefer the higher value (more economically significant).
    let denomination = value_freq
        .iter()
        .filter(|(&val, &count)| count >= 2 && val >= 10_000)
        .max_by(|a, b| {
            // Primary: higher count; secondary: higher value (deterministic tie-break)
            a.1.cmp(b.1).then(a.0.cmp(b.0))
        })
        .map(|(&val, _)| val);

    let denomination_value = match denomination {
        Some(v) => v,
        None => return HeuristicResult::not_detected(),
    };

    let equal_output_count = value_freq[&denomination_value] as u64;

    let confidence = if equal_output_count >= 5 && input_count >= 5 {
        "high"
    } else if equal_output_count >= 3 && input_count >= 3 {
        "medium"
    } else {
        "low"
    };

    HeuristicResult::detected()
        .with("denomination_sats", denomination_value)
        .with("equal_output_count", equal_output_count)
        .with("input_count", input_count as u64)
        .with("confidence", confidence)
}