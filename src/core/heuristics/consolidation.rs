// src/core/heuristics/consolidation.rs

use crate::core::analyzer::script_classifier::classify_output;
use crate::core::types::{HeuristicResult, PrevoutMap, RawTransaction};

/// Consolidation Detection heuristic.
///
/// # What it detects
/// Transactions that combine many inputs into few outputs — typically wallet
/// maintenance operations to reduce UTXO set size. Classic pattern:
/// N inputs (N ≥ 3) → 1 or 2 outputs of the same script type.
///
/// # Detection logic
/// `detected = input_count >= 3 && output_count <= 2`
///
/// Secondary signal: homogeneous script types across inputs and outputs
/// strengthen confidence (same wallet sweeping its own UTXOs).
///
/// # Confidence model
/// - `input_count >= 5 && homogeneous_types` → "high"
/// - `input_count >= 3 && homogeneous_types` → "medium"
/// - `input_count >= 3 && !homogeneous_types` → "low"
///
/// # Known false positives
/// - Exchange deposit sweeps: many customers → one hot wallet (different owners,
///   same script type → looks like consolidation).
/// - CoinJoin with a single output.
pub fn run(tx: &RawTransaction<'_>, prevout_map: &PrevoutMap) -> HeuristicResult {
    let input_count = tx.inputs.len();
    let output_count = tx.outputs.len();

    if input_count < 3 || output_count > 2 {
        return HeuristicResult::not_detected();
    }

    // Collect output script types for homogeneity check.
    let out_types: Vec<&str> = tx.outputs
        .iter()
        .map(|o| classify_output(o.script_pubkey).as_str())
        .collect();

    // Collect input prevout script types.
    let in_types: Vec<&str> = tx.inputs
        .iter()
        .filter_map(|inp| prevout_map.get(&inp.txid, inp.vout))
        .map(|pv| classify_output(&pv.script_pubkey).as_str())
        .collect();

    // Homogeneous = all inputs share one type AND all outputs share that type.
    // Note: inputs without prevout data are silently excluded from type analysis.
    // in_types.len() may be < input_count; homogeneity is best-effort.
    // If no prevout data is available at all, skip the homogeneity upgrade entirely.
    let homogeneous = if in_types.is_empty() {
        false
    } else {
        is_homogeneous(&in_types)
            && is_homogeneous(&out_types)
            && in_types.first() == out_types.first()
    };

    let confidence = if input_count >= 5 && homogeneous {
        "high"
    } else if homogeneous {
        "medium"
    } else {
        "low"
    };

    HeuristicResult::detected()
        .with("input_count", input_count as u64)
        .with("output_count", output_count as u64)
        .with("homogeneous_types", homogeneous)
        .with("confidence", confidence)
}

/// Returns true if all elements of the slice are equal and the slice is non-empty.
fn is_homogeneous(types: &[&str]) -> bool {
    match types.first() {
        None => false,
        Some(first) => types.iter().all(|t| t == first),
    }
}