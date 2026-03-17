// src/core/heuristics/self_transfer.rs

use crate::core::analyzer::script_classifier::{classify_output, OutputScriptType};
use crate::core::types::{HeuristicResult, PrevoutMap, RawTransaction};

/// Self-Transfer Detection heuristic.
///
/// # What it detects
/// Transactions where all spendable outputs appear to belong to the same
/// entity as the inputs — no observable "payment" component. All inputs and
/// all non-OP_RETURN outputs share the same script type.
///
/// # Detection logic
/// 1. Resolve input script types via prevout_map.
/// 2. Determine dominant input type (must be unanimous — no tie allowed).
/// 3. All non-OP_RETURN outputs must match that type.
/// 4. At least one input must be resolvable (otherwise no signal).
///
/// # Confidence model
/// - inputs >= 2 OR outputs >= 2, unanimous type match → "high"
/// - single input, single output, unanimous type match → "medium"
///   (could just be a normal same-type payment)
///
/// # Known false positives
/// - Normal payments between two parties who both use P2WPKH (very common).
/// - Change-only transactions (single input, single change output).
pub fn run(tx: &RawTransaction<'_>, prevout_map: &PrevoutMap) -> HeuristicResult {
    // Resolve input script types.
    let in_types: Vec<&'static str> = tx
        .inputs
        .iter()
        .filter_map(|inp| prevout_map.get(&inp.txid, inp.vout))
        .map(|pv| classify_output(&pv.script_pubkey).as_str())
        .filter(|&t| t != "op_return" && t != "unknown")
        .collect();

    if in_types.is_empty() {
        return HeuristicResult::not_detected();
    }

    // All resolved inputs must be the same type (unanimous — no tie-breaking needed).
    let dominant = in_types[0];
    if !in_types.iter().all(|&t| t == dominant) {
        return HeuristicResult::not_detected();
    }

    // All non-OP_RETURN outputs must also match.
    let spendable_out_types: Vec<&'static str> = tx
        .outputs
        .iter()
        .map(|o| classify_output(o.script_pubkey))
        .filter(|t| *t != OutputScriptType::OpReturn)
        .map(|t| t.as_str())
        .collect();

    if spendable_out_types.is_empty() {
        return HeuristicResult::not_detected();
    }

    if !spendable_out_types.iter().all(|&t| t == dominant) {
        return HeuristicResult::not_detected();
    }

    // Signal strength: more inputs or outputs = clearer self-transfer pattern.
    let confidence = if in_types.len() >= 2 || spendable_out_types.len() >= 2 {
        "high"
    } else {
        "medium"
    };

    HeuristicResult::detected()
        .with("script_type", dominant)
        .with("input_count", tx.inputs.len() as u64)
        .with("output_count", tx.outputs.len() as u64)
        .with("confidence", confidence)
}