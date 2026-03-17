// src/core/heuristics/op_return.rs

use crate::core::analyzer::script_classifier::{
    classify_output, decode_op_return_payload, op_return_protocol, OutputScriptType,
};
use crate::core::types::{HeuristicResult, RawTransaction};

/// OP_RETURN Analysis heuristic.
///
/// # What it detects
/// Transactions containing one or more OP_RETURN outputs. OP_RETURN outputs
/// embed arbitrary data in the blockchain and are provably unspendable.
///
/// # Detection logic
/// `detected = any output script starts with 0x6a (OP_RETURN)`
///
/// Reports: count of OP_RETURN outputs, index of first one, detected protocol.
///
/// # Confidence
/// Always "high" — OP_RETURN is structurally unambiguous.
///
/// # Protocol classification
/// Delegated to `script_classifier::op_return_protocol`:
/// - "omni"           — Omni Layer (starts with 0x6f6d6e69)
/// - "opentimestamps" — OpenTimestamps (starts with 0x0109f91102)
/// - "unknown"        — unrecognised protocol
pub fn run(tx: &RawTransaction<'_>) -> HeuristicResult {
    let mut op_return_indices: Vec<u64> = Vec::new();
    let mut first_protocol: Option<&'static str> = None;

    for (i, out) in tx.outputs.iter().enumerate() {
        if classify_output(out.script_pubkey) == OutputScriptType::OpReturn {
            op_return_indices.push(i as u64);
            if first_protocol.is_none() {
                let payload = decode_op_return_payload(out.script_pubkey);
                first_protocol = Some(op_return_protocol(&payload));
            }
        }
    }

    if op_return_indices.is_empty() {
        return HeuristicResult::not_detected();
    }

    HeuristicResult::detected()
        .with("op_return_count", op_return_indices.len() as u64)
        .with("first_index", op_return_indices[0])
        .with("protocol", first_protocol.expect("set in loop above: op_return_indices non-empty"))
        .with("confidence", "high")
}