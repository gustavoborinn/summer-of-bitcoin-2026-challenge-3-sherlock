// src/core/heuristics/peeling_chain.rs

use crate::core::analyzer::context::BlockContext;
use crate::core::analyzer::script_classifier::{classify_output, OutputScriptType};
use crate::core::types::{hex_encode, HeuristicResult, RawTransaction};

/// Peeling Chain Detection heuristic.
///
/// # What it detects
/// A sequence of transactions where a large UTXO is repeatedly split into one
/// small output (the payment) and one large output (the change), with the large
/// output being spent in a subsequent transaction in the same block.
///
/// # Detection logic (two-pass, block-scoped)
/// Pass 1 (in `block_analyzer`): builds `ctx.spend_index` mapping
///   `(txid, vout) → spending_txid` for all non-coinbase inputs in the block,
///   and `ctx.block_txids` containing all txids in this block.
///
/// Pass 2 (this function): a tx is a peeling chain link if:
///   1. Exactly 1 input.
///   2. Exactly 2 spendable (non-OP_RETURN) outputs.
///   3. Both outputs have different values (not a CoinJoin denomination).
///   4. The larger output is spent by another tx in the same block
///      (`spend_index` contains `(this_txid, large_vout)`).
///
/// # Confidence model
/// - Successor confirmed AND our input came from a tx in this block
///   (predecessor also visible) → "high"
/// - Successor confirmed, predecessor not in this block (start of chain)
///   → "medium"
///
/// # Known false positives
/// - Any 1-input 2-output tx where the larger output happens to be spent
///   in the same block for unrelated reasons.
///
/// # Block-scope limitation
/// Only detects chains spanning ≥ 2 transactions within the SAME block.
pub fn run(
    txid: &str,
    tx: &RawTransaction<'_>,
    ctx: &BlockContext,
) -> HeuristicResult {
    // Structural requirement: exactly 1 input.
    if tx.inputs.len() != 1 {
        return HeuristicResult::not_detected();
    }

    // Exactly 2 spendable (non-OP_RETURN) outputs.
    let spendable: Vec<(usize, u64)> = tx
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, o)| classify_output(o.script_pubkey) != OutputScriptType::OpReturn)
        .map(|(i, o)| (i, o.value))
        .collect();

    if spendable.len() != 2 {
        return HeuristicResult::not_detected();
    }

    if spendable[0].1 == spendable[1].1 {
        return HeuristicResult::not_detected();
    }
    // Identify larger (change) and smaller (payment) outputs.
    let (large_vout, large_value, small_vout, small_value) = if spendable[0].1 >= spendable[1].1 {
        (spendable[0].0 as u32, spendable[0].1, spendable[1].0 as u32, spendable[1].1)
    } else {
        (spendable[1].0 as u32, spendable[1].1, spendable[0].0 as u32, spendable[0].1)
    };
    // Ratio check: large must be >= 2x small to be a meaningful peel.
    if large_value < small_value.saturating_mul(2) {
        return HeuristicResult::not_detected();
    }

    // Check successor: is the large output spent by another tx in this block?
    let successor_txid = match ctx.spend_index.get(&(txid.to_string(), large_vout)) {
        Some(s) => s.clone(),
        None => return HeuristicResult::not_detected(),
    };

    // Check predecessor: did our input come from a tx in this block?
    // Compute display-format txid of our input's prevout.
    let mut rev = tx.inputs[0].txid;
    rev.reverse();
    let input_prevout_txid = hex_encode(&rev);

    // If the prevout tx is in this block, we are in the middle (or near end)
    // of a peeling chain — both links visible.
    let has_predecessor = ctx.block_txids.contains(&input_prevout_txid);

    let confidence = if has_predecessor { "high" } else { "medium" };

    HeuristicResult::detected()
        .with("large_output_vout", large_vout as u64)
        .with("small_output_vout", small_vout as u64)
        .with("successor_txid", successor_txid)
        .with("has_predecessor", has_predecessor)
        .with("confidence", confidence)
}