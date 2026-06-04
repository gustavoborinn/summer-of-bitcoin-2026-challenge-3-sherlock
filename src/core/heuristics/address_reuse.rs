// src/core/heuristics/address_reuse.rs

use crate::core::analyzer::script_classifier::{classify_output, OutputScriptType};
use crate::core::types::{HeuristicResult, PrevoutMap, RawTransaction};
use std::collections::{HashMap, HashSet};

/// Address Reuse heuristic.
///
/// # What it detects
/// The same scriptPubKey appearing in multiple transactions within the same
/// block — either as an output in two different txs, or as a prevout (input)
/// in one tx and an output in another. Address reuse weakens privacy and links
/// transactions to the same entity.
///
/// # Two-pass architecture
/// Pass 1 is performed in `block_analyzer::analyze_one_block` inline during
/// the first iteration over block transactions, building a
/// `HashMap<Vec<u8>, Vec<String>>` (scriptPubKey bytes → txids).
/// No extra parse is required — the index is built from already-parsed data.
///
/// Pass 2 is this function: checks each output and input prevout script
/// against the index. Fires if any script appears in ≥ 2 distinct txids.
///
/// # Confidence model
/// - `reused_script_count >= 3` → "high"
/// - `reused_script_count == 2` → "medium"
/// - `reused_script_count == 1` → "low"
///
/// # Known false positives
/// - High-frequency exchange deposit addresses appearing as outputs in many
///   txs within the same block.
/// - Mining pool payout addresses.
///
/// # OP_RETURN exclusion
/// OP_RETURN scripts are excluded — the same protocol identifier appearing
/// in multiple txs is not address reuse.
pub fn run(
    tx: &RawTransaction<'_>,
    prevout_map: &PrevoutMap,
    block_script_index: &HashMap<Vec<u8>, Vec<String>>,
) -> HeuristicResult {
    // Use Vec<u8> keys to unify lifetimes: output scripts borrow from the
    // parser buffer, prevout scripts borrow from PrevoutMap — different
    // lifetimes cannot coexist in a HashSet<&[u8]>.
    let mut checked: HashSet<Vec<u8>> = HashSet::new();
    let mut reused_count: usize = 0;

    // ── Output scripts ────────────────────────────────────────────────────────
    for out in &tx.outputs {
        let script = out.script_pubkey;
        if script.is_empty() {
            continue;
        }
        if classify_output(script) == OutputScriptType::OpReturn {
            continue;
        }
        if !checked.insert(script.to_vec()) {
            continue; // already evaluated this script in this tx
        }
        if let Some(txids) = block_script_index.get(script) {
            // The current transaction's own output is already in the block
            // index. Require at least two distinct txids to prove cross-tx
            // reuse rather than counting the output against itself.
            if txids.len() >= 2 {
                reused_count += 1;
            }
        }
    }

    // ── Input prevout scripts ─────────────────────────────────────────────────
    for inp in &tx.inputs {
        if let Some(prevout) = prevout_map.get(&inp.txid, inp.vout) {
            let script = prevout.script_pubkey.as_slice();
            if script.is_empty() {
                continue;
            }
            if classify_output(script) == OutputScriptType::OpReturn {
                continue;
            }
            if !checked.insert(script.to_vec()) {
                continue;
            }
            // A prevout script only appears in the index if another tx in
            // this block has an output to the same script. >= 2 is correct
            // because the prevout tx is from a previous block, not indexed here.
// For prevout scripts: the prevout tx is from a previous block and
            // is NOT in the index. len >= 1 means one tx in *this* block has
            // an output to the same script — that is cross-tx reuse.
            // (Contrast with output scripts where >= 2 is needed because the
            // current tx's own txid is already in the index.)
            if let Some(txids) = block_script_index.get(script) {
                if txids.len() >= 1 {
                    reused_count += 1;
                }
            }
        }
    }

    if reused_count == 0 {
        return HeuristicResult::not_detected();
    }

    let confidence = if reused_count >= 3 {
        "high"
    } else if reused_count == 2 {
        "medium"
    } else {
        "low"
    };

    HeuristicResult::detected()
        .with("reused_script_count", reused_count as u64)
        .with("confidence", confidence)
}
