// src/core/heuristics/change_detection.rs

use crate::core::analyzer::script_classifier::{classify_output, OutputScriptType};
use crate::core::types::{HeuristicResult, PrevoutMap, RawTransaction};

/// Change Detection heuristic.
///
/// # What it detects
/// The likely change output in a 2-output transaction — the output returning
/// funds to the sender vs. the output paying the recipient.
///
/// # Detection logic
/// Only applied to transactions with exactly 2 outputs. Methods tried in
/// priority order; first match wins:
///
/// 1. `script_type_match`  — change output's script type matches input type(s).
/// 2. `round_number_payment` — payment is a round-number amount; non-round is change.
/// 3. `op_return_companion`  — one output is OP_RETURN; the other must be change.
/// 4. `position`           — fallback: index 1 preferred (many wallets put change last).
///
/// # Confidence model
/// - `script_type_match`      → "high"
/// - `round_number_payment`   → "medium"
/// - `op_return_companion`    → "high"
/// - `position`               → "low"
///
/// # Known false positives
/// - Consolidations: no real change, but script_type_match fires anyway.
/// - Self-transfers: both outputs belong to sender.
/// - Anti-analysis wallets: deliberately mismatch change script type.
/// - Send-all: no change output; position fallback fires spuriously.
pub fn run(tx: &RawTransaction<'_>, prevout_map: &PrevoutMap) -> HeuristicResult {
    // Only meaningful for exactly 2 outputs.
    if tx.outputs.len() != 2 {
        return HeuristicResult::not_detected();
    }

    // Coinbase guard (belt-and-suspenders; caller should never send coinbase here).
    if tx.inputs.is_empty() {
        return HeuristicResult::not_detected();
    }

    // Classify each output's script type.
    let out0_type = classify_output(tx.outputs[0].script_pubkey);
    let out1_type = classify_output(tx.outputs[1].script_pubkey);

    // ── Method 1: OP_RETURN companion ────────────────────────────────────────
    // If one output is OP_RETURN, the other is definitionally change/payment
    // back to sender (OP_RETURN carries no spendable value).
    if out0_type == OutputScriptType::OpReturn {
        return HeuristicResult::detected()
            .with("likely_change_index", 1u64)
            .with("method", "op_return_companion")
            .with("confidence", "high");
    }
    if out1_type == OutputScriptType::OpReturn {
        return HeuristicResult::detected()
            .with("likely_change_index", 0u64)
            .with("method", "op_return_companion")
            .with("confidence", "high");
    }

    // ── Method 2: Script type match ──────────────────────────────────────────
    // Determine the dominant input script type.
    let dominant_input_type = dominant_input_type(tx, prevout_map);

    if let Some(input_type_str) = dominant_input_type {
        let out0_str = out0_type.as_str();
        let out1_str = out1_type.as_str();

        let out0_matches = script_types_compatible(input_type_str, out0_str);
        let out1_matches = script_types_compatible(input_type_str, out1_str);

        // Exactly one output matches the input type → that one is likely change.
        if out0_matches && !out1_matches {
            return HeuristicResult::detected()
                .with("likely_change_index", 0u64)
                .with("method", "script_type_match")
                .with("confidence", "high");
        }
        if out1_matches && !out0_matches {
            return HeuristicResult::detected()
                .with("likely_change_index", 1u64)
                .with("method", "script_type_match")
                .with("confidence", "high");
        }
        // Both match or neither matches → fall through to next method.
    }

    // ── Method 3: Round number payment ───────────────────────────────────────
    // A round-number output is more likely to be the intentional payment;
    // the non-round output is more likely to be change (residual).
    let val0 = tx.outputs[0].value;
    let val1 = tx.outputs[1].value;
    let round0 = is_round_number(val0);
    let round1 = is_round_number(val1);

    if round0 && !round1 {
        // output 0 is the round payment → output 1 is change
        return HeuristicResult::detected()
            .with("likely_change_index", 1u64)
            .with("method", "round_number_payment")
            .with("confidence", "medium");
    }
    if round1 && !round0 {
        // output 1 is the round payment → output 0 is change
        return HeuristicResult::detected()
            .with("likely_change_index", 0u64)
            .with("method", "round_number_payment")
            .with("confidence", "medium");
    }

    // ── Method 4: Position fallback ──────────────────────────────────────────
    // Many wallets place change at index 1 (payment first, change last).
    // This is the weakest signal — low confidence.
    HeuristicResult::detected()
        .with("likely_change_index", 1u64)
        .with("method", "position")
        .with("confidence", "low")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Determine the dominant input script type across all inputs in a transaction.
///
/// "Dominant" means the type that appears most frequently. Returns `None` if
/// all inputs are unresolvable (no prevout data) or all classify as `Unknown`.
///
/// Returns the output script type string of the prevout (not the input spend
/// type) because change detection compares prevout type → output type.
fn dominant_input_type<'a>(
    tx: &'a RawTransaction<'_>,
    prevout_map: &'a PrevoutMap,
) -> Option<&'static str> {
    let mut counts: [u32; 7] = [0; 7]; // indexed by OutputScriptType ordinal
    let mut total = 0u32;

    for inp in &tx.inputs {
        if let Some(prevout) = prevout_map.get(&inp.txid, inp.vout) {
            let t = classify_output(&prevout.script_pubkey);
            // Skip OP_RETURN and Unknown inputs — they carry no ownership signal.
            match t {
                OutputScriptType::Unknown | OutputScriptType::OpReturn => {}
                _ => {
                    counts[type_ordinal(&t)] += 1;
                    total += 1;
                }
            }
        }
    }

// dominant_input_type — substituir o bloco de find máximo:

    if total == 0 {
        return None;
    }

    // If two types tie, there is no dominant type — fall through to next method.
    // This prevents non-deterministic results from HashMap iteration order.
    let max_count = counts.iter().copied().max().unwrap_or(0);
    if counts.iter().filter(|&&c| c == max_count).count() > 1 {
        return None;
    }

    let max_idx = counts
        .iter()
        .enumerate()
        .position(|(_, &c)| c == max_count)?;

    Some(ordinal_to_str(max_idx))
}

/// Map `OutputScriptType` to a stable array index for counting.
fn type_ordinal(t: &OutputScriptType) -> usize {
    match t {
        OutputScriptType::P2PKH    => 0,
        OutputScriptType::P2SH     => 1,
        OutputScriptType::P2WPKH   => 2,
        OutputScriptType::P2WSH    => 3,
        OutputScriptType::P2TR     => 4,
        OutputScriptType::OpReturn => 5,
        OutputScriptType::Unknown  => 6,
    }
}

/// Map array index back to the script type string.
fn ordinal_to_str(idx: usize) -> &'static str {
    match idx {
        0 => "p2pkh",
        1 => "p2sh",
        2 => "p2wpkh",
        3 => "p2wsh",
        4 => "p2tr",
        5 => "op_return",
        _ => "unknown", // unreachable: indices 5-6 (OpReturn/Unknown) are never incremented
    }
}

/// Returns true if an input of `input_type` would naturally produce change
/// of `output_type`. Handles wrapped SegWit (P2SH inputs → P2SH outputs).
///
/// The mapping is:
///   p2pkh       → p2pkh
///   p2sh        → p2sh   (covers P2SH-P2WPKH, P2SH-P2WSH wrapped inputs)
///   p2wpkh      → p2wpkh
///   p2wsh       → p2wsh
///   p2tr        → p2tr
fn script_types_compatible(input_type: &str, output_type: &str) -> bool {
    input_type == output_type
}

/// Returns true if `value_sats` is a "round number" payment amount.
///
/// Definition: value is a non-zero multiple of 10_000 sats AND ≥ 100_000 sats.
/// Rationale: payments denominated in round BTC sub-units (0.001 BTC = 100_000
/// sats, 0.01 BTC = 1_000_000 sats) are characteristic of human-chosen payment
/// amounts. The 100_000 sat floor avoids flagging dust-level round numbers.
///
/// Known limitation: this fires on consolidation outputs and exchange
/// withdrawals which also tend to be round numbers.
fn is_round_number(value_sats: u64) -> bool {
    value_sats >= 100_000 && value_sats % 10_000 == 0
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(detected: bool, method: &str, idx: u64, confidence: &str) -> HeuristicResult {
        if !detected {
            return HeuristicResult::not_detected();
        }
        HeuristicResult::detected()
            .with("likely_change_index", idx)
            .with("method", method)
            .with("confidence", confidence)
    }

    #[test]
    fn round_number_thresholds() {
        assert!(!is_round_number(0));
        assert!(!is_round_number(546));          // dust
        assert!(!is_round_number(99_999));        // below floor
        assert!(!is_round_number(100_001));       // not multiple of 10_000
        assert!(is_round_number(100_000));        // exactly 0.001 BTC
        assert!(is_round_number(1_000_000));      // 0.01 BTC
        assert!(is_round_number(10_000_000));     // 0.1 BTC
        assert!(is_round_number(100_000_000));    // 1 BTC
    }

    #[test]
    fn script_type_compat_identity() {
        assert!(script_types_compatible("p2wpkh", "p2wpkh"));
        assert!(script_types_compatible("p2tr", "p2tr"));
        assert!(script_types_compatible("p2pkh", "p2pkh"));
        assert!(!script_types_compatible("p2wpkh", "p2tr"));
        assert!(!script_types_compatible("p2pkh", "p2wpkh"));
    }
}