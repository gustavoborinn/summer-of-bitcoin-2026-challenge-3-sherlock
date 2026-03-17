// src/core/heuristics/tx_classifier.rs — versão final

use crate::core::types::{TxAnalysis, TxClassification};

/// Transaction Classifier — aggregates heuristic results into a single
/// `TxClassification` enum value.
///
/// # Priority order (first matching rule wins)
/// 1. `coinjoin`      → Coinjoin
/// 2. `consolidation` → Consolidation
/// 3. `self_transfer` → SelfTransfer
/// 4. `cioh` && !`change_detection` → BatchPayment (proxy — see limitations)
/// 5. `cioh` OR `change_detection` → SimplePayment
/// 6. fallback → Unknown
///
/// # Known limitations (documented in APPROACH.md)
/// - BatchPayment also fires on 2-input 1-output transactions that did not
///   meet the 3-input consolidation threshold. These are micro-consolidations,
///   not batch payments. Root cause: `TxAnalysis` does not store `output_count`.
/// - The send-all SelfTransfer rule (`cioh=false && outputs==1`) is not
///   implemented because `output_count` is not available in `TxAnalysis`.
///   Adding `output_count` to `TxAnalysis` would fix both gaps.
pub fn classify(analysis: &TxAnalysis) -> TxClassification {
    let detected = |id: &str| -> bool {
        analysis
            .heuristics
            .get(id)
            .map(|h| h.detected)
            .unwrap_or(false)
    };

    // ── Rule 1: CoinJoin ──────────────────────────────────────────────────────
    if detected("coinjoin") {
        return TxClassification::Coinjoin;
    }

    // ── Rule 2: Consolidation ─────────────────────────────────────────────────
    if detected("consolidation") {
        return TxClassification::Consolidation;
    }

    // ── Rule 3: Self-transfer ─────────────────────────────────────────────────
    if detected("self_transfer") {
        return TxClassification::SelfTransfer;
    }

    // ── Rule 4: Batch payment ─────────────────────────────────────────────────
    // Proxy: CIOH fired (multi-input) AND change_detection did NOT fire
    // (change_detection requires exactly 2 outputs → absence implies != 2 outputs).
    // Combined with Rules 1-3 already cleared, this is a batch payment signal.
    // Known gap: also fires on 2-input 1-output txs (micro-consolidations below
    // the 3-input threshold). See module doc for details.
    if detected("cioh") && !detected("change_detection") {
        return TxClassification::BatchPayment;
    }

    // ── Rule 5: Simple payment ────────────────────────────────────────────────
    if detected("cioh") || detected("change_detection") {
        return TxClassification::SimplePayment;
    }

    // ── Fallback ──────────────────────────────────────────────────────────────
    TxClassification::Unknown
}