// src/core/heuristics/cioh.rs

use crate::core::types::{HeuristicResult, RawTransaction};

/// Common Input Ownership Heuristic (CIOH).
///
/// # What it detects
/// Transactions where all inputs are assumed to belong to the same entity.
/// The foundational chain analysis assumption: if multiple UTXOs are spent
/// together, they were likely controlled by the same wallet.
///
/// # Detection logic
/// `detected = input_count > 1`
///
/// No script-type filtering, no value analysis. Any multi-input transaction
/// is flagged — downstream heuristics (coinjoin, consolidation) may override
/// or contextualize the result.
///
/// # Confidence model
/// - `input_count >= 3` → "high"   (strong co-spend signal)
/// - `input_count == 2` → "medium" (weak co-spend signal; many false positives)
/// - `input_count == 1` → not detected
///
/// # Known false positives
/// - **CoinJoin**: multiple owners co-sign intentionally; CIOH is the privacy
///   model being attacked, not evidence of ownership.
/// - **Payjoin / P2EP**: recipient contributes an input; two owners, one tx.
/// - **Exchange consolidations**: many UTXOs, same owner, but CIOH overstates
///   clustering confidence when combined with other signals.
///
/// # Note on coinbase
/// Coinbase transactions must not reach this function. The caller
/// (`block_analyzer`) skips coinbase before invoking heuristics.
pub fn run(tx: &RawTransaction<'_>) -> HeuristicResult {
    let input_count = tx.inputs.len();

    if input_count <= 1 {
        return HeuristicResult::not_detected();
    }

    let confidence = if input_count >= 3 { "high" } else { "medium" };

    HeuristicResult::detected()
        .with("input_count", input_count as u64)
        .with("confidence", confidence)
}