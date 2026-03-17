// src/core/analyzer/context.rs

use std::collections::{HashMap, HashSet};

/// Block-level context passed to per-transaction heuristics that require
/// cross-transaction state. Built once per block in `block_analyzer` during
/// pass 1; all fields are derived from already-parsed transactions.
///
/// Kept in a separate module to avoid circular imports between
/// `block_analyzer` (which calls heuristics) and `peeling_chain`
/// (which needs BlockContext).
pub struct BlockContext {
    /// scriptPubKey bytes → Vec<txid> for all non-OP_RETURN outputs in this block.
    /// Used by `address_reuse::run`.
    pub script_index: HashMap<Vec<u8>, Vec<String>>,

    /// (display_txid, vout) → display_txid_of_spending_tx for all inputs in
    /// this block (excluding coinbase). Used by `peeling_chain::run` to detect
    /// whether a given output was spent within the same block.
    pub spend_index: HashMap<(String, u32), String>,

    /// Set of all display-format txids in this block.
    /// Used by `peeling_chain::run` to determine whether the current tx's
    /// input came from another tx in the same block (predecessor link).
    pub block_txids: HashSet<String>,
}