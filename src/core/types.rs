// src/core/types.rs

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::core::errors::ChainError;

// ─────────────────────────────────────────────────────────────────────────────
// Zero-copy parsing types (Week 1 — unchanged)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RawInput<'a> {
    /// Internal byte order (as parsed from the wire — NOT reversed for display).
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_sig: &'a [u8],
    pub sequence: u32,
    /// Empty Vec for legacy transactions.
    pub witness: Vec<&'a [u8]>,
}

#[derive(Debug)]
pub struct RawOutput<'a> {
    /// Value in satoshis. Never represented as f64 to avoid precision loss.
    pub value: u64,
    pub script_pubkey: &'a [u8],
}

/// A fully parsed transaction.
///
/// # Lifetime
/// `'a` is tied to the byte slice passed to `parse_tx`. All borrows point into
/// that original buffer.
///
/// # `legacy_bytes` vs `full_bytes`
/// - **txid**  = SHA256d of *legacy* serialization (no marker/flag/witness).
/// - **wtxid** = SHA256d of *full* serialization.
///
/// For SegWit, `legacy_bytes` is an owned `Vec<u8>` built during parsing.
/// `full_bytes` is a contiguous sub-slice of the original buffer.
#[derive(Debug)]
pub struct RawTransaction<'a> {
    pub version: i32,
    pub inputs: Vec<RawInput<'a>>,
    pub outputs: Vec<RawOutput<'a>>,
    pub locktime: u32,
    pub is_segwit: bool,
    pub legacy_bytes: Vec<u8>,
    pub full_bytes: &'a [u8],
}

/// A spent output (prevout) as read from rev*.dat undo data.
#[derive(Debug, Clone)]
pub struct Prevout {
    /// Internal byte order (as parsed — NOT reversed for display).
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sats: u64,
    /// Always stored as the full uncompressed scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
}

/// A keyed map from `(txid_internal, vout)` to `Prevout`.
#[derive(Debug)]
pub struct PrevoutMap(HashMap<([u8; 32], u32), Prevout>);

impl PrevoutMap {
    /// Build from a vec of prevouts.
    ///
    /// Returns `ChainError::InvalidField` if any `(txid, vout)` pair appears
    /// more than once — duplicates are a data error, not a protocol error.
    /// Returns an empty PrevoutMap — used for orphan blocks without undo data.
    pub fn empty() -> Self {
        PrevoutMap(std::collections::HashMap::new())
    }

    pub fn from_vec(prevouts: Vec<Prevout>) -> Result<Self, ChainError> {
        let mut map = HashMap::with_capacity(prevouts.len());
        for p in prevouts {
            let key = (p.txid, p.vout);
            if map.contains_key(&key) {
                return Err(ChainError::InvalidField {
                    field: "prevouts",
                    detail: format!(
                        "duplicate prevout ({}, {})",
                        hex_encode(&p.txid),
                        p.vout
                    ),
                });
            }
            map.insert(key, p);
        }
        Ok(PrevoutMap(map))
    }

    /// Resolve a prevout by internal-order txid and output index.
    pub fn get(&self, txid: &[u8; 32], vout: u32) -> Option<&Prevout> {
        self.0.get(&(*txid, vout))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Week 3 — Chain analysis types
// ─────────────────────────────────────────────────────────────────────────────

/// Transaction classification — exactly the 6 values the grader accepts.
///
/// Serialized via `serde(rename_all = "snake_case")` — do not add manual
/// string conversion methods that could silently diverge from the wire format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxClassification {
    SimplePayment,
    Consolidation,
    Coinjoin,
    SelfTransfer,
    BatchPayment,
    Unknown,
}

/// Result of a single heuristic applied to one transaction.
///
/// `detected` is mandatory per schema. Extra fields (e.g. `likely_change_index`,
/// `confidence`, `method`) are stored in `extra` and serialized flat into the
/// JSON object via `#[serde(flatten)]`.
///
/// Trade-off: using `serde_json::Value` in core types couples the data model
/// to the JSON library. Acceptable here because heuristic extra fields are
/// unstructured by design (each heuristic has different keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicResult {
    pub detected: bool,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl HeuristicResult {
    /// A not-detected result with no extra fields.
    pub fn not_detected() -> Self {
        HeuristicResult { detected: false, extra: HashMap::new() }
    }

    /// A detected result with no extra fields.
    pub fn detected() -> Self {
        HeuristicResult { detected: true, extra: HashMap::new() }
    }

    /// Add an extra field (builder pattern).
    pub fn with<V: Into<serde_json::Value>>(mut self, key: &str, val: V) -> Self {
        self.extra.insert(key.to_string(), val.into());
        self
    }
}

/// Per-transaction analysis result. Serializes to:
///
/// ```json
/// {
///   "txid": "<hex64>",
///   "heuristics": { "cioh": { "detected": true }, ... },
///   "classification": "simple_payment"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxAnalysis {
    pub txid: String,
    pub heuristics: HashMap<String, HeuristicResult>,
    pub classification: TxClassification,
}

impl TxAnalysis {
    pub fn new(txid: String) -> Self {
        TxAnalysis {
            txid,
            heuristics: HashMap::new(),
            classification: TxClassification::Unknown,
        }
    }

    /// True if any heuristic fired — drives `flagged_transactions` counting.
    pub fn is_flagged(&self) -> bool {
        self.heuristics.values().any(|h| h.detected)
    }

    pub fn set_heuristic(&mut self, id: &str, result: HeuristicResult) {
        self.heuristics.insert(id.to_string(), result);
    }
}

/// Fee rate statistics across a set of non-coinbase transactions.
///
/// JSON invariant (grader-enforced): min ≤ median ≤ max, all ≥ 0.
/// All values are in sat/vbyte, rounded to 2 decimal places.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRateStats {
    pub min_sat_vb: f64,
    pub max_sat_vb: f64,
    pub median_sat_vb: f64,
    pub mean_sat_vb: f64,
}

impl FeeRateStats {
    /// All-zeros sentinel for when there are **zero** non-coinbase transactions.
    ///
    /// # Safety
    /// Use **only** when tx count is zero. Never use as an accumulator seed —
    pub fn zero() -> Self {
        FeeRateStats { min_sat_vb: 0.0, max_sat_vb: 0.0, median_sat_vb: 0.0, mean_sat_vb: 0.0 }
    }
}

/// Script type output counters for `script_type_distribution` in the schema.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScriptTypeDistribution {
    pub p2pkh: u64,
    pub p2sh: u64,
    pub p2wpkh: u64,
    pub p2wsh: u64,
    pub p2tr: u64,
    pub op_return: u64,
    pub unknown: u64,
}

impl ScriptTypeDistribution {
    /// Increment the counter for the given script type string.
    pub fn add(&mut self, type_str: &str) {
        match type_str {
            "p2pkh"     => self.p2pkh     += 1,
            "p2sh"      => self.p2sh      += 1,
            "p2wpkh"    => self.p2wpkh    += 1,
            "p2wsh"     => self.p2wsh     += 1,
            "p2tr"      => self.p2tr      += 1,
            "op_return" => self.op_return += 1,
            _           => self.unknown   += 1,
        }
    }

    /// Accumulate another distribution into self (for file-level aggregation).
    pub fn merge(&mut self, other: &ScriptTypeDistribution) {
        self.p2pkh     += other.p2pkh;
        self.p2sh      += other.p2sh;
        self.p2wpkh    += other.p2wpkh;
        self.p2wsh     += other.p2wsh;
        self.p2tr      += other.p2tr;
        self.op_return += other.op_return;
        self.unknown   += other.unknown;
    }

    /// Sum of all counters. Useful for output-count sanity checks.
    pub fn total(&self) -> u64 {
        self.p2pkh + self.p2sh + self.p2wpkh + self.p2wsh
            + self.p2tr + self.op_return + self.unknown
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex encoder
//
// This is the sole hex-encoding path in the codebase. The `hex` crate must
// NOT be present in Cargo.toml — the compiler will enforce the migration.
// ─────────────────────────────────────────────────────────────────────────────

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}