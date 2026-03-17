use std::fmt;

/// Central error type for all Chain Lens operations.
///
/// Every variant maps to a distinct failure mode in protocol parsing or I/O.
/// No `unwrap()`, `expect()`, or panics propagate through this type.
#[derive(Debug)]
pub enum ChainError {
    /// The buffer was exhausted before the requested read completed.
    UnexpectedEof { context: &'static str },

    /// A VarInt first byte was valid but the continuation bytes were missing
    /// or formed an impossible encoding (e.g. non-minimal).
    InvalidVarInt { byte: u8 },

    /// A `blk*.dat` magic number didn't match 0xD9B4BEF9.
    InvalidMagic { expected: u32, got: u32 },

    /// Raw bytes claimed to be UTF-8 but were not.
    Utf8Error(std::str::Utf8Error),

    /// Underlying OS / file I/O error.
    IoError(std::io::Error),

    /// A field value was structurally legal but semantically invalid
    /// (e.g. duplicate prevout, missing prevout, out-of-range index).
    InvalidField { field: &'static str, detail: String },

    /// The computed Merkle root does not match the value in the block header.
    MerkleRootMismatch { computed: String, header: String },

    /// The coinbase transaction is malformed (missing, wrong txid, etc.).
    InvalidCoinbase { detail: String },

    /// The undo (rev*.dat) data is truncated or structurally invalid.
    InvalidUndoData { detail: String },

    /// Feature not yet implemented — used only during scaffolding.
    NotImplemented { feature: &'static str },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::UnexpectedEof { context } => {
                write!(f, "unexpected EOF while reading {context}")
            }
            ChainError::InvalidVarInt { byte } => {
                write!(f, "invalid VarInt leading byte: 0x{byte:02x}")
            }
            ChainError::InvalidMagic { expected, got } => {
                write!(
                    f,
                    "invalid block magic: expected 0x{expected:08x}, got 0x{got:08x}"
                )
            }
            ChainError::Utf8Error(e) => write!(f, "UTF-8 decode error: {e}"),
            ChainError::IoError(e) => write!(f, "I/O error: {e}"),
            ChainError::InvalidField { field, detail } => {
                write!(f, "invalid field '{field}': {detail}")
            }
            ChainError::MerkleRootMismatch { computed, header } => {
                write!(
                    f,
                    "merkle root mismatch: computed {computed}, header {header}"
                )
            }
            ChainError::InvalidCoinbase { detail } => {
                write!(f, "invalid coinbase transaction: {detail}")
            }
            ChainError::InvalidUndoData { detail } => {
                write!(f, "invalid undo data: {detail}")
            }
            ChainError::NotImplemented { feature } => {
                write!(f, "not implemented: {feature}")
            }
        }
    }
}

impl std::error::Error for ChainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ChainError::Utf8Error(e) => Some(e),
            ChainError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ChainError {
    fn from(e: std::io::Error) -> Self {
        ChainError::IoError(e)
    }
}

impl From<std::str::Utf8Error> for ChainError {
    fn from(e: std::str::Utf8Error) -> Self {
        ChainError::Utf8Error(e)
    }
}

/// Maps a `ChainError` to the stable error code string used in JSON output.
pub fn error_code(e: &ChainError) -> &'static str {
    match e {
        ChainError::UnexpectedEof { .. } => "UNEXPECTED_EOF",
        ChainError::InvalidVarInt { .. } => "INVALID_VARINT",
        ChainError::InvalidMagic { .. } => "INVALID_MAGIC",
        ChainError::Utf8Error(_) => "UTF8_ERROR",
        ChainError::IoError(_) => "IO_ERROR",
        ChainError::InvalidField { .. } => "INVALID_FIELD",
        ChainError::MerkleRootMismatch { .. } => "MERKLE_ROOT_MISMATCH",
        ChainError::InvalidCoinbase { .. } => "INVALID_COINBASE",
        ChainError::InvalidUndoData { .. } => "INVALID_UNDO_DATA",
        ChainError::NotImplemented { .. } => "NOT_IMPLEMENTED",
    }
}