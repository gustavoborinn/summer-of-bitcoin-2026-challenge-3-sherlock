use sha2::{Digest, Sha256};

use crate::core::errors::ChainError;
use crate::core::io::buffer_reader::BufferReader;
use crate::core::parser::transaction::parse_tx;
use crate::core::types::RawTransaction;

const MAINNET_MAGIC: u32 = 0xD9B4BEF9;

// ─── Types ───────────────────────────────────────────────────────────────────

pub struct BlockHeader {
    pub version: i32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}

pub struct ParsedBlock {
    pub header: BlockHeader,
    pub block_hash: [u8; 32],
    /// Raw bytes of each transaction, owned, for re-parsing by the analyzer.
    pub transactions: Vec<Vec<u8>>,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

pub fn hex_enc(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, &x| {
        s.push_str(&format!("{:02x}", x));
        s
    })
}

pub fn hash_display(h: &[u8; 32]) -> String {
    let mut rev = *h;
    rev.reverse();
    hex_enc(&rev)
}

// ─── Merkle ──────────────────────────────────────────────────────────────────

pub fn compute_merkle_root(txids: &[[u8; 32]]) -> Option<[u8; 32]> {
    if txids.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = txids.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&left);
            combined[32..].copy_from_slice(&right);
            next.push(sha256d(&combined));
            i += 2;
        }
        level = next;
    }
    Some(level[0])
}

// ─── Block file parser ───────────────────────────────────────────────────────

pub fn parse_block_file(data: &[u8]) -> Result<Vec<ParsedBlock>, ChainError> {
    let mut r = BufferReader::new(data);
    let mut blocks = Vec::new();

    while r.remaining() > 0 {
        if r.remaining() < 8 {
            break;
        }
        let magic = r.read_u32_le()?;
        if magic == 0 {
            break;
        }
        if magic != MAINNET_MAGIC {
            return Err(ChainError::InvalidMagic { expected: MAINNET_MAGIC, got: magic });
        }
        let block_size = r.read_u32_le()? as usize;
        if r.remaining() < block_size {
            return Err(ChainError::UnexpectedEof { context: "block_size" });
        }
        let block_start = r.position();
        r.read_bytes(block_size)?;
        let block_slice = &data[block_start..block_start + block_size];
        let blk_idx = blocks.len();
        let block = match parse_single_block(block_slice) {
            Ok(b) => b,
            Err(e) => {
                        return Err(e);
            }
        };
        blocks.push(block);
    }

    Ok(blocks)
}

fn parse_single_block(data: &[u8]) -> Result<ParsedBlock, ChainError> {
    let mut r = BufferReader::new(data);

    if r.remaining() < 80 {
        return Err(ChainError::UnexpectedEof { context: "block_data" });
    }

    let raw_header_bytes = r.read_bytes(80)?;
    let mut raw_header = [0u8; 80];
    raw_header.copy_from_slice(raw_header_bytes);

    let mut hr = BufferReader::new(&raw_header);
    let version = hr.read_i32_le()?;
    let prev_hash = hr.read_bytes(32)?;
    let merkle_bytes = hr.read_bytes(32)?;
    let timestamp = hr.read_u32_le()?;
    let bits = hr.read_u32_le()?;
    let nonce = hr.read_u32_le()?;

    let mut prev_block_hash = [0u8; 32];
    prev_block_hash.copy_from_slice(prev_hash);
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(merkle_bytes);

    let block_hash = sha256d(&raw_header);

    let header = BlockHeader { version, prev_block_hash, merkle_root, timestamp, bits, nonce };

    let tx_count = r.read_compact_size()? as usize;
    if tx_count == 0 {
        return Err(ChainError::InvalidField {
            field: "tx_count",
            detail: "block has no transactions".into(),
        });
    }

    let mut transactions: Vec<Vec<u8>> = Vec::with_capacity(tx_count);
    let mut txids: Vec<[u8; 32]> = Vec::with_capacity(tx_count);

    for tx_idx in 0..tx_count {
        let tx_start = r.position();
        let remaining_data = &data[tx_start..];
        let parsed = match parse_tx(remaining_data) {
            Ok(p) => p,
            Err(e) => {
                        return Err(e);
            }
        };
        let tx_len = parsed.full_bytes.len();
        let wire_consumed = tx_start; // before push

        let txid = sha256d(&parsed.legacy_bytes);
        txids.push(txid);

        if tx_idx == 0 {
            validate_coinbase(&parsed)?;
        }

        if tx_start + tx_len > data.len() {
                return Err(ChainError::UnexpectedEof { context: "tx_boundary" });
        }
        transactions.push(data[tx_start..tx_start + tx_len].to_vec());
        r.read_bytes(tx_len)?;
        let _ = wire_consumed;
    }

    let computed_root = compute_merkle_root(&txids).ok_or(ChainError::InvalidField {
        field: "merkle",
        detail: "no transactions".into(),
    })?;

    if computed_root != merkle_root {
        return Err(ChainError::MerkleRootMismatch {
            computed: hash_display(&computed_root),
            header: hash_display(&merkle_root),
        });
    }

    Ok(ParsedBlock { header, block_hash, transactions })
}

fn validate_coinbase(tx: &RawTransaction<'_>) -> Result<(), ChainError> {
    let inp = tx.inputs.first().ok_or(ChainError::InvalidCoinbase {
        detail: "no inputs".into(),
    })?;
    if inp.txid != [0u8; 32] {
        return Err(ChainError::InvalidCoinbase {
            detail: "coinbase txid is not all zeros".into(),
        });
    }
    if inp.vout != 0xFFFF_FFFF {
        return Err(ChainError::InvalidCoinbase {
            detail: "coinbase vout is not 0xFFFFFFFF".into(),
        });
    }
    Ok(())
}