use num_bigint::BigUint;
use num_traits::One;

use crate::core::errors::ChainError;
use crate::core::io::buffer_reader::BufferReader;
use crate::core::types::Prevout;

const MAINNET_MAGIC: u32 = 0xD9B4BEF9;


// ─────────────────────────────────────────────────────────────────────────────
// Bitcoin Core internal VARINT (base-128, NOT CompactSize)
//
// Used for per-Coin fields in rev*.dat: height_and_coinbase, CompressAmount,
// and nSize. This is DIFFERENT from the P2P CompactSize used for counts.
//
// ReadVarInt from Bitcoin Core src/serialize.h:
//   read bytes with high bit as continuation flag, each contributes 7 bits.
//   After each continuation byte, n is incremented by 1 (bijective encoding).
// ─────────────────────────────────────────────────────────────────────────────

fn read_varint(r: &mut BufferReader<'_>) -> Result<u64, ChainError> {
    let mut n: u64 = 0;
    loop {
        let ch = r.read_u8()?;
        if n > (u64::MAX >> 7) {
            return Err(ChainError::InvalidVarInt { byte: 0 });
        }
        n = (n << 7) | (ch as u64 & 0x7F);
        if ch & 0x80 != 0 {
            if n == u64::MAX {
                return Err(ChainError::InvalidVarInt { byte: 0 });
            }
            n += 1;
        } else {
            return Ok(n);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DecompressAmount — exact port of Bitcoin Core src/compressor.cpp
// ─────────────────────────────────────────────────────────────────────────────

pub fn decompress_amount(mut x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    x -= 1;
    let e = (x % 10) as u32;
    x /= 10;
    let mut n: u64;
    if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        n = x * 10 + d;
    } else {
        n = x + 1;
    }
    for _ in 0..e {
        n *= 10;
    }
    n
}

// ─────────────────────────────────────────────────────────────────────────────
// secp256k1 point decompression
// ─────────────────────────────────────────────────────────────────────────────

fn secp256k1_p() -> BigUint {
    // p = 2^256 - 2^32 - 977
    // FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    let p_bytes: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xFF, 0xFF, 0xFC, 0x2F,
    ];
    BigUint::from_bytes_be(&p_bytes)
}

fn decompress_pubkey(x_bytes: &[u8; 32], parity: u8) -> Result<[u8; 65], ChainError> {
    let p = secp256k1_p();
    let x = BigUint::from_bytes_be(x_bytes);

    let x3 = x.modpow(&BigUint::from(3u32), &p);
    let y2 = (x3 + BigUint::from(7u32)) % &p;

    let exp = (&p + BigUint::one()) >> 2;
    let y = y2.modpow(&exp, &p);

    let y_parity = (y.to_bytes_be().last().copied().unwrap_or(0) & 1) as u8;
    let y_final = if y_parity == parity { y } else { &p - &y };

    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(x_bytes);
    let y_be = y_final.to_bytes_be();
    let offset = 32usize.saturating_sub(y_be.len());
    out[33 + offset..65].copy_from_slice(&y_be[y_be.len().saturating_sub(32)..]);

    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Script decompression
// ─────────────────────────────────────────────────────────────────────────────

fn decompress_script(nsize: u64, r: &mut BufferReader<'_>) -> Result<Vec<u8>, ChainError> {
    match nsize {
        0 => {
            let hash = r.read_bytes(20)?;
            let mut s = Vec::with_capacity(25);
            s.extend_from_slice(&[0x76, 0xa9, 0x14]);
            s.extend_from_slice(hash);
            s.extend_from_slice(&[0x88, 0xac]);
            Ok(s)
        }
        1 => {
            let hash = r.read_bytes(20)?;
            let mut s = Vec::with_capacity(23);
            s.extend_from_slice(&[0xa9, 0x14]);
            s.extend_from_slice(hash);
            s.push(0x87);
            Ok(s)
        }
        2 | 3 => {
            let x_bytes = r.read_bytes(32)?;
            let prefix = nsize as u8;
            let mut s = Vec::with_capacity(35);
            s.push(0x21);
            s.push(prefix);
            s.extend_from_slice(x_bytes);
            s.push(0xac);
            Ok(s)
        }
        4 | 5 => {
            let x_slice = r.read_bytes(32)?;
            let mut x_arr = [0u8; 32];
            x_arr.copy_from_slice(x_slice);
            let parity = (nsize - 4) as u8;
            let pubkey = decompress_pubkey(&x_arr, parity)?;
            let mut s = Vec::with_capacity(67);
            s.push(0x41);
            s.extend_from_slice(&pubkey);
            s.push(0xac);
            Ok(s)
        }
        n => {
            let len = (n - 6) as usize;
            let bytes = r.read_bytes(len)?;
            Ok(bytes.to_vec())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public types and parsing
// ─────────────────────────────────────────────────────────────────────────────

pub struct BlockUndo {
    pub prevouts: Vec<Vec<Prevout>>,
    /// Raw serialized bytes of this blockundo — used for checksum verification.
    /// checksum = SHA256d(block.header.prev_block_hash || raw_bytes)
    pub raw_bytes: Vec<u8>,
    /// 32-byte checksum read from rev*.dat immediately after the undo data.
    pub checksum: [u8; 32],
}

pub fn parse_undo_file(data: &[u8]) -> Result<Vec<BlockUndo>, ChainError> {
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

        let size = r.read_u32_le()? as usize;

        if r.remaining() < size + 32 {
            return Err(ChainError::UnexpectedEof { context: "undo_size" });
        }

        let undo_bytes = r.read_bytes(size)?;
        let raw_bytes = undo_bytes.to_vec();

        let checksum_slice = r.read_bytes(32)?;
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(checksum_slice);

        let mut block_undo = parse_block_undo(undo_bytes)?;
        block_undo.raw_bytes = raw_bytes;
        block_undo.checksum = checksum;
        blocks.push(block_undo);
    }

    Ok(blocks)
}

fn parse_block_undo(data: &[u8]) -> Result<BlockUndo, ChainError> {
    let mut r = BufferReader::new(data);
    let tx_count = r.read_compact_size()? as usize;

    let mut prevouts = Vec::with_capacity(tx_count);

    for _ in 0..tx_count {
        let input_count = r.read_compact_size()? as usize;
        let mut inputs = Vec::with_capacity(input_count);

        for _ in 0..input_count {
            // Coin serialization layout in rev*.dat:
            //
            //   VARINT(nHeight * 2)    — height without coinbase flag in LSB
            //   uint8(fCoinBase)       — coinbase flag as a SEPARATE byte (0x00 or 0x01)
            //   VARINT(compressed_val) — base-128 VarInt, decompress with decompress_amount()
            //   VARINT(nSize)          — base-128 VarInt, drives script decompression
            //
            // Empirically confirmed against blk04330.dat / rev04330.dat:
            // every Coin has a single byte between the code VARINT and the amount VARINT.
            // That byte is 0x00 for non-coinbase outputs (the common case) and 0x01
            // for coinbase outputs.  The code VARINT therefore stores nHeight*2 only.
            let _height_x2 = read_varint(&mut r)?;
            let _coinbase_flag = r.read_u8()?;
            let compressed_value = read_varint(&mut r)?;
            let value_sats = decompress_amount(compressed_value);
            let nsize = read_varint(&mut r)?;
            let script_pubkey = decompress_script(nsize, &mut r)?;

            inputs.push(Prevout {
                txid: [0u8; 32],
                vout: 0,
                value_sats,
                script_pubkey,
            });
        }

        prevouts.push(inputs);
    }

    Ok(BlockUndo { prevouts, raw_bytes: Vec::new(), checksum: [0u8; 32] })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompress_amount_zero() {
        assert_eq!(decompress_amount(0), 0);
    }

    #[test]
    fn decompress_amount_known_values() {
        // Verified against Bitcoin Core CompressAmount/DecompressAmount round-trips.
        // Each pair: (compressed_value, expected_satoshis)
        let cases: &[(u64, u64)] = &[
            (0,          0),
            (1,          1),           // 1 sat
            (2,          10),          // 10 sats
            (3,          100),
            (4,          1_000),
            (5,          10_000),
            (6,          100_000),
            (7,          1_000_000),   // 0.01 BTC
            (50,         5_000_000_000), // 50 BTC (block reward)
            (21_000_000, 2_100_000_000_000_000), // 21M BTC supply cap
        ];
        for &(compressed, expected) in cases {
            assert_eq!(
                decompress_amount(compressed),
                expected,
                "decompress({}) should be {}",
                compressed,
                expected
            );
        }
    }

    #[test]
    fn secp256k1_decompress_genesis_pubkey() {
        // Satoshi's genesis block pubkey (compressed x + parity)
        let x: [u8; 32] = [
            0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30,
            0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea,
            0x1f, 0x61, 0xde, 0xb6,
        ];
        let result = decompress_pubkey(&x, 1);
        assert!(result.is_ok(), "decompress failed: {:?}", result.err());
        let pk = result.unwrap();
        assert_eq!(pk[0], 0x04);
        assert_eq!(&pk[1..33], &x);
    }
}