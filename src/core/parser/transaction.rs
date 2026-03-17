use crate::core::errors::ChainError;
use crate::core::io::BufferReader;
use crate::core::types::{RawInput, RawOutput, RawTransaction};

/// Parse a raw Bitcoin transaction from a byte slice.
///
/// Returns a `RawTransaction<'a>` whose borrowed fields point directly into
/// `data` (zero-copy). The only allocation is `legacy_bytes` (owned `Vec<u8>`)
/// which reconstructs the non-witness serialization needed for txid hashing.
///
/// # Wire format
/// ```text
/// [version: i32 le]
/// [marker: 0x00, flag: 0x01]  ← SegWit only
/// [input_count: CompactSize]
/// [inputs: ...]
/// [output_count: CompactSize]
/// [outputs: ...]
/// [witness: ...]               ← SegWit only, one stack per input
/// [locktime: u32 le]
/// ```
pub fn parse_tx<'a>(data: &'a [u8]) -> Result<RawTransaction<'a>, ChainError> {
    let mut r = BufferReader::new(data);

    // ── version ──────────────────────────────────────────────────────────────
    let version = r.read_i32_le()?;

    // ── SegWit detection ─────────────────────────────────────────────────────
    // Peek at the next byte. If it is 0x00 this is the SegWit marker; read the
    // flag byte (must be 0x01). Otherwise it is the input count CompactSize.
    let is_segwit;
    let input_count: u64;

    let peek = r.read_u8()?;
    if peek == 0x00 {
        // SegWit transaction
        let flag = r.read_u8()?;
        if flag != 0x01 {
            return Err(ChainError::InvalidField {
                field: "segwit_flag",
                detail: format!("expected 0x01, got 0x{flag:02x}"),
            });
        }
        is_segwit = true;
        input_count = r.read_compact_size()?;
    } else {
        // `peek` was the first byte of the CompactSize for input count.
        // Re-feed it: CompactSize values < 0xfd are just the byte itself.
        is_segwit = false;
        input_count = decode_compact_size_with_first_byte(&mut r, peek)?;
    }

    // ── inputs ───────────────────────────────────────────────────────────────
    if input_count == 0 {
        return Err(ChainError::InvalidField {
            field: "input_count",
            detail: "transaction must have at least one input".into(),
        });
    }

    let mut inputs: Vec<RawInput<'a>> = Vec::with_capacity(input_count as usize);
    for _ in 0..input_count {
        let txid_bytes = r.read_bytes(32)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(txid_bytes);

        let vout = r.read_u32_le()?;
        let script_len = r.read_compact_size()? as usize;
        let script_sig = r.read_bytes(script_len)?;
        let sequence = r.read_u32_le()?;

        inputs.push(RawInput {
            txid,
            vout,
            script_sig,
            sequence,
            witness: Vec::new(), // filled below for SegWit
        });
    }

    // ── outputs ──────────────────────────────────────────────────────────────
    let output_count = r.read_compact_size()? as usize;
    let mut outputs: Vec<RawOutput<'a>> = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let value = r.read_u64_le()?;
        let script_len = r.read_compact_size()? as usize;
        let script_pubkey = r.read_bytes(script_len)?;
        outputs.push(RawOutput { value, script_pubkey });
    }

    // ── witness ──────────────────────────────────────────────────────────────
    if is_segwit {
        for inp in inputs.iter_mut() {
            let item_count = r.read_compact_size()? as usize;
            let mut stack: Vec<&'a [u8]> = Vec::with_capacity(item_count);
            for _ in 0..item_count {
                let item_len = r.read_compact_size()? as usize;
                let item = r.read_bytes(item_len)?;
                stack.push(item);
            }
            inp.witness = stack;
        }
    }

    // ── locktime ─────────────────────────────────────────────────────────────
    let locktime = r.read_u32_le()?;

    // ── slices for hashing ───────────────────────────────────────────────────
    // full_bytes: everything consumed from `data`.
    let consumed = r.position();
    let full_bytes = &data[..consumed];

    // legacy_bytes: re-serialized without marker/flag/witness.
    // This cannot be a zero-copy slice for SegWit transactions because the
    // witness data is interleaved in the wire format.
    let legacy_bytes = build_legacy_serialization(version, &inputs, &outputs, locktime);

    Ok(RawTransaction {
        version,
        inputs,
        outputs,
        locktime,
        is_segwit,
        legacy_bytes,
        full_bytes,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Decode a CompactSize integer when the first byte has already been consumed.
///
/// For values < 0xfd the first byte IS the value (no continuation bytes).
/// For 0xfd/0xfe/0xff we still need to read the continuation from `r`.
#[inline]
fn decode_compact_size_with_first_byte(
    r: &mut BufferReader<'_>,
    first: u8,
) -> Result<u64, ChainError> {
    match first {
        0x00..=0xfc => Ok(first as u64),
        0xfd => {
            let v = r.read_u16_le().map_err(|_| ChainError::InvalidVarInt { byte: first })?;
            Ok(v as u64)
        }
        0xfe => {
            let v = r.read_u32_le().map_err(|_| ChainError::InvalidVarInt { byte: first })?;
            Ok(v as u64)
        }
        0xff => {
            let v = r.read_u64_le().map_err(|_| ChainError::InvalidVarInt { byte: first })?;
            Ok(v)
        }
    }
}

/// Serialize a CompactSize integer into `out`.
fn write_compact_size(out: &mut Vec<u8>, v: u64) {
    match v {
        0x00..=0xfc => out.push(v as u8),
        0x0000_fd..=0x0000_ffff => {
            out.push(0xfd);
            out.extend_from_slice(&(v as u16).to_le_bytes());
        }
        0x0001_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(v as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
}

/// Reconstruct the legacy (non-witness) serialization.
///
/// Layout: version (4) | inputs | outputs | locktime (4)
/// No marker, flag, or witness data.
fn build_legacy_serialization(
    version: i32,
    inputs: &[RawInput<'_>],
    outputs: &[RawOutput<'_>],
    locktime: u32,
) -> Vec<u8> {
    // Pre-compute a rough capacity to avoid repeated reallocs.
    let approx = 4                                          // version
        + 9                                                 // input count CompactSize (max)
        + inputs.iter().map(|i| 32 + 4 + 9 + i.script_sig.len() + 4).sum::<usize>()
        + 9                                                 // output count CompactSize
        + outputs.iter().map(|o| 8 + 9 + o.script_pubkey.len()).sum::<usize>()
        + 4;                                                // locktime
    let mut out = Vec::with_capacity(approx);

    out.extend_from_slice(&version.to_le_bytes());

    write_compact_size(&mut out, inputs.len() as u64);
    for inp in inputs {
        out.extend_from_slice(&inp.txid);
        out.extend_from_slice(&inp.vout.to_le_bytes());
        write_compact_size(&mut out, inp.script_sig.len() as u64);
        out.extend_from_slice(inp.script_sig);
        out.extend_from_slice(&inp.sequence.to_le_bytes());
    }

    write_compact_size(&mut out, outputs.len() as u64);
    for o in outputs {
        out.extend_from_slice(&o.value.to_le_bytes());
        write_compact_size(&mut out, o.script_pubkey.len() as u64);
        out.extend_from_slice(o.script_pubkey);
    }

    out.extend_from_slice(&locktime.to_le_bytes());
    out
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ── tx_legacy_p2pkh ──────────────────────────────────────────────────────

    const TX_LEGACY_P2PKH: &str =
        "020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff\
         02b0040000000000001976a914010101010101010101010101010101010101010188ac\
         00000000000000000a6a08736f622d3230323600000000";

    #[test]
    fn parse_legacy_p2pkh_structure() {
        let raw = from_hex(TX_LEGACY_P2PKH);
        let tx = parse_tx(&raw).unwrap();

        assert!(!tx.is_segwit, "must be legacy");
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.locktime, 0);
        assert_eq!(tx.version, 2);
        // Legacy: all witnesses must be empty
        assert!(tx.inputs[0].witness.is_empty());
    }

    #[test]
    fn parse_legacy_p2pkh_legacy_bytes_roundtrip() {
        let raw = from_hex(TX_LEGACY_P2PKH);
        let tx = parse_tx(&raw).unwrap();
        // For a legacy transaction, legacy_bytes must equal full_bytes.
        assert_eq!(tx.legacy_bytes, tx.full_bytes,
            "legacy tx: legacy_bytes must equal full wire bytes");
    }

    // ── tx_segwit_p2wpkh_p2tr ────────────────────────────────────────────────

    const TX_SEGWIT_P2WPKH_P2TR: &str =
        "0200000000010122222222222222222222222222222222222222222222222222222222222222220100000000\
         feffffff02102700000000000016001403030303030303030303030303030303030303038813000000000000\
         225120040404040404040404040404040404040404040404040404040404040404040402\
         471e5180f383a5dcf31ae239e5999f8e6bc8928cd7bbc6c47dc0c596703d009d141c49d1197302d0e4af7\
         dad5035654059faffed5bce60ffbe83a313b957168e894a497524e0a5b421b7934f06d9b55e5d766c1766\
         e4958d7fde1d6c81cdc0dd99e07d65ea8642d86b9000000000";

    #[test]
    fn parse_segwit_p2wpkh_p2tr_structure() {
        let raw = from_hex(TX_SEGWIT_P2WPKH_P2TR);
        let tx = parse_tx(&raw).unwrap();

        assert!(tx.is_segwit, "must be segwit");
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.locktime, 0);
        // The witness for this p2wpkh spend has 2 items: signature + pubkey.
        assert_eq!(tx.inputs[0].witness.len(), 2,
            "p2wpkh witness must have 2 items (sig + pubkey)");
    }

    #[test]
    fn parse_segwit_legacy_bytes_differ_from_full() {
        let raw = from_hex(TX_SEGWIT_P2WPKH_P2TR);
        let tx = parse_tx(&raw).unwrap();
        // SegWit: legacy_bytes strip marker/flag/witness → shorter than full.
        assert!(
            tx.legacy_bytes.len() < tx.full_bytes.len(),
            "legacy_bytes ({}) must be shorter than full_bytes ({}) for segwit",
            tx.legacy_bytes.len(),
            tx.full_bytes.len()
        );
    }

    // ── prevouts_unordered ───────────────────────────────────────────────────

    const TX_PREVOUTS_UNORDERED: &str =
        "02000000021032547698badcfeefcdab89674523011032547698badcfeefcdab89674523010000000000\
         ffffffff00112233445566778899aabbccddeeffffeeddccbbaa998877665544332211000100000000\
         fdffffff02b80b0000000000001600142323232323232323232323232323232323232323\
         e803000000000000225120242424242424242424242424242424242424242424242424242424242424242400000000";

    #[test]
    fn parse_prevouts_unordered_inputs() {
        let raw = from_hex(TX_PREVOUTS_UNORDERED);
        let tx = parse_tx(&raw).unwrap();

        assert!(!tx.is_segwit);
        assert_eq!(tx.inputs.len(), 2);
        // First input: sequence 0xffffffff
        assert_eq!(tx.inputs[0].sequence, 0xffff_ffff,
            "input[0] sequence must be 0xffffffff");
        // Second input: sequence 0xfffffffd (RBF signal)
        assert_eq!(tx.inputs[1].sequence, 0xffff_fffd,
            "input[1] sequence must be 0xfffffffd");
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.locktime, 0);
    }

    // ── segwit_nested_scriptsig_empty_witness_item ───────────────────────────

    const TX_SEGWIT_NESTED: &str =
        "02000000000101010101010101010101010101010101019f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f\
         00000000171600142727272727272727272727272727272727272727fdffffff02401f000000000000\
         1600142828282828282828282828282828282828282828e80300000000000017a9142929292929292929\
         29292929292929292929292987030048e28d0d6090024c26f086e70f9dc900a30cd42c9e8a2a82c35d\
         536b5c49a0fddf8ed12d368149842cfab087ad7d16704e3dd7be4e7dd068f52639f488fafb1873f1c5\
         af86eb5271ea218dd3f8159ec9b7ec002f9153262917c2a9cddf343ce4eb0b58865f975d2f2351fb00000000";

    #[test]
    fn parse_segwit_nested_empty_witness_item() {
        let raw = from_hex(TX_SEGWIT_NESTED);
        let tx = parse_tx(&raw).unwrap();

        assert!(tx.is_segwit);
        assert_eq!(tx.inputs.len(), 1);
        // Witness: [empty_item, sig, pubkey] — 3 items, first is 0-length.
        assert_eq!(tx.inputs[0].witness.len(), 3,
            "p2sh-p2wpkh witness has 3 items (empty + sig + pubkey)");
        assert_eq!(tx.inputs[0].witness[0].len(), 0,
            "first witness item must be empty (0 bytes)");
    }

    // ── multi_input_segwit ───────────────────────────────────────────────────

    const TX_MULTI_INPUT_SEGWIT: &str =
        "02000000000102a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\
         0000000000feffffffb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\
         0200000000fdffffff0210270000000000001600141313131313131313131313131313131313131313\
         e02e00000000000022512014141414141414141414141414141414141414141414141414141414141414\
         140247eed60c73dec1a4307bb6ade00521a58737c9e184e5f42329a9d82f63456c886ade14624e2f58\
         2c43767fffc7d06a49772d53847b711e86cb86cb46d018d9363b01f417e074a55421688bc8d5d9d8ab\
         2ef6065ad8285a8faf92ca89371c9eb7478ec091bb36914b90440000000000";

    #[test]
    fn parse_multi_input_segwit_structure() {
        let raw = from_hex(TX_MULTI_INPUT_SEGWIT);
        let tx = parse_tx(&raw).unwrap();

        assert!(tx.is_segwit);
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs.len(), 2);
        // input[0]: p2wpkh witness → 2 items
        assert_eq!(tx.inputs[0].witness.len(), 2);
        // input[1]: p2pkh (legacy in segwit tx) → 0 witness items
        assert_eq!(tx.inputs[1].witness.len(), 0);
    }

    // ── tx_legacy_p2sh_p2wsh ─────────────────────────────────────────────────

    const TX_LEGACY_P2SH_P2WSH: &str =
        "01000000013333333333333333333333333333333333333333333333333333333333333333020000000151\
         ffffffff0250c300000000000017a914060606060606060606060606060606060606060687\
         409c000000000000220020070707070707070707070707070707070707070707070707070707070707070700000000";

    #[test]
    fn parse_legacy_p2sh_p2wsh_structure() {
        let raw = from_hex(TX_LEGACY_P2SH_P2WSH);
        let tx = parse_tx(&raw).unwrap();

        assert!(!tx.is_segwit);
        assert_eq!(tx.version, 1);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.locktime, 0);
    }

    // ── tx_multi_input_legacy ────────────────────────────────────────────────

    const TX_MULTI_INPUT_LEGACY: &str =
        "0200000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000\
         ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100000000\
         feffffff02b80b0000000000001976a9140f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f88ac\
         a00f000000000000160014101010101010101010101010101010101010101000000000";

    #[test]
    fn parse_multi_input_legacy_structure() {
        let raw = from_hex(TX_MULTI_INPUT_LEGACY);
        let tx = parse_tx(&raw).unwrap();

        assert!(!tx.is_segwit);
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.locktime, 0);
        assert_eq!(tx.inputs[0].sequence, 0xffff_ffff);
        assert_eq!(tx.inputs[1].sequence, 0xffff_fffe); // feffffff
    }
}