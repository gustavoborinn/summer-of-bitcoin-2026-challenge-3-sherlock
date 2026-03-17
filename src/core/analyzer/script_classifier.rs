/// Output script type classification per Bitcoin Core patterns.
#[derive(Debug, Clone, PartialEq)]
pub enum OutputScriptType {
    P2PKH,
    P2SH,
    P2WPKH,
    P2WSH,
    P2TR,
    OpReturn,
    Unknown,
}

impl OutputScriptType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::P2PKH => "p2pkh",
            Self::P2SH => "p2sh",
            Self::P2WPKH => "p2wpkh",
            Self::P2WSH => "p2wsh",
            Self::P2TR => "p2tr",
            Self::OpReturn => "op_return",
            Self::Unknown => "unknown",
        }
    }
}

/// Input spend type classification.
#[derive(Debug, Clone, PartialEq)]
pub enum InputScriptType {
    P2PKH,
    P2SHP2WPKH,
    P2SHP2WSH,
    P2WPKH,
    P2WSH,
    P2TRKeypath,
    P2TRScriptpath,
    Unknown,
}

impl InputScriptType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::P2PKH => "p2pkh",
            Self::P2SHP2WPKH => "p2sh-p2wpkh",
            Self::P2SHP2WSH => "p2sh-p2wsh",
            Self::P2WPKH => "p2wpkh",
            Self::P2WSH => "p2wsh",
            Self::P2TRKeypath => "p2tr_keypath",
            Self::P2TRScriptpath => "p2tr_scriptpath",
            Self::Unknown => "unknown",
        }
    }
}

/// Classify a scriptPubKey by its byte pattern.
pub fn classify_output(script: &[u8]) -> OutputScriptType {
    match script.len() {
        25 if script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14
            && script[23] == 0x88 && script[24] == 0xac =>
        {
            OutputScriptType::P2PKH
        }
        23 if script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 => {
            OutputScriptType::P2SH
        }
        22 if script[0] == 0x00 && script[1] == 0x14 => OutputScriptType::P2WPKH,
        34 if script[0] == 0x00 && script[1] == 0x20 => OutputScriptType::P2WSH,
        34 if script[0] == 0x51 && script[1] == 0x20 => OutputScriptType::P2TR,
        _ if !script.is_empty() && script[0] == 0x6a => OutputScriptType::OpReturn,
        _ => OutputScriptType::Unknown,
    }
}

/// Classify an input's spend type from prevout script + script_sig + witness.
pub fn classify_input(
    prevout_script: &[u8],
    script_sig: &[u8],
    witness: &[&[u8]],
) -> InputScriptType {
    match classify_output(prevout_script) {
        OutputScriptType::P2PKH => InputScriptType::P2PKH,
        OutputScriptType::P2WPKH => InputScriptType::P2WPKH,
        OutputScriptType::P2WSH => InputScriptType::P2WSH,
        OutputScriptType::P2TR => classify_p2tr_input(witness),
        OutputScriptType::P2SH => classify_p2sh_input(script_sig, witness),
        _ => InputScriptType::Unknown,
    }
}

fn classify_p2tr_input(witness: &[&[u8]]) -> InputScriptType {
    // Strip annex if present (annex starts with 0x50 and only applies when
    // there are at least 2 items — BIP341).
    let eff = if witness.len() >= 2
        && witness.last().map_or(false, |w| !w.is_empty() && w[0] == 0x50)
    {
        &witness[..witness.len() - 1]
    } else {
        witness
    };

    match eff.len() {
        // Keypath: exactly 1 item, 64 bytes (SIGHASH_DEFAULT) or 65 bytes (explicit sighash)
        1 if eff[0].len() == 64 || eff[0].len() == 65 => InputScriptType::P2TRKeypath,
        // Scriptpath: ≥ 2 items; last item is control block (0xc0 | parity)
        n if n >= 2 => {
            let control = eff[eff.len() - 1];
            if !control.is_empty() && (control[0] & 0xfe) == 0xc0 {
                InputScriptType::P2TRScriptpath
            } else {
                InputScriptType::P2TRKeypath
            }
        }
        _ => InputScriptType::Unknown,
    }
}

fn classify_p2sh_input(script_sig: &[u8], witness: &[&[u8]]) -> InputScriptType {
    // The redeemScript is the last push of script_sig.
    let redeem = match extract_last_push(script_sig) {
        Some(r) => r,
        None => return InputScriptType::Unknown,
    };
    match redeem.len() {
        22 if redeem[0] == 0x00 && redeem[1] == 0x14 => {
            // P2SH-P2WPKH: redeemScript is a P2WPKH template
            let _ = witness; // witness contains sig + pubkey
            InputScriptType::P2SHP2WPKH
        }
        34 if redeem[0] == 0x00 && redeem[1] == 0x20 => {
            // P2SH-P2WSH: redeemScript is a P2WSH template
            InputScriptType::P2SHP2WSH
        }
        _ => InputScriptType::Unknown,
    }
}

/// Extract the data bytes pushed by the last opcode in `script`.
/// Returns None if the script is empty or ends with a non-data-push opcode.
pub fn extract_last_push(script: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    let mut last: Option<&[u8]> = None;
    while i < script.len() {
        let op = script[i];
        i += 1;
        match op {
            0x00 => last = Some(&script[0..0]),
            0x01..=0x4b => {
                let n = op as usize;
                if i + n > script.len() {
                    return None;
                }
                last = Some(&script[i..i + n]);
                i += n;
            }
            0x4c => {
                if i >= script.len() {
                    return None;
                }
                let n = script[i] as usize;
                i += 1;
                if i + n > script.len() {
                    return None;
                }
                last = Some(&script[i..i + n]);
                i += n;
            }
            0x4d => {
                if i + 2 > script.len() {
                    return None;
                }
                let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                if i + n > script.len() {
                    return None;
                }
                last = Some(&script[i..i + n]);
                i += n;
            }
            0x4e => {
                if i + 4 > script.len() {
                    return None;
                }
                let n =
                    u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]])
                        as usize;
                i += 4;
                if i + n > script.len() {
                    return None;
                }
                last = Some(&script[i..i + n]);
                i += n;
            }
            _ => last = None,
        }
    }
    last
}

/// Decode the payload of an OP_RETURN script.
/// Concatenates all data-push bytes after the OP_RETURN opcode.
pub fn decode_op_return_payload(script: &[u8]) -> Vec<u8> {
    if script.is_empty() || script[0] != 0x6a {
        return Vec::new();
    }
    let mut i = 1;
    let mut out = Vec::new();
    while i < script.len() {
        let op = script[i];
        i += 1;
        match op {
            0x01..=0x4b => {
                let n = op as usize;
                if i + n > script.len() {
                    break;
                }
                out.extend_from_slice(&script[i..i + n]);
                i += n;
            }
            0x4c => {
                if i >= script.len() {
                    break;
                }
                let n = script[i] as usize;
                i += 1;
                if i + n > script.len() {
                    break;
                }
                out.extend_from_slice(&script[i..i + n]);
                i += n;
            }
            0x4d => {
                if i + 2 > script.len() {
                    break;
                }
                let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                if i + n > script.len() {
                    break;
                }
                out.extend_from_slice(&script[i..i + n]);
                i += n;
            }
            0x4e => {
                if i + 4 > script.len() {
                    break;
                }
                let n =
                    u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]])
                        as usize;
                i += 4;
                if i + n > script.len() {
                    break;
                }
                out.extend_from_slice(&script[i..i + n]);
                i += n;
            }
            _ => {} // ignore non-push opcodes (e.g. bare OP_RETURN with no data)
        }
    }
    out
}

/// Detect the OP_RETURN protocol from the decoded payload bytes.
pub fn op_return_protocol(data: &[u8]) -> &'static str {
    if data.starts_with(&[0x6f, 0x6d, 0x6e, 0x69]) {
        "omni"
    } else if data.starts_with(&[0x01, 0x09, 0xf9, 0x11, 0x02]) {
        "opentimestamps"
    } else {
        "unknown"
    }
}

/// Disassemble a Bitcoin script into space-separated tokens.
/// Data pushes: `OP_PUSHBYTES_<n> <hex>` (direct 0x01-0x4b),
///              `OP_PUSHDATA1/2/4 <hex>` (extended push).
pub fn disassemble(script: &[u8]) -> String {
    if script.is_empty() {
        return String::new();
    }
    let mut tokens: Vec<String> = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        match op {
            0x00 => tokens.push("OP_0".into()),
            0x01..=0x4b => {
                let n = op as usize;
                if i + n <= script.len() {
                    tokens.push(format!("OP_PUSHBYTES_{}", n));
                    tokens.push(hex_enc(&script[i..i + n]));
                    i += n;
                } else {
                    tokens.push(format!("OP_PUSHBYTES_{}", n));
                }
            }
            0x4c => {
                if i < script.len() {
                    let n = script[i] as usize;
                    i += 1;
                    if i + n <= script.len() {
                        tokens.push("OP_PUSHDATA1".into());
                        tokens.push(hex_enc(&script[i..i + n]));
                        i += n;
                    } else {
                        tokens.push("OP_PUSHDATA1".into());
                    }
                }
            }
            0x4d => {
                if i + 2 <= script.len() {
                    let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                    i += 2;
                    if i + n <= script.len() {
                        tokens.push("OP_PUSHDATA2".into());
                        tokens.push(hex_enc(&script[i..i + n]));
                        i += n;
                    } else {
                        tokens.push("OP_PUSHDATA2".into());
                    }
                }
            }
            0x4e => {
                if i + 4 <= script.len() {
                    let n = u32::from_le_bytes([
                        script[i],
                        script[i + 1],
                        script[i + 2],
                        script[i + 3],
                    ]) as usize;
                    i += 4;
                    if i + n <= script.len() {
                        tokens.push("OP_PUSHDATA4".into());
                        tokens.push(hex_enc(&script[i..i + n]));
                        i += n;
                    } else {
                        tokens.push("OP_PUSHDATA4".into());
                    }
                }
            }
            b => tokens.push(opcode_name_owned(b)),
        }
    }
    tokens.join(" ")
}

fn hex_enc(b: &[u8]) -> String {
    b.iter().fold(String::with_capacity(b.len() * 2), |mut s, &x| {
        s.push_str(&format!("{:02x}", x));
        s
    })
}

fn opcode_name(op: u8) -> &'static str {
    match op {
        0x4f => "OP_1NEGATE",
        0x50 => "OP_RESERVED",
        0x51 => "OP_1",
        0x52 => "OP_2",
        0x53 => "OP_3",
        0x54 => "OP_4",
        0x55 => "OP_5",
        0x56 => "OP_6",
        0x57 => "OP_7",
        0x58 => "OP_8",
        0x59 => "OP_9",
        0x5a => "OP_10",
        0x5b => "OP_11",
        0x5c => "OP_12",
        0x5d => "OP_13",
        0x5e => "OP_14",
        0x5f => "OP_15",
        0x60 => "OP_16",
        0x61 => "OP_NOP",
        0x62 => "OP_VER",
        0x63 => "OP_IF",
        0x64 => "OP_NOTIF",
        0x65 => "OP_VERIF",
        0x66 => "OP_VERNOTIF",
        0x67 => "OP_ELSE",
        0x68 => "OP_ENDIF",
        0x69 => "OP_VERIFY",
        0x6a => "OP_RETURN",
        0x6b => "OP_TOALTSTACK",
        0x6c => "OP_FROMALTSTACK",
        0x6d => "OP_2DROP",
        0x6e => "OP_2DUP",
        0x6f => "OP_3DUP",
        0x70 => "OP_2OVER",
        0x71 => "OP_2ROT",
        0x72 => "OP_2SWAP",
        0x73 => "OP_IFDUP",
        0x74 => "OP_DEPTH",
        0x75 => "OP_DROP",
        0x76 => "OP_DUP",
        0x77 => "OP_NIP",
        0x78 => "OP_OVER",
        0x79 => "OP_PICK",
        0x7a => "OP_ROLL",
        0x7b => "OP_ROT",
        0x7c => "OP_SWAP",
        0x7d => "OP_TUCK",
        0x7e => "OP_CAT",
        0x7f => "OP_SUBSTR",
        0x80 => "OP_LEFT",
        0x81 => "OP_RIGHT",
        0x82 => "OP_SIZE",
        0x83 => "OP_INVERT",
        0x84 => "OP_AND",
        0x85 => "OP_OR",
        0x86 => "OP_XOR",
        0x87 => "OP_EQUAL",
        0x88 => "OP_EQUALVERIFY",
        0x89 => "OP_RESERVED1",
        0x8a => "OP_RESERVED2",
        0x8b => "OP_1ADD",
        0x8c => "OP_1SUB",
        0x8d => "OP_2MUL",
        0x8e => "OP_2DIV",
        0x8f => "OP_NEGATE",
        0x90 => "OP_ABS",
        0x91 => "OP_NOT",
        0x92 => "OP_0NOTEQUAL",
        0x93 => "OP_ADD",
        0x94 => "OP_SUB",
        0x95 => "OP_MUL",
        0x96 => "OP_DIV",
        0x97 => "OP_MOD",
        0x98 => "OP_LSHIFT",
        0x99 => "OP_RSHIFT",
        0x9a => "OP_BOOLAND",
        0x9b => "OP_BOOLOR",
        0x9c => "OP_NUMEQUAL",
        0x9d => "OP_NUMEQUALVERIFY",
        0x9e => "OP_NUMNOTEQUAL",
        0x9f => "OP_LESSTHAN",
        0xa0 => "OP_GREATERTHAN",
        0xa1 => "OP_LESSTHANOREQUAL",
        0xa2 => "OP_GREATERTHANOREQUAL",
        0xa3 => "OP_MIN",
        0xa4 => "OP_MAX",
        0xa5 => "OP_WITHIN",
        0xa6 => "OP_RIPEMD160",
        0xa7 => "OP_SHA1",
        0xa8 => "OP_SHA256",
        0xa9 => "OP_HASH160",
        0xaa => "OP_HASH256",
        0xab => "OP_CODESEPARATOR",
        0xac => "OP_CHECKSIG",
        0xad => "OP_CHECKSIGVERIFY",
        0xae => "OP_CHECKMULTISIG",
        0xaf => "OP_CHECKMULTISIGVERIFY",
        0xb0 => "OP_NOP1",
        0xb1 => "OP_CHECKLOCKTIMEVERIFY",
        0xb2 => "OP_CHECKSEQUENCEVERIFY",
        0xb3 => "OP_NOP4",
        0xb4 => "OP_NOP5",
        0xb5 => "OP_NOP6",
        0xb6 => "OP_NOP7",
        0xb7 => "OP_NOP8",
        0xb8 => "OP_NOP9",
        0xb9 => "OP_NOP10",
        0xba => "OP_CHECKSIGADD",
        // Bitcoin Core renders undefined opcodes as OP_UNKNOWN_0xNN
        _ => "OP_UNKNOWN",
    }
}

/// Returns the static name, or a heap-allocated "OP_UNKNOWN_0xNN" for unknowns.
/// Callers that need the full unknown string should use `disassemble` which handles this.
pub fn opcode_name_owned(op: u8) -> String {
    let s = opcode_name(op);
    if s == "OP_UNKNOWN" {
        format!("OP_UNKNOWN_{:#04x}", op)
    } else {
        s.to_string()
    }
}
