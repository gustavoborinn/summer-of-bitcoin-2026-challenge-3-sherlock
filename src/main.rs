mod core;

use crate::core::analyzer::block_analyzer::analyze_block_file;
use crate::core::errors::{error_code, ChainError};
use crate::core::io::xor_decoder::xor_decode;
use crate::core::parser::block_parser::parse_block_file;
use crate::core::parser::undo_parser::parse_undo_file;
use crate::core::reporter::{json_report, markdown};
use std::fs;
use std::path::Path;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let argv = &args[1..];

    let result = match argv.first().map(String::as_str) {
        Some("--block") => run_block_mode(&argv[1..]),
        _ => Err(ChainError::InvalidField {
            field: "args",
            detail: "Usage: sherlock --block <blk*.dat> <rev*.dat> <xor.dat>".into(),
        }),
    };

    match result {
        Ok(()) => process::exit(0),
        Err(e) => {
            emit_error(&e);
            process::exit(1);
        }
    }
}

fn run_block_mode(args: &[String]) -> Result<(), ChainError> {
    if args.len() < 3 {
        return Err(ChainError::InvalidField {
            field: "args",
            detail: "--block requires: <blk*.dat> <rev*.dat> <xor.dat>".into(),
        });
    }
    let blk_path = &args[0];
    let rev_path = &args[1];
    let xor_path = &args[2];

    let blk_stem = Path::new(blk_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| ChainError::InvalidField {
            field: "blk_path",
            detail: format!("cannot derive stem from path: {}", blk_path),
        })?
        .to_string();

    let blk_filename = Path::new(blk_path)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| ChainError::InvalidField {
            field: "blk_path",
            detail: format!("cannot derive filename from path: {}", blk_path),
        })?
        .to_string();

    let xor_key = fs::read(xor_path).map_err(ChainError::IoError)?;

    let blk_raw = fs::read(blk_path).map_err(ChainError::IoError)?;
    let blk_data = xor_decode(&blk_raw, &xor_key);

    let rev_raw = fs::read(rev_path).map_err(ChainError::IoError)?;
    let rev_data = xor_decode(&rev_raw, &xor_key);

    let blocks = parse_block_file(&blk_data)?;
    let undos  = parse_undo_file(&rev_data)?;

    // Match blocks to undo records via the cryptographic checksum in rev*.dat.
    // Bitcoin Core writes: checksum = SHA256d(block.header.prev_block_hash || raw_undo_bytes)
    // This is the only reliable key — blk*.dat and rev*.dat store blocks in different
    // orders, and tx-count matching fails when multiple blocks share the same count.
    // Orphan blocks (forks with no undo data written) become None and are still included
    // in output — their fee stats will be zero and heuristics will be skipped.
    let mut undo_used = vec![false; undos.len()];
    let block_undo_pairs: Vec<(
        &crate::core::parser::block_parser::ParsedBlock,
        Option<&crate::core::parser::undo_parser::BlockUndo>,
    )> = {
        use sha2::{Sha256, Digest};
        blocks.iter().map(|block| {
            let prev = &block.header.prev_block_hash;
            let matched = undos.iter().enumerate().find(|(i, undo)| {
                if undo_used[*i] { return false; }
                let mut buf = Vec::with_capacity(32 + undo.raw_bytes.len());
                buf.extend_from_slice(prev);
                buf.extend_from_slice(&undo.raw_bytes);
                let h1 = Sha256::digest(&buf);
                let h2 = Sha256::digest(&h1);
                let mut computed = [0u8; 32];
                computed.copy_from_slice(&h2);
                computed == undo.checksum
            });
            match matched {
                Some((i, undo)) => { undo_used[i] = true; (block, Some(undo)) }
                None => (block, None),
            }
        }).collect()
    };

    fs::create_dir_all("out").map_err(ChainError::IoError)?;

    let report = analyze_block_file(&blk_filename, &block_undo_pairs)?;

    json_report::write(&report, &blk_stem)?;
    markdown::write(&report, &blk_stem)?;

    Ok(())
}

fn emit_error(e: &ChainError) {
    let payload = serde_json::json!({
        "ok": false,
        "error": {
            "code": error_code(e),
            "message": e.to_string()
        }
    });
    println!("{}", payload);
}