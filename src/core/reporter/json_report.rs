// src/core/reporter/json_report.rs

use std::fs;
use std::io::Write;
use std::path::Path;

use serde_json::Value;

use crate::core::errors::ChainError;

pub fn validate(report: &Value) -> Result<(), ChainError> {
    // ok == true
    if report.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(ChainError::InvalidField {
            field: "ok",
            detail: "report.ok must be true".into(),
        });
    }

    let blocks = report
        .get("blocks")
        .and_then(|v| v.as_array())
        .ok_or(ChainError::InvalidField {
            field: "blocks",
            detail: "missing or non-array".into(),
        })?;

    // block_count == blocks.len()
    let block_count = report
        .get("block_count")
        .and_then(|v| v.as_u64())
        .ok_or(ChainError::InvalidField {
            field: "block_count",
            detail: "missing or non-integer".into(),
        })?;
    if block_count != blocks.len() as u64 {
        return Err(ChainError::InvalidField {
            field: "block_count",
            detail: format!("block_count={} but blocks.len()={}", block_count, blocks.len()),
        });
    }

    // File-level analysis_summary
    let file_summary = report
        .get("analysis_summary")
        .ok_or(ChainError::InvalidField {
            field: "analysis_summary",
            detail: "missing file-level analysis_summary".into(),
        })?;

    // total_transactions_analyzed == Σ tx_count
    let file_total = file_summary
        .get("total_transactions_analyzed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let sum_tx: u64 = blocks
        .iter()
        .filter_map(|b| b.get("tx_count").and_then(|v| v.as_u64()))
        .sum();
    if file_total != sum_tx {
        return Err(ChainError::InvalidField {
            field: "total_transactions_analyzed",
            detail: format!("file total={} but Σ tx_count={}", file_total, sum_tx),
        });
    }

    // flagged_transactions (file) == Σ blocks[i].analysis_summary.flagged_transactions
    let file_flagged = file_summary
        .get("flagged_transactions")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let sum_flagged: u64 = blocks
        .iter()
        .filter_map(|b| {
            b.get("analysis_summary")
                .and_then(|s| s.get("flagged_transactions"))
                .and_then(|v| v.as_u64())
        })
        .sum();
    if file_flagged != sum_flagged {
        return Err(ChainError::InvalidField {
            field: "flagged_transactions",
            detail: format!(
                "file flagged={} but Σ per-block flagged={}",
                file_flagged, sum_flagged
            ),
        });
    }

    // heuristics_applied: >= 5, includes "cioh" and "change_detection"
    let heuristics = file_summary
        .get("heuristics_applied")
        .and_then(|v| v.as_array())
        .ok_or(ChainError::InvalidField {
            field: "heuristics_applied",
            detail: "missing or non-array".into(),
        })?;
    if heuristics.len() < 5 {
        return Err(ChainError::InvalidField {
            field: "heuristics_applied",
            detail: format!("only {} heuristics, need >= 5", heuristics.len()),
        });
    }
    let h_strings: Vec<&str> = heuristics
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    if !h_strings.contains(&"cioh") {
        return Err(ChainError::InvalidField {
            field: "heuristics_applied",
            detail: "missing mandatory heuristic: cioh".into(),
        });
    }
    if !h_strings.contains(&"change_detection") {
        return Err(ChainError::InvalidField {
            field: "heuristics_applied",
            detail: "missing mandatory heuristic: change_detection".into(),
        });
    }

    // fee_rate_stats: file-level
    validate_fee_stats(file_summary, "file-level")?;

    // fee_rate_stats: per-block        ← NOVO
    for (i, block) in blocks.iter().enumerate() {
        if let Some(block_summary) = block.get("analysis_summary") {
            validate_fee_stats(block_summary, &format!("blocks[{}]", i))?;
        }
    }

    // blocks[0]: transactions array exists and len == tx_count
    if let Some(block0) = blocks.first() {
        let tx_count = block0.get("tx_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let txs = block0
            .get("transactions")
            .and_then(|v| v.as_array())
            .ok_or(ChainError::InvalidField {
                field: "blocks[0].transactions",
                detail: "missing or non-array".into(),
            })?;
        if txs.len() as u64 != tx_count {
            return Err(ChainError::InvalidField {
                field: "blocks[0].transactions",
                detail: format!("len()={} but tx_count={}", txs.len(), tx_count),
            });
        }

        // Validate classification enum values in blocks[0]
        let valid_classifications = [
            "simple_payment", "consolidation", "coinjoin",
            "self_transfer", "batch_payment", "unknown",
        ];
        for (i, tx) in txs.iter().enumerate() {
            if let Some(cls) = tx.get("classification").and_then(|v| v.as_str()) {
                if !valid_classifications.contains(&cls) {
                    return Err(ChainError::InvalidField {
                        field: "classification",
                        detail: format!("tx[{}] has invalid classification: {}", i, cls),
                    });
                }
            }
        }
    }

    // blocks[1+]: transactions must be []        ← NOVO
    for (i, block) in blocks.iter().enumerate().skip(1) {
        if let Some(txs) = block.get("transactions").and_then(|v| v.as_array()) {
            if !txs.is_empty() {
                return Err(ChainError::InvalidField {
                    field: "blocks[n].transactions",
                    detail: format!(
                        "blocks[{}].transactions must be [] but has {} entries",
                        i,
                        txs.len()
                    ),
                });
            }
        }
    }

    Ok(())
}

// validate_fee_stats — ausente agora é Err        ← ALTERADO
fn validate_fee_stats(summary: &Value, context: &str) -> Result<(), ChainError> {
    let stats = match summary.get("fee_rate_stats") {
        Some(s) => s,
        None => return Err(ChainError::InvalidField {
            field: "fee_rate_stats",
            detail: format!("{}: fee_rate_stats field missing", context),
        }),
    };
    let min    = stats.get("min_sat_vb")   .and_then(|v| v.as_f64()).unwrap_or(-1.0);
    let median = stats.get("median_sat_vb").and_then(|v| v.as_f64()).unwrap_or(-1.0);
    let max    = stats.get("max_sat_vb")   .and_then(|v| v.as_f64()).unwrap_or(-1.0);

    if min < 0.0 || median < 0.0 || max < 0.0 {
        return Err(ChainError::InvalidField {
            field: "fee_rate_stats",
            detail: format!(
                "{}: negative value (min={} median={} max={})",
                context, min, median, max
            ),
        });
    }
    if !(min <= median && median <= max) {
        return Err(ChainError::InvalidField {
            field: "fee_rate_stats",
            detail: format!(
                "{}: invariant min<=median<=max violated ({}<={}<={} is false)",
                context, min, median, max
            ),
        });
    }
    Ok(())
}

pub fn write(report: &Value, blk_stem: &str) -> Result<(), ChainError> {
    validate(report)?;

    let out_dir = Path::new("out");
    fs::create_dir_all(out_dir).map_err(ChainError::IoError)?;

    let json_bytes = serde_json::to_vec_pretty(report).map_err(|e| ChainError::InvalidField {
        field: "json_serialize",
        detail: e.to_string(),
    })?;

    let path = out_dir.join(format!("{}.json", blk_stem));
    let mut f = fs::File::create(&path).map_err(ChainError::IoError)?;
    f.write_all(&json_bytes).map_err(ChainError::IoError)?;

    Ok(())
}