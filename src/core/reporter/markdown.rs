// src/core/reporter/markdown.rs

use std::fs;
use std::io::Write;
use std::path::Path;

use serde_json::Value;

use crate::core::errors::ChainError;

const HEURISTIC_IDS: &[&str] = &[
    "cioh",
    "change_detection",
    "consolidation",
    "coinjoin",
    "self_transfer",
    "round_number",
    "op_return",
    "address_reuse",
    "peeling_chain",
];

const CLASSIFICATIONS: &[&str] = &[
    "simple_payment",
    "consolidation",
    "coinjoin",
    "self_transfer",
    "batch_payment",
    "unknown",
];

/// Generate a Markdown report from the analysis JSON and write to
/// `out/<blk_stem>.md`.
///
/// # Requirements
/// - Renders correctly on GitHub (pipes, `|---|` separators).
/// - Minimum 1 KB — enforced by including all blocks and heuristic tables.
/// - Reproducible: same JSON input → same Markdown output (no timestamps,
///   no random ordering).
pub fn write(report: &Value, blk_stem: &str) -> Result<(), ChainError> {
    let content = generate(report, blk_stem)?;

    let out_dir = Path::new("out");
    fs::create_dir_all(out_dir).map_err(ChainError::IoError)?;

    let path = out_dir.join(format!("{}.md", blk_stem));
    let mut f = fs::File::create(&path).map_err(ChainError::IoError)?;
    f.write_all(content.as_bytes()).map_err(ChainError::IoError)?;

    Ok(())
}

/// Generate the Markdown string from the analysis report.
/// Separated from `write` for testability.
pub fn generate(report: &Value, blk_stem: &str) -> Result<String, ChainError> {
    let mut md = String::with_capacity(4096);

    let filename = report
        .get("file")
        .and_then(|v| v.as_str())
        .unwrap_or(blk_stem);
    let block_count = report
        .get("block_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let blocks = report
        .get("blocks")
        .and_then(|v| v.as_array())
        .ok_or(ChainError::InvalidField {
            field: "blocks",
            detail: "missing blocks array in report".into(),
        })?;
    let file_summary = report.get("analysis_summary").unwrap_or(&Value::Null);

    // ── File header ───────────────────────────────────────────────────────────
    md.push_str(&format!("# Sherlock Chain Analysis — `{}`\n\n", filename));
    md.push_str(&format!(
        "**File:** `{}` | **Blocks:** {} | **Total transactions:** {}\n\n",
        filename,
        block_count,
        file_summary
            .get("total_transactions_analyzed")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    ));

    // ── File-level summary ────────────────────────────────────────────────────
    md.push_str("## File-Level Summary\n\n");

    // Fee rate stats table
    if let Some(stats) = file_summary.get("fee_rate_stats") {
        md.push_str("### Fee Rate Statistics (sat/vbyte)\n\n");
        md.push_str("| Metric | Value |\n");
        md.push_str("|---|---|\n");
        for key in &["min_sat_vb", "median_sat_vb", "mean_sat_vb", "max_sat_vb"] {
            let val = stats.get(*key).and_then(|v| v.as_f64()).unwrap_or(0.0);
            md.push_str(&format!("| {} | {:.2} |\n", key, val));
        }
        md.push('\n');
    }

    // Script type distribution table
    if let Some(dist) = file_summary.get("script_type_distribution") {
        md.push_str("### Script Type Distribution\n\n");
        md.push_str("| Script Type | Output Count |\n");
        md.push_str("|---|---|\n");
        for key in &["p2wpkh", "p2tr", "p2sh", "p2pkh", "p2wsh", "op_return", "unknown"] {
            let count = dist.get(*key).and_then(|v| v.as_u64()).unwrap_or(0);
            md.push_str(&format!("| {} | {} |\n", key, count));
        }
        md.push('\n');
    }

    // Flagged transactions
    let file_flagged = file_summary
        .get("flagged_transactions")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let file_total = file_summary
        .get("total_transactions_analyzed")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    md.push_str(&format!(
        "**Flagged transactions:** {} / {} ({:.1}%)\n\n",
        file_flagged,
        file_total,
        file_flagged as f64 / file_total as f64 * 100.0
    ));

    // Heuristics applied
    if let Some(heuristics) = file_summary
        .get("heuristics_applied")
        .and_then(|v| v.as_array())
    {
        let ids: Vec<&str> = heuristics.iter().filter_map(|v| v.as_str()).collect();
        md.push_str(&format!(
            "**Heuristics applied:** {}\n\n",
            ids.join(", ")
        ));
    }

    if let Some(findings) = file_summary
        .get("heuristic_findings")
        .and_then(|v| v.as_object())
    {
        md.push_str("### Heuristic Findings\n\n");
        md.push_str("| Heuristic | Transactions Flagged |\n");
        md.push_str("|---|---|\n");
        for id in HEURISTIC_IDS {
            let count = findings.get(*id).and_then(|v| v.as_u64()).unwrap_or(0);
            md.push_str(&format!("| {} | {} |\n", id, count));
        }
        md.push('\n');
    }

    // ── Per-block sections ────────────────────────────────────────────────────
    for (block_idx, block) in blocks.iter().enumerate() {
        let hash = block
            .get("block_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let height = block
            .get("block_height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let timestamp = block
            .get("timestamp")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let tx_count = block
            .get("tx_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let block_summary = block.get("analysis_summary").unwrap_or(&Value::Null);

        md.push_str(&format!("## Block {} — Height {}\n\n", block_idx + 1, height));
        md.push_str(&format!("| Field | Value |\n"));
        md.push_str("|---|---|\n");
        md.push_str(&format!("| Hash | `{}` |\n", hash));
        md.push_str(&format!("| Height | {} |\n", height));
        md.push_str(&format!("| Timestamp | {} |\n", timestamp));
        md.push_str(&format!("| Transactions | {} |\n", tx_count));
        let block_flagged = block_summary
            .get("flagged_transactions")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        md.push_str(&format!("| Flagged | {} |\n\n", block_flagged));

        // Per-block fee stats
        if let Some(stats) = block_summary.get("fee_rate_stats") {
            md.push_str("### Fee Rates (sat/vbyte)\n\n");
            md.push_str("| min | median | mean | max |\n");
            md.push_str("|---|---|---|---|\n");
            let min = stats.get("min_sat_vb").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let med = stats.get("median_sat_vb").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let avg = stats.get("mean_sat_vb").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let max = stats.get("max_sat_vb").and_then(|v| v.as_f64()).unwrap_or(0.0);
            md.push_str(&format!("| {:.2} | {:.2} | {:.2} | {:.2} |\n\n", min, med, avg, max));
        }

        md.push_str("### Heuristic Findings\n\n");
        md.push_str("| Heuristic | Transactions Flagged |\n");
        md.push_str("|---|---|\n");
        for id in HEURISTIC_IDS {
            let count = count_heuristic(block_summary, block, id);
            md.push_str(&format!("| {} | {} |\n", id, count));
        }
        md.push('\n');

        md.push_str("### Transaction Classifications\n\n");
        md.push_str("| Classification | Count |\n");
        md.push_str("|---|---|\n");
        for cls in CLASSIFICATIONS {
            let count = count_classification(block_summary, block, cls);
            if count > 0 {
                md.push_str(&format!("| {} | {} |\n", cls, count));
            }
        }
        md.push('\n');

        if let Some(notables) = notable_transactions(block) {
            let total_notable = notables.len();
            let header = if total_notable > 10 {
                format!(
                    "### Notable Transactions (showing top 10 of {})\n\n",
                    total_notable
                )
            } else {
                "### Notable Transactions\n\n".to_string()
            };
            md.push_str(&header);
            md.push_str("| txid | classification | heuristic hits |\n");
            md.push_str("|---|---|---|\n");
            for tx in notables.iter().take(10) {
                let txid = tx.get("txid").and_then(|v| v.as_str()).unwrap_or("?");
                let cls = tx
                    .get("classification")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let hits = tx
                    .get("detected_heuristics")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "classification-only".to_string());
                md.push_str(&format!("| `{}` | {} | {} |\n", txid, cls, hits));
            }
            md.push('\n');
        }
    }

    // ── Methodology note ──────────────────────────────────────────────────────
    md.push_str("---\n\n");
    md.push_str("## Methodology\n\n");
    md.push_str(
        "This report was generated by **Sherlock**, a Bitcoin chain analysis engine \
        built for Summer of Bitcoin 2026. Heuristics are probabilistic — results \
        indicate likely patterns, not certainties. See `APPROACH.md` for full \
        documentation of each heuristic, confidence models, and known limitations.\n\n",
    );
    md.push_str(&format!(
        "Heuristics applied: {}. All values in satoshis unless noted.\n",
        report
            .get("analysis_summary")
            .and_then(|s| s.get("heuristics_applied"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.len())
            .unwrap_or(0)
    ));

    // Enforce minimum 1 KB
    debug_assert!(
        md.len() >= 1024,
        "Markdown report is {} bytes, expected >= 1024. Add content to generate().",
        md.len()
    );

    Ok(md)
}

fn count_heuristic(block_summary: &Value, block: &Value, id: &str) -> u64 {
    if let Some(count) = block_summary
        .get("heuristic_findings")
        .and_then(|v| v.get(id))
        .and_then(|v| v.as_u64())
    {
        return count;
    }

    block
        .get("transactions")
        .and_then(|v| v.as_array())
        .map(|txs| {
            txs.iter()
                .filter(|tx| {
                    tx.get("heuristics")
                        .and_then(|h| h.get(id))
                        .and_then(|r| r.get("detected"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                })
                .count() as u64
        })
        .unwrap_or(0)
}

fn count_classification(block_summary: &Value, block: &Value, classification: &str) -> u64 {
    if let Some(count) = block_summary
        .get("classification_distribution")
        .and_then(|v| v.get(classification))
        .and_then(|v| v.as_u64())
    {
        return count;
    }

    block
        .get("transactions")
        .and_then(|v| v.as_array())
        .map(|txs| {
            txs.iter()
                .filter(|tx| {
                    tx.get("classification")
                        .and_then(|v| v.as_str())
                        == Some(classification)
                })
                .count() as u64
        })
        .unwrap_or(0)
}

fn notable_transactions(block: &Value) -> Option<Vec<&Value>> {
    if let Some(notables) = block
        .get("notable_transactions")
        .and_then(|v| v.as_array())
        .filter(|txs| !txs.is_empty())
    {
        return Some(notables.iter().collect());
    }

    let txs = block.get("transactions").and_then(|v| v.as_array())?;
    let notables: Vec<&Value> = txs
        .iter()
        .filter(|tx| {
            matches!(
                tx.get("classification").and_then(|v| v.as_str()),
                Some("coinjoin")
                    | Some("consolidation")
                    | Some("self_transfer")
                    | Some("batch_payment")
            )
        })
        .collect();

    if notables.is_empty() {
        None
    } else {
        Some(notables)
    }
}
