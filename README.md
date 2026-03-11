[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/BKxF-kj7)
# Week 3 Challenge: Sherlock

Build a chain analysis engine that applies chain-analysis heuristics to a dataset of Bitcoin transactions from real block data, a web visualizer to surface and display the results, and Markdown reports documenting your findings.

This challenge builds on the transaction parser (Challenge 1) and PSBT builder (Challenge 2). You are now applying analytical reasoning on top of parsed transaction data to infer patterns, identify entities, and classify transaction behavior.

This challenge is deliberately open-ended on heuristics. There is no single "right answer" — the quality of your analysis, the rigor of your approach, and the clarity of your documentation are what matter.

---

## Assumptions / scope

- You **must** parse raw block files (`blk*.dat`, `rev*.dat`, `xor.dat`) to extract transactions and their prevout data, as you did in Challenge 1.
- You do **not** need to validate signatures or execute scripts.
- You do **not** need to connect to a node or external API.
- Heuristics are probabilistic — document your confidence model and limitations in `APPROACH.md`.

---

## Deliverables

You must ship **all** of the following:

1. **CLI chain analyzer** — applies heuristics to every transaction in a block and produces machine-readable JSON output.
2. **Markdown reports** — human-readable reports summarizing the analysis for each block file. Must be committed to `out/`.
3. **Web visualizer** — interactive UI for exploring chain analysis results.
4. **APPROACH.md** — documents your heuristics, architecture, trade-offs, and references.
5. **Demo video** — a screen recording of your web UI walkthrough, linked in `demo.md`.

---

## Required repo interface

Your repository must include these scripts:

### 1) `cli.sh`

```bash
./cli.sh --block <blk.dat> <rev.dat> <xor.dat>
```

- Reads the block data files and applies chain analysis heuristics.
- Writes per-block-file outputs (where `<blk_stem>` is the blk filename without extension, e.g., `blk04330`):
  - `out/<blk_stem>.json` — machine-readable analysis report
  - `out/<blk_stem>.md` — human-readable Markdown report
- A single `blk*.dat` file may contain **multiple blocks**. Both the JSON and Markdown outputs should cover all blocks in the file.
- The `out/` directory must be created if it does not exist.
- Exits `0` on success, `1` on error.
- Errors must be returned as structured JSON: `{ "ok": false, "error": { "code": "...", "message": "..." } }`

### 2) `web.sh`

- Starts the web visualizer.
- Must print a single line containing the URL (e.g. `http://127.0.0.1:3000`) to stdout.
- Must keep running until terminated (CTRL+C / SIGTERM).
- Must honor `PORT` if set (default `3000`).
- Must serve `GET /api/health` → `200 { "ok": true }`.

### 3) `setup.sh`

- Installs project dependencies.
- Decompresses block fixture files (`fixtures/*.dat.gz`).
- Run once before grading.

---

## JSON output schema

Each `out/<blk_stem>.json` must conform to the following schema. Since a single `blk*.dat` file may contain multiple blocks, the output wraps per-block data in a `blocks` array with a file-level aggregated summary:

```json
{
  "ok": true,
  "mode": "chain_analysis",
  "file": "blk04330.dat",
  "block_count": 2,
  "analysis_summary": {
    "total_transactions_analyzed": 4500,
    "heuristics_applied": ["cioh", "change_detection", "..."],
    "flagged_transactions": 120,
    "script_type_distribution": {
      "p2wpkh": 2100,
      "p2tr": 900,
      "p2sh": 300,
      "p2pkh": 150,
      "p2wsh": 60,
      "op_return": 40,
      "unknown": 10
    },
    "fee_rate_stats": {
      "min_sat_vb": 1.0,
      "max_sat_vb": 800.0,
      "median_sat_vb": 28.0,
      "mean_sat_vb": 45.2
    }
  },
  "blocks": [
    {
      "block_hash": "<hex64>",
      "block_height": 800000,
      "tx_count": 3000,
      "analysis_summary": {
        "total_transactions_analyzed": 3000,
        "heuristics_applied": ["cioh", "change_detection", "..."],
        "flagged_transactions": 80,
        "script_type_distribution": {
          "p2wpkh": 1200,
          "p2tr": 500,
          "p2sh": 200,
          "p2pkh": 80,
          "p2wsh": 30,
          "op_return": 20,
          "unknown": 5
        },
        "fee_rate_stats": {
          "min_sat_vb": 1.0,
          "max_sat_vb": 800.0,
          "median_sat_vb": 30.0,
          "mean_sat_vb": 50.1
        }
      },
      "transactions": [
        {
          "txid": "<hex64>",
          "heuristics": {
            "cioh": {
              "detected": true
            },
            "change_detection": {
              "detected": true,
              "likely_change_index": 1,
              "method": "script_type_match",
              "confidence": "high"
            }
          },
          "classification": "simple_payment"
        }
      ]
    }
  ]
}
```

### Field requirements

**Top-level fields:**

- `ok`: boolean, `true` on success.
- `mode`: string, always `"chain_analysis"`.
- `file`: string, the source block filename (e.g., `"blk04330.dat"`).
- `block_count`: integer, must equal the length of the `blocks` array.
- `analysis_summary`: file-level aggregated summary (see below).
- `blocks`: array of per-block analysis results.

**File-level `analysis_summary`:**

- `total_transactions_analyzed`: integer, must equal the sum of all `blocks[].tx_count`.
- `heuristics_applied`: array of heuristic IDs applied. Must be the union of all per-block `heuristics_applied`. Must contain at least 5 distinct IDs, including `"cioh"` and `"change_detection"`.
- `flagged_transactions`: integer, must equal the sum of all `blocks[].analysis_summary.flagged_transactions`.
- `fee_rate_stats`: fee rate statistics computed across all non-coinbase transactions in all blocks. `min_sat_vb` ≤ `median_sat_vb` ≤ `max_sat_vb`, all non-negative.

**Per-block fields (each element of `blocks[]`):**

- `block_hash`: hex string (64 chars), standard reversed-hex display convention.
- `block_height`: integer, decoded from coinbase BIP34.
- `tx_count`: integer, total number of transactions in the block.
- `analysis_summary`: per-block summary, same shape as file-level summary. `total_transactions_analyzed` must equal `tx_count`. `flagged_transactions` must match the actual count of transactions with at least one `detected: true` heuristic.
- `transactions`: array of per-transaction analysis results. **Required for the first block** (`blocks[0]`): the grader validates that the array exists and its length equals `tx_count`. **Optional for subsequent blocks** — you may omit it or use an empty array to reduce JSON size and speed up grading.

**Per-transaction fields (each element of `blocks[].transactions[]`):**

- `txid`: hex string (64 chars).
- `heuristics`: object mapping heuristic ID → result object. Each result must have a `detected` boolean field.
- `classification`: one of `"simple_payment"`, `"consolidation"`, `"coinjoin"`, `"self_transfer"`, `"batch_payment"`, `"unknown"`.

> **Note:** The automated grader validates the `transactions` array (existence + length) for the first block only. Including full per-transaction data for all blocks is encouraged for your own analysis and web UI, but not required for grading.

---

## Markdown report requirements

For each block file, generate a Markdown report at `out/<blk_stem>.md` (e.g., `out/blk04330.md`). The report renders directly on GitHub and should include:

- **File overview:** source filename, number of blocks, total transactions analyzed.
- **Summary statistics:** fee rate distribution, script type breakdown, flagged transaction count (aggregated across all blocks in the file).
- **Per-block sections:** for each block in the file:
  - Block hash, height, timestamp, transaction count.
  - Per-heuristic findings: which heuristics fired and on how many transactions.
  - Notable transactions: highlight transactions classified as coinjoin, consolidation, or other interesting patterns.

Use Markdown tables and headers for structure. The report must be at least 1 KB in size (i.e., not empty or trivially generated).

**Important:** Markdown reports must be committed to the `out/` directory. The grader checks that committed reports exist and are reproducible (re-running `cli.sh` should produce reports of similar content).

---

## Heuristic catalogue

You must implement **at least 5** of the following heuristics. The `cioh` and `change_detection` heuristics are **mandatory**.

| ID | Name | Description |
|---|---|---|
| `cioh` | Common Input Ownership | All inputs to a transaction likely belong to the same entity. This is the foundational chain analysis assumption: if multiple inputs are spent together, they are probably controlled by the same wallet. Flag transactions with multiple inputs. |
| `change_detection` | Change Detection | Identify the likely change output in a transaction. Methods include: script type matching (change output matches input script type), round number analysis (payment amounts tend to be round), output ordering heuristics, and value analysis. Report the likely change index, method used, and confidence level. |
| `address_reuse` | Address Reuse | Detect when the same address appears in both inputs and outputs of a transaction, or across multiple transactions within the same block. Address reuse weakens privacy and links transactions to the same entity. |
| `coinjoin` | CoinJoin Detection | Identify CoinJoin transactions: multiple inputs from apparently different owners, equal-value outputs designed to obscure the transaction graph. Look for symmetric output values and high input counts. |
| `consolidation` | Consolidation Detection | Detect consolidation transactions: many inputs combined into 1-2 outputs, typically of the same script type. These reduce UTXO set size and are common wallet maintenance operations. |
| `self_transfer` | Self-Transfer Detection | Identify transactions where all inputs and outputs appear to belong to the same entity. All outputs match the input script type pattern, and the transaction has no obvious "payment" component. |
| `peeling_chain` | Peeling Chain Detection | Detect peeling chain patterns: a large input is split into one small output (payment) and one large output (change), with the large output being spent in a subsequent transaction following the same pattern. |
| `op_return` | OP_RETURN Analysis | Detect OP_RETURN outputs and classify the embedded data by protocol (Omni, OpenTimestamps, etc.). Track usage patterns within the block. |
| `round_number_payment` | Round Number Payment | Identify outputs with values that are round BTC amounts (e.g., 0.1 BTC, 0.01 BTC, 1 BTC). Round-number outputs are more likely to be payments; non-round outputs are more likely to be change. |

---

## APPROACH.md requirements

You must include an `APPROACH.md` file in the repository root that documents:

1. **Heuristics Implemented** — for each heuristic:
   - What it detects
   - How you detect/compute it
   - Your confidence model (how you assess reliability)
   - Known limitations (false positives, false negatives, edge cases)
2. **Architecture overview** — how your code is organized, what languages/frameworks you used, how data flows from raw block files to JSON + Markdown output.
3. **Trade-offs and design decisions** — accuracy vs performance, simplicity vs coverage, and any other significant choices.
4. **References** — BIPs, papers, blog posts, or documentation you used.

The file must be at least 500 bytes.

---

## Web visualizer requirements

Your web app must:

- Provide an interactive view of chain analysis results for a block.
- Allow users to explore individual transactions and their heuristic results.
- Visualize patterns: highlight CoinJoins, consolidations, flagged transactions.
- Display block-level statistics: fee rate distribution, script type breakdown.
- Serve `GET /api/health` → `200 { "ok": true }`.

Recommended features (not strictly required but strongly encouraged):

- Color-coded transaction classifications.
- Interactive filtering by heuristic or classification.
- Visual transaction graph showing input/output relationships.
- Click-to-expand details for each transaction's heuristic results.

---

## Committed outputs

Unlike Challenges 1 and 2, you **must commit the `out/` directory** to your repository. This directory should contain:

- `out/<blk_stem>.json` for each block file in the fixtures (e.g., `out/blk04330.json`).
- `out/<blk_stem>.md` for each block file in the fixtures (e.g., `out/blk04330.md`).

The grader verifies that these files exist and are reproducible.

---

## Demo video

Include a link to your demo video in `demo.md` at the repository root. The file should contain only the link.

- **Where to upload:** YouTube, Loom, or Google Drive. The link must be viewable by evaluators without requesting access (public or unlisted is fine; no "request access" links).
- **What to record:** a screen recording of your **web UI** walkthrough (no code walkthrough; don't spend time scrolling through source files).
- **What to demonstrate:** use your UI to analyze at least one block from the provided fixtures and walk through the chain analysis results.
- **How to explain:** speak as if to a non-technical person who wants to understand what chain analysis reveals about Bitcoin transactions.
- **Topics your walkthrough must cover (using the UI):**
  - What chain analysis is and why it matters for Bitcoin privacy
  - Common Input Ownership Heuristic — what it assumes and what it reveals
  - Change detection — how your tool identifies likely change outputs
  - At least one other heuristic you implemented and what it found
  - Transaction classification — how your tool categorizes transactions
  - Block-level statistics — fee rates, script type distribution, flagged transaction counts
  - A specific interesting transaction from the block data and what your analysis reveals about it
- **Hard limit:** the video must be strictly **less than 2 minutes** long.

---

## Acceptance criteria

- `cli.sh --block` succeeds on all provided block fixtures
- CLI JSON output matches the required schema (all fields present, correct types, valid enums)
- `block_count` matches the length of the `blocks` array
- File-level aggregated summary is consistent with per-block summaries
- At least 5 heuristics are applied per block, including `cioh` and `change_detection`
- `transactions` array is present and correct for the first block (length == `tx_count`)
- `flagged_transactions` count is consistent (per-block values are valid, file-level sum matches)
- Fee rate statistics are consistent (min ≤ median ≤ max, all non-negative)
- Markdown reports exist in `out/` for each block file and are reproducible
- `APPROACH.md` exists and documents at least 5 heuristics
- Web app launches via `web.sh` and serves `GET /api/health` → `200 { "ok": true }`
- Demo video link is included in `demo.md`
- Errors are returned as structured JSON with non-empty `error.code` and `error.message`

---

## Evaluation criteria

Evaluation happens in two phases:

### Phase 1: Automated evaluation (before deadline)

- **Schema validation:** JSON output is checked for required fields, correct types, and valid values.
- **Heuristic coverage:** at least 5 heuristics applied, `cioh` and `change_detection` mandatory.
- **Transaction validation:** `transactions` array is validated for the first block only (type check + length == tx_count). Subsequent blocks may omit it.
- **Consistency checks:** `flagged_transactions` is valid (0 ≤ n ≤ tx_count), fee rate stats are ordered correctly, file-level aggregation matches per-block data.
- **Report reproducibility:** committed Markdown reports exist and re-running `cli.sh` produces similar reports.
- **Documentation:** `APPROACH.md` exists, is substantial (>500 bytes), and covers at least 5 heuristics. `demo.md` contains a valid video link.
- **Web health check:** `web.sh` must start and respond to `GET /api/health`.

### Phase 2: Manual evaluation (after deadline)

- **Heuristic quality:** are the heuristics well-reasoned? Do they produce meaningful results? Are confidence levels appropriate?
- **Report quality:** clarity, completeness, and presentation of findings in the Markdown reports.
- **Web UI quality:** interactivity, visual design, and how well it surfaces analysis results.
- **APPROACH.md quality:** depth of explanation, awareness of limitations, quality of references.
- **Demo video:** coverage of required topics, clarity of explanation, adherence to the 2-minute limit.
- **Code quality:** readability, structure, and appropriate use of abstractions.

---

## Plagiarism policy

- All submitted code must be your own original work. You may use AI coding assistants (e.g. GitHub Copilot, ChatGPT, Claude) as tools, but you must understand and be able to explain every part of your submission.
- Copying code from other participants' submissions (current or past cohorts) is strictly prohibited.
- Using open-source libraries and referencing public documentation (BIPs, papers, blog posts, etc.) is encouraged — that is research, not plagiarism.
- Submissions will be checked for similarity against other participants. If two or more submissions share substantially identical logic or structure beyond what would arise from following the spec, all involved submissions may be disqualified.
- If you are unsure whether something counts as plagiarism, ask before submitting.
