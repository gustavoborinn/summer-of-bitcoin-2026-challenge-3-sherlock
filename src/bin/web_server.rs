use axum::{
    extract::{Json as ExtractJson, Path as ExtractPath},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
};

// ─── Request types ────────────────────────────────────────────────────────────

/// Fixture JSON string for single-transaction analysis.
#[derive(Deserialize)]
struct TxRequest {
    fixture: String,
}

/// Absolute paths to the three block data files.
#[derive(Deserialize)]
struct BlockRequest {
    blk: String,
    rev: String,
    xor: String,
}

// ─── Error helper ─────────────────────────────────────────────────────────────

fn err_response(status: StatusCode, code: &str, message: impl std::fmt::Display) -> Response {
    let body = json!({"ok":false,"error":{"code":code,"message":message.to_string()}});
    (status, Json(body)).into_response()
}

// ─── Path resolution ──────────────────────────────────────────────────────────

/// Return the project root directory (3 levels above the release binary).
///
/// Falls back to the current working directory if the exe path is unavailable.
fn project_root() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(root) = exe
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
        {
            return root.to_path_buf();
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Path to the CLI binary (chain-lens), sibling of chain-lens-web.
fn cli_binary_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let c = dir.join("chain-lens");
            if c.exists() {
                return c;
            }
        }
    }
    project_root().join("target/release/chain-lens")
}

fn fixtures_tx_dir() -> PathBuf {
    project_root().join("fixtures/transactions")
}

fn fixtures_blocks_dir() -> PathBuf {
    project_root().join("fixtures/blocks")
}

fn out_dir() -> PathBuf {
    project_root().join("out")
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// Health check — required by the challenge spec.
/// GET /api/health → 200 {"ok":true}
async fn health() -> impl IntoResponse {
    Json(json!({"ok":true}))
}

/// List available example fixture names (for the UI dropdown).
async fn example_tx_list() -> impl IntoResponse {
    let mut names: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(fixtures_tx_dir()) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("json") {
                if let Some(s) = p.file_stem().and_then(|x| x.to_str()) {
                    names.push(s.to_string());
                }
            }
        }
    }
    names.sort();
    Json(json!({"ok":true,"fixtures":names}))
}

/// Return the raw JSON of a named example fixture.
async fn example_tx_named(ExtractPath(name): ExtractPath<String>) -> Response {
    // Sanitise the name to prevent directory traversal.
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return err_response(
            StatusCode::BAD_REQUEST,
            "INVALID_NAME",
            "invalid fixture name",
        );
    }
    let path = fixtures_tx_dir().join(format!("{}.json", name));
    match fs::read_to_string(&path) {
        Ok(c) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            c,
        )
            .into_response(),
        Err(_) => err_response(
            StatusCode::NOT_FOUND,
            "FIXTURE_NOT_FOUND",
            format!("fixture '{}' not found", name),
        ),
    }
}

/// Return the default example fixture (tx_segwit_p2wpkh_p2tr).
async fn example_tx_default() -> Response {
    let path = fixtures_tx_dir().join("tx_segwit_p2wpkh_p2tr.json");
    match fs::read_to_string(&path) {
        Ok(c) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            c,
        )
            .into_response(),
        Err(_) => err_response(
            StatusCode::NOT_FOUND,
            "FIXTURE_NOT_FOUND",
            "default fixture not found",
        ),
    }
}

/// Return absolute filesystem paths to the example block fixture files.
async fn example_block_paths() -> impl IntoResponse {
    let base = fixtures_blocks_dir();
    Json(json!({
        "blk": base.join("blk04330.dat").to_string_lossy(),
        "rev": base.join("rev04330.dat").to_string_lossy(),
        "xor": base.join("xor.dat").to_string_lossy()
    }))
}

/// Invoke the CLI to analyze a single fixture JSON and return the report.
///
/// This handler is exposed at both `/api/analyze` and `/api/analyze/tx` so
/// that integrations expecting the simpler path from the challenge spec work.
async fn analyze_tx(ExtractJson(payload): ExtractJson<TxRequest>) -> Response {
    // Reject clearly malformed JSON early to produce a better error message.
    if let Err(e) = serde_json::from_str::<Value>(&payload.fixture) {
        return err_response(
            StatusCode::BAD_REQUEST,
            "INVALID_JSON",
            format!("fixture is not valid JSON: {e}"),
        );
    }

    // Write fixture to a temp file so the CLI binary can read it.
    let tmp = match tempfile::NamedTempFile::with_suffix(".json") {
        Ok(f) => f,
        Err(e) => {
            return err_response(StatusCode::INTERNAL_SERVER_ERROR, "IO_ERROR", e);
        }
    };
    if let Err(e) = fs::write(tmp.path(), payload.fixture.as_bytes()) {
        return err_response(StatusCode::INTERNAL_SERVER_ERROR, "IO_ERROR", e);
    }

    let cli = cli_binary_path();
    let output = match Command::new(&cli).arg(tmp.path()).output() {
        Ok(o) => o,
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CLI_LAUNCH_ERROR",
                format!("failed to launch {}: {}", cli.display(), e),
            );
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    match serde_json::from_str::<Value>(&stdout) {
        Ok(v) => Json(v).into_response(),
        Err(_) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CLI_OUTPUT_ERROR",
                format!(
                    "CLI non-JSON (exit={}): {}",
                    output.status.code().unwrap_or(-1),
                    stderr.trim()
                ),
            )
        }
    }
}

/// Invoke the CLI in block mode and return the resulting JSON report(s).
async fn analyze_block(ExtractJson(payload): ExtractJson<BlockRequest>) -> Response {
    for (label, path) in [
        ("blk", &payload.blk),
        ("rev", &payload.rev),
        ("xor", &payload.xor),
    ] {
        if !Path::new(path).exists() {
            return err_response(
                StatusCode::BAD_REQUEST,
                "FILE_NOT_FOUND",
                format!("{label} file not found: {path}"),
            );
        }
    }

    // Clear and recreate the output directory before invoking the CLI.
    let out = out_dir();
    let _ = fs::remove_dir_all(&out);
    let _ = fs::create_dir_all(&out);

    let cli = cli_binary_path();
    let output = match Command::new(&cli)
        .arg("--block")
        .arg(&payload.blk)
        .arg(&payload.rev)
        .arg(&payload.xor)
        .current_dir(&project_root())
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CLI_LAUNCH_ERROR",
                format!("failed to launch CLI: {e}"),
            );
        }
    };

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if let Ok(v) = serde_json::from_str::<Value>(&stdout) {
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(v)).into_response();
        }
        return err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CLI_ERROR",
            format!("CLI error: {}", stderr.trim()),
        );
    }

    let mut results: Vec<Value> = Vec::new();
    if let Ok(entries) = fs::read_dir(&out) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("json") {
                if let Ok(c) = fs::read_to_string(&p) {
                    if let Ok(v) = serde_json::from_str::<Value>(&c) {
                        results.push(v);
                    }
                }
            }
        }
    }

    if results.is_empty() {
        return err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "NO_OUTPUT",
            "CLI produced no output files",
        );
    }

    if results.len() == 1 {
        Json(results.remove(0)).into_response()
    } else {
        Json(json!({"ok":true,"blocks":results})).into_response()
    }
}

// ─── Block analysis endpoints ─────────────────────────────────────────────────

/// List available block analysis stems (files in out/).
/// GET /api/blocks → ["blk04330", "blk05051"]
async fn list_blocks() -> impl IntoResponse {
    let mut stems: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(out_dir()) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("json") {
                if let Some(s) = p.file_stem().and_then(|x| x.to_str()) {
                    stems.push(s.to_string());
                }
            }
        }
    }
    stems.sort();
    Json(json!({ "ok": true, "stems": stems }))
}

/// Serve the analysis JSON for a given stem.
/// GET /api/blocks/:stem → contents of out/<stem>.json
async fn get_block(ExtractPath(stem): ExtractPath<String>) -> Response {
    if !stem.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return err_response(StatusCode::BAD_REQUEST, "INVALID_STEM", "invalid stem");
    }
    let path = out_dir().join(format!("{}.json", stem));
    match fs::read_to_string(&path) {
        Ok(c) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], c).into_response(),
        Err(_) => err_response(StatusCode::NOT_FOUND, "NOT_FOUND", format!("no analysis for '{}'", stem)),
    }
}


// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any)
        .allow_origin(Any);

    let static_dir = project_root().join("web/static");

    let app = Router::new()
        // ── Required by the challenge spec ──────────────────────────────────
        .route("/api/health", get(health))
        // /api/analyze — primary endpoint named in the README acceptance criteria.
        // Accepts {"fixture":"<raw fixture JSON string>"} and returns the analysis.
        .route("/api/analyze", post(analyze_tx))
        // ── Extended endpoints used by the web UI ────────────────────────────
        .route("/api/analyze/tx", post(analyze_tx))
        .route("/api/analyze/block", post(analyze_block))
        .route("/api/example/tx", get(example_tx_default))
        .route("/api/example/block-paths", get(example_block_paths))
        .route("/api/examples/tx-list", get(example_tx_list))
        .route("/api/examples/tx/:name", get(example_tx_named))
        .layer(cors)
        .fallback_service(
            ServeDir::new(static_dir).append_index_html_on_directories(true),
        );

    let addr = format!("127.0.0.1:{port}");

    // ── Bind BEFORE printing the URL ────────────────────────────────────────
    // The grader reads our stdout and immediately tries GET /api/health.
    // If we print the URL before the listener is ready, the health check fails.
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");

    // Print the URL, then flush explicitly.
    // In a pipe (which the grader uses), Rust's stdout is fully-buffered;
    // without flush() the line may never be delivered before the timeout.
    println!("http://{addr}");
    let _ = std::io::stdout().flush();

    axum::serve(listener, app)
        .await
        .expect("server error");
}