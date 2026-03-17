#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-3000}"
export PORT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Try release binary first, fall back to debug build
for BIN in \
    "$SCRIPT_DIR/target/release/web_server" \
    "$SCRIPT_DIR/target/release/chain-lens-web" \
    "$SCRIPT_DIR/target/debug/web_server" \
    "$SCRIPT_DIR/target/debug/chain-lens-web"
do
    if [ -x "$BIN" ]; then
        exec "$BIN"
    fi
done

# Binary not found — build first
echo "Building web server..." >&2
cargo build --release --bin web_server 2>/dev/null || \
cargo build --release 2>/dev/null

for BIN in \
    "$SCRIPT_DIR/target/release/web_server" \
    "$SCRIPT_DIR/target/release/chain-lens-web"
do
    if [ -x "$BIN" ]; then
        exec "$BIN"
    fi
done

echo "Error: could not find web_server binary after build" >&2
exit 1
