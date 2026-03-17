#!/usr/bin/env bash
set -euo pipefail
cargo run --release --bin chain-lens -- "$@"
