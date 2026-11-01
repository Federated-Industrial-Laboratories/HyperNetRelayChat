#!/usr/bin/env bash
# Validate the transport crate and its maintained boundary tests.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
