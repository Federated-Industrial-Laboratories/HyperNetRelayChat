#!/usr/bin/env bash
# Validate the HRC crate and its maintained contract tests.
set -euo pipefail
cd "$(dirname "$0")/.."
source Tools/Environment.sh
python3 -B -m unittest discover -s Tests/Packaging -p 'Test*.py'
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
