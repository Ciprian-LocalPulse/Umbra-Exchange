#!/usr/bin/env bash
# Run the full Umbra Exchange test suite.
#
# Thin wrapper around the commands documented in docs/BUILD_NOTES.md, so
# CI and local contributors run exactly the same thing.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../circuits"

echo "==> reputation-accumulator"
cargo test -p reputation-accumulator

echo "==> proof-of-observation"
cargo test -p proof-of-observation

echo "==> whole workspace"
cargo test --workspace
