#!/usr/bin/env bash
# One-time local setup / sanity check for Umbra Exchange contributors.
#
# Verifies the toolchain floor documented in docs/BUILD_NOTES.md (rustc/cargo
# 1.75.0+) and does a dependency fetch so the first real build isn't also the
# first network fetch.
set -euo pipefail

REQUIRED_MAJOR=1
REQUIRED_MINOR=75

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found. Install Rust via https://rustup.rs first." >&2
    exit 1
fi

version_line="$(cargo --version)"
version="$(echo "$version_line" | awk '{print $2}')"
major="$(echo "$version" | cut -d. -f1)"
minor="$(echo "$version" | cut -d. -f2)"

if [ "$major" -lt "$REQUIRED_MAJOR" ] || { [ "$major" -eq "$REQUIRED_MAJOR" ] && [ "$minor" -lt "$REQUIRED_MINOR" ]; }; then
    echo "warning: found cargo $version, but docs/BUILD_NOTES.md verifies against 1.75.0+." >&2
    echo "         things may still work, but this isn't the tested floor." >&2
fi

echo "==> fetching workspace dependencies"
cd "$(dirname "${BASH_SOURCE[0]}")/../circuits"
cargo fetch

echo "==> done. Run scripts/test.sh to run the test suite."
