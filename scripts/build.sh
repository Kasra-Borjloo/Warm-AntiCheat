#!/usr/bin/env bash
# Warm-AntiCheat Linux / macOS Build & Packaging Script

set -euo pipefail

echo "=========================================================="
echo "   Warm-AntiCheat Build Script (Linux / macOS)"
echo "=========================================================="

# 1. Format check
echo "[1/4] Checking code formatting..."
cargo fmt --all -- --check

# 2. Clippy lint
echo "[2/4] Running clippy linter..."
cargo clippy --workspace --all-targets -- -D warnings

# 3. Test execution
echo "[3/4] Running test suite..."
cargo test --workspace

# 4. Build release binaries
echo "[4/4] Compiling release binaries..."
cargo build --workspace --release

echo ""
echo "[SUCCESS] Build complete! Binaries available in target/release/"
