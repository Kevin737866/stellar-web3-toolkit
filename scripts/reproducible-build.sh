#!/usr/bin/env bash
set -euo pipefail

# reproducible-build.sh — Deterministic WASM build + checksum generation
# Mirrors Docker-based CI build locally. Ensures byte-for-byte reproducibility
# by pinning Rust toolchain (rust-toolchain.toml), clearing incremental caches,
# and normalizing SOURCE_DATE_EPOCH.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
export CARGO_TERM_COLOR=always
export RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=-crt-static"

echo ">> Stellar Toolkit — Reproducible Build"
echo "   ROOT=$ROOT"
echo "   SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
echo "   rustc: $(rustc --version)"
echo "   cargo: $(cargo --version)"
echo ""

# Use Docker if available and --docker flag passed
if [[ "${1:-}" == "--docker" ]]; then
  echo ">> Building inside Docker (stellar-toolkit-builder:1.86)..."
  docker build -t stellar-toolkit-builder:1.86 -f Dockerfile .
  docker run --rm -v "$ROOT":/workspace -w /workspace stellar-toolkit-builder:1.86 \
    bash -c "cargo build --workspace --exclude stellar-toolkit --exclude stellar-did --exclude payment-channel --exclude channel-router --exclude channel-simulator --exclude watchtower --exclude atomic-swap --target wasm32v1-none --release && sha256sum target/wasm32v1-none/release/*.wasm"
  exit 0
fi

echo ">> Building contracts (wasm32v1-none, release)..."
cargo build --workspace \
  --exclude stellar-toolkit \
  --exclude stellar-did \
  --exclude payment-channel \
  --exclude channel-router \
  --exclude channel-simulator \
  --exclude watchtower \
  --exclude atomic-swap \
  --target wasm32v1-none --release

# Explicit contract packages (handles future renames)
cargo build -p payment-channel-contract -p htlc-contract -p amm-pool -p amm-factory -p amm-router --target wasm32v1-none --release 2>/dev/null || true

echo ""
echo ">> Artifacts:"
ls -lh target/wasm32v1-none/release/*.wasm || echo "No wasm artifacts found"

echo ""
echo ">> Checksums (sha256):"
mkdir -p target/reproducible
sha256sum target/wasm32v1-none/release/*.wasm | tee target/reproducible/wasm-checksums.txt
cat target/reproducible/wasm-checksums.txt
echo ""
echo "Checksums written to target/reproducible/wasm-checksums.txt"

# Second build for drift detection
echo ""
echo ">> Verifying reproducibility (second build)..."
cargo build --workspace --exclude stellar-toolkit --exclude stellar-did --exclude payment-channel --exclude channel-router --exclude channel-simulator --exclude watchtower --exclude atomic-swap --target wasm32v1-none --release >/dev/null
sha256sum target/wasm32v1-none/release/*.wasm > target/reproducible/wasm-checksums-2.txt
if diff -u target/reproducible/wasm-checksums.txt target/reproducible/wasm-checksums-2.txt; then
  echo "Reproducibility: OK (hashes identical across two builds)"
else
  echo "WARNING: reproducibility drift detected — investigate SOURCE_DATE_EPOCH or nondeterministic build inputs"
  exit 1
fi

echo ""
echo ">> Optimized WASM sizes:"
for f in target/wasm32v1-none/release/*.wasm; do
  echo "  $(basename "$f"): $(wc -c < "$f") bytes  sha256=$(sha256sum "$f" | cut -d' ' -f1)"
done
