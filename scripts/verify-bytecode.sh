#!/usr/bin/env bash
set -euo pipefail
# verify-bytecode.sh — Compare local WASM checksums against a reference artifact or Docker build
# Usage: ./scripts/verify-bytecode.sh [--reference path/to/checksums.txt] [--docker]

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

REF=""
USE_DOCKER=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reference) REF="$2"; shift 2;;
    --docker) USE_DOCKER=true; shift;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

if [[ "$USE_DOCKER" == true ]]; then
  echo ">> Verifying via Docker reproducible builder..."
  docker build -t stellar-toolkit-builder:1.98 -f Dockerfile . >/dev/null
  docker run --rm -v "$ROOT":/workspace -w /workspace stellar-toolkit-builder:1.98 \
    bash -c "cargo build --workspace --exclude stellar-toolkit --exclude payment-channel --exclude channel-router --exclude channel-simulator --exclude watchtower --exclude atomic-swap --target wasm32v1-none --release && sha256sum target/wasm32v1-none/release/*.wasm" > /tmp/docker-checksums.txt
  echo "Docker checksums:"
  cat /tmp/docker-checksums.txt
  echo ""
  echo "Local checksums:"
  sha256sum target/wasm32v1-none/release/*.wasm || { echo "No local wasm found — run ./scripts/reproducible-build.sh first"; exit 1; }
  echo ""
  if diff -u <(sort /tmp/docker-checksums.txt) <(sha256sum target/wasm32v1-none/release/*.wasm | sort); then
    echo "Verification: PASS — local and Docker builds match"
  else
    echo "Verification: FAIL — local and Docker builds differ"
    exit 1
  fi
  exit 0
fi

if [[ -n "$REF" ]]; then
  echo ">> Comparing local build against reference: $REF"
  [[ -f "$REF" ]] || { echo "Reference not found: $REF"; exit 1; }
  sha256sum target/wasm32v1-none/release/*.wasm > /tmp/local-checksums.txt
  # Compare only filenames present in reference
  echo "Reference:"
  cat "$REF"
  echo "Local:"
  cat /tmp/local-checksums.txt
  if diff -u <(sort "$REF") <(sort /tmp/local-checksums.txt); then
    echo "Verification: PASS"
  else
    echo "Verification: FAIL"
    exit 1
  fi
else
  echo ">> Local WASM checksums:"
  sha256sum target/wasm32v1-none/release/*.wasm 2>/dev/null || echo "No wasm artifacts — run ./scripts/reproducible-build.sh"
  echo ""
  echo "Usage: $0 --reference <checksums.txt>   # compare against release artifact"
  echo "       $0 --docker                      # compare against Docker build"
fi
