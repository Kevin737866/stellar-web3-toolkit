# Reproducible WASM Builds

**Issue:** #119 Create Dockerized build environment for reproducible WASM

This document describes how the toolkit guarantees byte-for-byte deterministic Soroban WASM across machines, CI and Docker.

## Pinning

- **Rust:** `rust-toolchain.toml` → `1.98.1` + `wasm32v1-none` + `rustfmt`/`clippy`.
- **System:** `Dockerfile` → `rust:1.98-bookworm` + `binaryen` + `wabt` + `soroban-cli 21.5.0`.
- **Dependencies:** `Cargo.lock` is committed; `cargo build` uses locked versions.
- **Env:** `SOURCE_DATE_EPOCH=0`, `RUSTFLAGS="-C target-feature=-crt-static"` in both CI and scripts.

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/reproducible-build.sh` | Native reproducible build + double-build diff + `target/reproducible/wasm-checksums.txt` |
| `scripts/reproducible-build.sh --docker` | Same inside `stellar-toolkit-builder:1.98` |
| `scripts/verify-bytecode.sh --reference <file>` | Compare local WASM against a release's `wasm-checksums.txt` |
| `scripts/verify-bytecode.sh --docker` | Compare local WASM against Docker build |

## CI

`.github/workflows/ci.yml` job `wasm` runs the same steps as `reproducible-build.sh`, uploads `wasm-checksums.txt` and fails if the second build's hashes differ. The `release` workflow (`release.yml`) reuses the script and attaches `dist/wasm-checksums.txt` to every GitHub Release.

## Verification

```bash
./scripts/reproducible-build.sh
cat target/reproducible/wasm-checksums.txt
sha256sum target/wasm32v1-none/release/*.wasm

# Against a release
gh release download v0.1.0 --pattern wasm-checksums.txt
./scripts/verify-bytecode.sh --reference wasm-checksums.txt

# Docker parity
./scripts/verify-bytecode.sh --docker
```

If verification fails, check `SOURCE_DATE_EPOCH`, `Cargo.lock` drift, or toolchain mismatch (`rustc --version` vs. `rust-toolchain.toml`).
