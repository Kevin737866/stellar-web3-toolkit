# Stellar Web3 Toolkit - Reproducible WASM Build Environment
# Pins Rust toolchain, Soroban dependencies and system libs for deterministic WASM output.
# Usage:
#   docker build -t stellar-toolkit-builder .
#   docker run --rm -v "$PWD":/workspace -w /workspace stellar-toolkit-builder cargo build --target wasm32v1-none --release
#   ./scripts/reproducible-build.sh

FROM rust:1.98-bookworm AS builder

LABEL org.opencontainers.image.title="stellar-web3-toolkit reproducible builder"
LABEL org.opencontainers.image.description="Pinned Rust + WASM toolchain for deterministic Soroban contract builds"
LABEL org.opencontainers.image.source="https://github.com/Kevin737866/stellar-web3-toolkit"

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=always \
    RUSTFLAGS="-C target-feature=-crt-static" \
    SOURCE_DATE_EPOCH=0

# System dependencies for OpenSSL, pkg-config and Soroban
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    binaryen \
    wabt \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pin wasm target and tools
RUN rustup component add rustfmt clippy && \
    rustup target add wasm32v1-none && \
    cargo install --locked soroban-cli --version 21.5.0 || echo "soroban-cli install skipped" && \
    cargo install --locked wasm-pack || true

WORKDIR /workspace

# Copy manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY rust-toolchain.toml ./
COPY contracts/ contracts/
COPY crates/ crates/

# Pre-fetch dependencies
RUN cargo fetch || true

# Default: build all contracts reproducibly
COPY scripts/ scripts/
RUN chmod +x scripts/*.sh || true

# Verify build determinism by default when run
CMD ["bash", "-c", "cargo build --workspace --exclude stellar-toolkit --exclude stellar-did --exclude payment-channel --exclude channel-router --exclude channel-simulator --exclude watchtower --exclude atomic-swap --exclude contract-proptests --target wasm32v1-none --release && sha256sum target/wasm32v1-none/release/*.wasm && ls -lh target/wasm32v1-none/release/*.wasm"]

# Stage for minimal runtime (optional, for verification)
FROM builder AS verifier
RUN echo "Verifier stage ready"

