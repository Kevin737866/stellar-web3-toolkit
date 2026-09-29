#!/usr/bin/env bash
set -euo pipefail

# coverage.sh — source-based line coverage for the whole workspace.
#
# Uses `cargo-llvm-cov` (LLVM source-based coverage) rather than a ptrace
# sampler. The contracts are `#![no_std]` and most of the suite runs inside the
# Soroban test host, which a ptrace sampler attributes to the harness rather than
# to the contract source, so its numbers are not usable here.
#
# Outputs (under $COVERAGE_DIR, default target/coverage):
#   lcov.info   — for editors, badge services and `genhtml`
#   html/       — browsable per-line report (html/index.html)
#   summary.txt — the console table, kept as a CI artifact
#
# Environment:
#   COVERAGE_DIR         output directory            (default: target/coverage)
#   COVERAGE_MIN_LINES   fail below this percentage  (default: 0 = report only)
#   COVERAGE_IGNORE      filename filter             (default: see below)
#
# Any arguments are forwarded to `cargo llvm-cov`.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT_DIR="${COVERAGE_DIR:-target/coverage}"
MIN_LINES="${COVERAGE_MIN_LINES:-0}"
# Test-only code and the property-test harness are not shipped product code.
# Counting them would let the headline number drift while contract coverage
# stays flat.
IGNORE="${COVERAGE_IGNORE:-'(^|/)(tests|benches)/|crates/contract-proptests/|/target/|/rustc/'}"

echo ">> Stellar Toolkit — line coverage"
echo "   ROOT=$ROOT"
echo "   output=$OUT_DIR"
echo "   ignore=$IGNORE"
if [ "$MIN_LINES" = "0" ]; then
  echo "   gate=disabled (set COVERAGE_MIN_LINES to enable)"
else
  echo "   gate=fail below ${MIN_LINES}% lines"
fi
echo ""

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  cat >&2 <<'EOF'
cargo-llvm-cov is not installed. Install it with:

  rustup component add llvm-tools-preview
  cargo install cargo-llvm-cov --locked

EOF
  exit 1
fi

mkdir -p "$OUT_DIR"

# The gate flag is only added when a gate is requested, so the default path
# stays a pure report and cannot fail for a coverage reason.
GATE_ARGS=()
if [ "$MIN_LINES" != "0" ]; then
  GATE_ARGS+=(--fail-under-lines "$MIN_LINES")
fi

echo ">> Instrumenting and running the test suite (this recompiles everything)..."
# `${GATE_ARGS[@]+...}` is the portable way to expand a possibly-empty array
# under `set -u` on bash 3.2 as well as bash 5.
cargo llvm-cov \
  --workspace \
  --all-features \
  --ignore-filename-regex "$IGNORE" \
  --lcov --output-path "$OUT_DIR/lcov.info" \
  --html --output-dir "$OUT_DIR/html" \
  ${GATE_ARGS[@]+"${GATE_ARGS[@]}"} \
  "$@"

# Best-effort console table. `report` re-reads the profile data the run above
# wrote, so it does not re-run the suite.
if cargo llvm-cov report --summary-only > "$OUT_DIR/summary.txt" 2>/dev/null; then
  cat "$OUT_DIR/summary.txt"
else
  echo "(no per-file summary available; the LCOV and HTML reports are unaffected)"
fi

echo ""
echo ">> Reports written to $OUT_DIR"
echo "   lcov: $OUT_DIR/lcov.info"
echo "   html: $OUT_DIR/html/index.html"
echo ""
echo "   Raise/lower the gate with COVERAGE_MIN_LINES=<percent>."
