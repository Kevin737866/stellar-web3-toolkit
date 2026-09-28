#!/usr/bin/env bash
set -euo pipefail
# test-verify-bytecode.sh — Self-contained tests for scripts/verify-bytecode.sh --diff
#
# Creates a temp directory of fake .wasm artifacts, points WASM_DIR at it, and
# exercises the diff classification, the JSON output and every exit code. Does
# not require a build, a network, or a Docker daemon, and cleans up after
# itself. Run with: bash scripts/test-verify-bytecode.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERIFY="$SCRIPT_DIR/verify-bytecode.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ART="$TMP/art"
REF="$TMP/reference.txt"
mkdir -p "$ART"

PASS=0
FAIL=0

# --- tiny assertion helpers -------------------------------------------------

ok() { PASS=$((PASS + 1)); echo "  ok   — $1"; }

no() {
  FAIL=$((FAIL + 1))
  echo "  FAIL — $1"
  if [[ $# -gt 1 ]]; then echo "         $2"; fi
  return 0
}

# run <expected-exit> <description> <command...>
run() {
  local want="$1" desc="$2"; shift 2
  set +e
  "$@" >"$TMP/out" 2>"$TMP/err"
  local got=$?
  set -e
  if [[ "$got" == "$want" ]]; then
    ok "$desc (exit $got)"
  else
    no "$desc" "expected exit $want, got $got; stderr: $(cat "$TMP/err")"
  fi
}

has() { grep -qF -- "$2" "$TMP/out" && ok "$1" || no "$1" "missing from stdout: $2"; }
# Diagnostics for a non-zero exit go to stderr, so that --json keeps stdout pure.
has_err() { grep -qF -- "$2" "$TMP/err" && ok "$1" || no "$1" "missing from stderr: $2"; }
hasnt() { grep -qF -- "$2" "$TMP/out" && no "$1" "unexpectedly present: $2" || ok "$1"; }

diff_mode() { WASM_DIR="$ART" bash "$VERIFY" --diff "$@"; }

# --- fixtures ----------------------------------------------------------------
# Four artifacts. Their *original* hashes are recorded first; later cases
# mutate the directory to create each classification.
printf 'alpha-v1' > "$ART/alpha.wasm"
printf 'beta-v1'  > "$ART/beta.wasm"
printf 'gamma-v1' > "$ART/gamma.wasm"
printf 'delta-v1' > "$ART/delta.wasm"

ORIG="$TMP/original.txt"
( cd "$ART" && sha256sum alpha.wasm beta.wasm gamma.wasm delta.wasm ) > "$ORIG"

# --- 1. identical checksums pass ---------------------------------------------
IDENTICAL="$TMP/identical.txt"
( cd "$ART" && sha256sum alpha.wasm beta.wasm > "$IDENTICAL" )
# Hide everything the reference does not mention, so the sets match exactly.
mkdir -p "$TMP/hidden"
mv "$ART/gamma.wasm" "$ART/delta.wasm" "$TMP/hidden/"
run 0 "identical checksums pass" diff_mode "$IDENTICAL"
has "identical run reports PASS" "Verification: PASS"
has "identical run reports the UNCHANGED class" "UNCHANGED"
run 0 "--json exits 0 when identical" diff_mode "$IDENTICAL" --json
has "--json reports pass" '"result":"pass"'
has "--json reports 2 unchanged" '"unchanged":2'
mv "$TMP/hidden/gamma.wasm" "$TMP/hidden/delta.wasm" "$ART/"
# A locally-added artifact whose hashes agree with nothing must still be
# classified, not silently dropped: the pre-existing --reference mode's comment
# claims it "compare[s] only filenames present in reference" but diffs the whole
# file, and this mode deliberately reports the difference instead.
run 1 "a locally-added artifact is not silently ignored" diff_mode "$IDENTICAL"
has "gamma.wasm classified as ADDED" "  gamma.wasm"
has "ADDED class is reported for extra local artifacts" "ADDED"

# --- 2. a changed hash is `changed`, never `added` or `removed` ---------------
printf 'gamma-v2-MODIFIED' > "$ART/gamma.wasm"
# $ORIG still records gamma's *pre-modification* hash, which is what makes this
# a `changed` case rather than an `unchanged` one.
CHANGED="$TMP/changed.txt"
cp "$ORIG" "$CHANGED"
run 1 "one changed hash fails verification" diff_mode "$CHANGED"
has "changed class is reported" "CHANGED"
has "gamma.wasm is listed under CHANGED" "  gamma.wasm"
has "changed run reports FAIL" "Verification: FAIL"
run 1 "--json classifies a changed hash exactly once" diff_mode "$CHANGED" --json
has "gamma counted as changed" '"changed":1'
has "gamma is not counted as removed" '"removed":0'
has "gamma is not counted as added" '"added":0'
has "alpha/beta/delta counted as unchanged" '"unchanged":3'

# --- 3. an artifact only in the local build is `added` ------------------------
printf 'epsilon-local-only' > "$ART/epsilon.wasm"
run 1 "local-only artifact fails verification" diff_mode "$CHANGED"
has "epsilon.wasm is listed under ADDED" "  epsilon.wasm"
has "ADDED direction is stated" "ADDED      local only"
run 1 "--json counts the local-only artifact" diff_mode "$CHANGED" --json
has "epsilon counted as added" '"added":1'
rm -f "$ART/epsilon.wasm"

# --- 4. an artifact only in the reference is `removed` ------------------------
ZETA_REF="$TMP/zeta.txt"
cp "$ORIG" "$ZETA_REF"
echo "2222222222222222222222222222222222222222222222222222222222222222  zeta.wasm" >> "$ZETA_REF"
run 1 "reference-only artifact fails verification" diff_mode "$ZETA_REF"
has "zeta.wasm is listed under REMOVED" "  zeta.wasm"
has "REMOVED direction is stated" "REMOVED    reference only"
run 1 "--json counts the missing artifact" diff_mode "$ZETA_REF" --json
has "zeta counted as removed" '"removed":1'

# --- 5. all four classes at once ---------------------------------------------
# gamma is CHANGED (local differs from the reference), eta is ADDED (local only)
# and epsilon is REMOVED (reference only). alpha/beta/delta are UNCHANGED.
ALL="$TMP/all.txt"
printf 'gamma-v1-original' > "$ART/gamma.wasm"   # restore, so gamma is CHANGED
rm -f "$ART/epsilon.wasm"
printf 'eta-local-only' > "$ART/eta.wasm"
printf 'epsilon-v1' > "$TMP/epsilon.wasm"
cp "$ORIG" "$ALL"
( cd "$TMP" && sha256sum epsilon.wasm ) >> "$ALL"
run 1 "mixed differences fail verification" diff_mode "$ALL"
has "epsilon.wasm classified as REMOVED" "  epsilon.wasm"
has "eta.wasm classified as ADDED" "  eta.wasm"
has "gamma.wasm classified as CHANGED" "  gamma.wasm"
for label in UNCHANGED CHANGED ADDED REMOVED; do
  has "mixed run reports the $label class" "$label"
done
has "mixed run summarises the counts" "1 changed, 1 added, 1 removed"
has "alpha.wasm listed as UNCHANGED" "  alpha.wasm"
has "beta.wasm listed as UNCHANGED" "  beta.wasm"
run 1 "--json summarises the mixed case" diff_mode "$ALL" --json
has "--json unchanged count" '"unchanged":3'
has "--json changed count" '"changed":1'
has "--json added count" '"added":1'
has "--json removed count" '"removed":1'
has "--json names the added artifact" '"eta.wasm"'
has "--json names the removed artifact" '"epsilon.wasm"'
has "--json emits the mode" '"mode":"diff"'
# --json must put nothing but the document on stdout, so that a CI job can pipe
# it straight into a JSON parser.
if command -v python3 >/dev/null 2>&1; then
  if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["mode"]=="diff"' "$TMP/out" 2>/dev/null; then
    ok "--json output parses as JSON"
  else
    no "--json output parses as JSON" "$(cat "$TMP/out")"
  fi
else
  ok "--json output parses as JSON (python3 unavailable; structural check only)"
fi

# --- 6. a reference with full target/... paths still matches -----------------
PATHS="$TMP/paths.txt"
( cd "$ART" && sha256sum alpha.wasm beta.wasm | awk '{ print $1, "target/wasm32-unknown-unknown/release/" $2 }' ) > "$PATHS"
mkdir -p "$TMP/hidden2"
mv "$ART/gamma.wasm" "$ART/delta.wasm" "$ART/eta.wasm" "$TMP/hidden2/"
run 0 "reference paths are normalised to basenames" diff_mode "$PATHS"
mv "$TMP/hidden2/"*.wasm "$ART/"

# --- 7. usage errors exit 2, not 1 -------------------------------------------
run 2 "unknown arg in diff mode is a usage error" diff_mode "$ALL" --nope
has "unknown arg is reported" "Unknown arg: --nope"
run 2 "--diff without a value is a usage error" diff_mode
run 2 "--diff combined with --docker is a usage error" diff_mode "$ALL" --docker
run 2 "--diff combined with --reference is a usage error" diff_mode "$ALL" --reference "$ALL"
run 2 "--json without --diff is a usage error" bash "$VERIFY" --json
run 2 "missing reference file is a usage error" diff_mode "$TMP/does-not-exist.txt"
has "missing reference is explained" "Reference not found"

# --- 8. nothing to compare exits 3 -------------------------------------------
: > "$TMP/empty.txt"
run 3 "empty reference exits 3" diff_mode "$TMP/empty.txt"
has_err "empty reference is explained" "nothing to compare"
printf '\n   \n' > "$TMP/blank.txt"
run 3 "reference of only blank lines exits 3" diff_mode "$TMP/blank.txt"
run 3 "missing artifact directory exits 3" \
  env WASM_DIR="$TMP/no-such-dir" bash "$VERIFY" --diff "$ALL"
has "missing artifact directory is explained" "No local wasm directory"
mkdir -p "$TMP/empty-dir"
run 3 "no local artifacts exits 3" env WASM_DIR="$TMP/empty-dir" bash "$VERIFY" --diff "$ALL"
has_err "no local artifacts is explained" "nothing to compare"

# --- 9. a malformed reference is an input error, not a silent pass -----------
DUP="$TMP/dup.txt"
( cd "$ART" && sha256sum alpha.wasm ) > "$DUP"
( cd "$ART" && sha256sum alpha.wasm ) >> "$DUP"
run 2 "duplicate artifact names in the reference are rejected" diff_mode "$DUP"
has "duplicate names are explained" "duplicate artifact names"

# --- 10. the pre-existing modes keep their original exit codes ---------------
run 1 "--reference with a missing file still exits 1" \
  bash "$VERIFY" --reference "$TMP/does-not-exist.txt"
run 1 "unknown arg outside diff mode still exits 1" bash "$VERIFY" --bogus
run 0 "no-arg help path still exits 0" bash "$VERIFY"
has "usage still documents --reference" "--reference <checksums.txt>"
has "usage still documents --docker" "--docker"
has "usage documents the new --diff mode" "--diff"

# --- summary -----------------------------------------------------------------
echo ""
echo "passed: $PASS   failed: $FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
