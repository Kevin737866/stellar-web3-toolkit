#!/usr/bin/env bash
set -euo pipefail
# verify-bytecode.sh — Compare local WASM checksums against a reference artifact or Docker build
# Usage: ./scripts/verify-bytecode.sh [--reference path/to/checksums.txt] [--docker]
#        ./scripts/verify-bytecode.sh --diff path/to/checksums.txt [--json]
#
# --diff exit codes (the pre-existing modes keep their original behaviour: 0 on
# match, 1 on mismatch, 1 on a bad argument):
#   0  local and reference are byte-for-byte identical
#   1  at least one artifact is added / removed / changed  (verification failed)
#   2  usage or input error (bad flag combination, malformed checksum file)
#   3  nothing to compare (no local artifacts, or an empty reference)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Artifact directory the new --diff mode reads. Overridable so the mode can be
# exercised against fixture files without performing (or polluting) a real
# build; the default is exactly what the pre-existing modes glob.
WASM_DIR="${WASM_DIR:-target/wasm32-unknown-unknown/release}"

REF=""
USE_DOCKER=false
DIFF_REF=""
JSON=false
DIFF_MODE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reference) REF="$2"; shift 2;;
    --docker) USE_DOCKER=true; shift;;
    --diff)
      # Exit 2 (not 1) for a usage error once --diff is in play, so CI can tell
      # "you called me wrong" from "the build is wrong". See the header.
      [[ $# -ge 2 ]] || { echo "Missing value for --diff"; exit 2; }
      DIFF_REF="$2"; DIFF_MODE=true; shift 2;;
    --json)
      JSON=true; shift;;
    *)
      echo "Unknown arg: $1"
      if [[ "$DIFF_MODE" == true ]]; then exit 2; else exit 1; fi;;
  esac
done

# ---------------------------------------------------------------------------
# Diff mode: classify every artifact instead of emitting a text diff.
#
# `diff -u` cannot say *what kind* of difference occurred, so in CI a renamed
# artifact, a deleted artifact and a genuinely rebuilt artifact are all just
# "one line differs". This mode reports the four cases separately:
#
#   UNCHANGED  present in both, identical sha256
#   CHANGED    present in both, different sha256   (the artifact was rebuilt)
#   ADDED      present in the local build only     (new artifact)
#   REMOVED    present in the reference only       (artifact is missing locally)
#
# Direction is stated explicitly everywhere: ADDED means "local only",
# REMOVED means "reference only / missing locally". Note that the pre-existing
# --reference mode diffs the *whole* file despite its comment claiming it
# "compare[s] only filenames present in reference"; this mode deliberately does
# not inherit that, because the local-only / reference-only split is the whole
# point of the classification.
#
# Portability: only `awk`, `sort`, `uniq`, `wc` and `sha256sum` are used, and
# none with a GNU-only flag. `join -a1 -a2 -o` was the obvious choice and is
# wrong: for an *unpairable* line the missing field is dropped rather than
# emitted empty, so a reference-only artifact is indistinguishable from a
# local-only one. The classification is therefore done in `awk`, which gives an
# unambiguous per-line verdict. `${var,,}` is also avoided throughout because it
# is a bash 4+ expansion and macOS still ships bash 3.2.
# ---------------------------------------------------------------------------
if [[ "$DIFF_MODE" == true ]]; then
  if [[ -n "$REF" || "$USE_DOCKER" == true ]]; then
    echo "Error: --diff cannot be combined with --reference or --docker"
    exit 2
  fi
  [[ -f "$DIFF_REF" ]] || { echo "Reference not found: $DIFF_REF"; exit 2; }
  [[ -d "$WASM_DIR" ]] || { echo "No local wasm directory: $WASM_DIR — run ./scripts/reproducible-build.sh first"; exit 3; }

  # In --json mode stdout must contain nothing but the JSON document, so the
  # human progress line moves to stderr. A CI job doing `--json | jq` would
  # otherwise fail to parse.
  if [[ "$JSON" == true ]]; then
    echo ">> Diffing local build against reference: $DIFF_REF" >&2
  else
    echo ">> Diffing local build against reference: $DIFF_REF"
  fi

  # Normalise both sides to "<basename> <hash>", sorted by basename, so the
  # comparison is path independent (the reference written by
  # reproducible-build.sh holds full target/ paths).
  # `trap ... EXIT` keeps the temp files from surviving a failure.
  local_named="$(mktemp)"; ref_named="$(mktemp)"; classes="$(mktemp)"
  trap 'rm -f "$local_named" "$ref_named" "$classes"' EXIT

  shopt -s nullglob
  local_wasm=("$WASM_DIR"/*.wasm)
  shopt -u nullglob
  if [[ ${#local_wasm[@]} -eq 0 ]]; then
    echo "No local wasm artifacts in $WASM_DIR — nothing to compare" >&2
    exit 3
  fi
  sha256sum "${local_wasm[@]}" | awk '{ n = $2; sub(/.*\//, "", n); print n, $1 }' | sort > "$local_named"

  # `awk` alone filters blank and short lines; a separate `grep -v` would
  # return 1 on an all-blank file and, under `set -o pipefail`, abort the script.
  awk 'NF >= 2 { n = $2; sub(/.*\//, "", n); print n, $1 }' "$DIFF_REF" | sort > "$ref_named"

  if [[ ! -s "$ref_named" ]]; then
    echo "Reference contains no checksum entries: $DIFF_REF — nothing to compare" >&2
    exit 3
  fi

  # A duplicate artifact name would make the two sides ambiguous, so refuse the
  # input instead of silently picking one of the entries.
  if [[ "$(uniq -d "$local_named" | wc -l | tr -d ' ')" != "0" ]]; then
    echo "Malformed local checksum set: duplicate artifact names"
    exit 2
  fi
  if [[ "$(uniq -d "$ref_named" | wc -l | tr -d ' ')" != "0" ]]; then
    echo "Malformed reference checksum file: duplicate artifact names"
    exit 2
  fi

  # One awk pass per direction. `$1` is the basename, `$2` the hash, and an
  # absent key is exactly the "only on one side" case.
  awk 'NR == FNR { r[$1] = $2; next }
       !($1 in r) { print "ADDED", $1; next }
       r[$1] != $2 { print "CHANGED", $1; next }
       { print "UNCHANGED", $1 }' "$ref_named" "$local_named" > "$classes"
  awk 'NR == FNR { l[$1] = 1; next }
       !($1 in l) { print "REMOVED", $1 }' "$local_named" "$ref_named" >> "$classes"

  n_unchanged=0; n_changed=0; n_added=0; n_removed=0
  changed_list=""; added_list=""; removed_list=""; unchanged_list=""
  while read -r class name; do
    case "$class" in
      UNCHANGED) n_unchanged=$((n_unchanged + 1)); unchanged_list+="$name"$'\n';;
      CHANGED)   n_changed=$((n_changed + 1));     changed_list+="$name"$'\n';;
      ADDED)     n_added=$((n_added + 1));         added_list+="$name"$'\n';;
      REMOVED)   n_removed=$((n_removed + 1));     removed_list+="$name"$'\n';;
    esac
  done < "$classes"

  json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
  json_array() {
    local first=1 line out=""
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      if [[ $first -eq 1 ]]; then first=0; else out+=","; fi
      out+="\"$(json_escape "$line")\""
    done <<< "$1"
    printf '[%s]' "$out"
  }

  if [[ "$JSON" == true ]]; then
    printf '{"mode":"diff","reference":"%s","wasm_dir":"%s","counts":{"unchanged":%d,"changed":%d,"added":%d,"removed":%d},"artifacts":{"unchanged":%s,"changed":%s,"added":%s,"removed":%s},"result":"%s"}\n' \
      "$(json_escape "$DIFF_REF")" "$(json_escape "$WASM_DIR")" \
      "$n_unchanged" "$n_changed" "$n_added" "$n_removed" \
      "$(json_array "$unchanged_list")" "$(json_array "$changed_list")" \
      "$(json_array "$added_list")" "$(json_array "$removed_list")" \
      "$([[ $((n_changed + n_added + n_removed)) -eq 0 ]] && echo pass || echo fail)"
    exit "$([[ $((n_changed + n_added + n_removed)) -eq 0 ]] && echo 0 || echo 1)"
  fi

  echo ""
  echo "Classification (relative to the local build):"
  echo "  UNCHANGED  present in both, identical sha256 ($n_unchanged)"
  echo "  CHANGED    present in both, different sha256 ($n_changed)"
  echo "  ADDED      local only, absent from reference  ($n_added)"
  echo "  REMOVED    reference only, missing locally    ($n_removed)"
  for label in ADDED REMOVED CHANGED UNCHANGED; do
    # No `${label,,}`: that is a bash 4+ expansion and macOS ships bash 3.2.
    case "$label" in
      ADDED) list="$added_list";;
      REMOVED) list="$removed_list";;
      CHANGED) list="$changed_list";;
      UNCHANGED) list="$unchanged_list";;
    esac
    [[ -z "$list" ]] && continue
    echo ""
    echo "$label:"
    while IFS= read -r line; do
      [[ -n "$line" ]] && echo "  $line"
    done <<< "$list"
  done
  echo ""

  if [[ $((n_changed + n_added + n_removed)) -eq 0 ]]; then
    echo "Verification: PASS — local and reference are identical"
    exit 0
  fi
  echo "Verification: FAIL — $n_changed changed, $n_added added, $n_removed removed"
  exit 1
fi

if [[ "$JSON" == true ]]; then
  echo "Error: --json is only meaningful with --diff"
  exit 2
fi

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
  echo "       $0 --diff <checksums.txt> [--json]   # classify per-artifact differences (exit 0/1/2/3)"
fi
