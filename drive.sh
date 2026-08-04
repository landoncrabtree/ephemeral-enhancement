#!/usr/bin/env bash
# Re-run every pipeline family from ATTEMPTS.md against the current ciphertext.
#
# All ATTEMPTS.md rows are stale: they used the pre-correction ciphertext and
# smaller axis sizes (beaufort>b64 was 24 combos, it is now 120). The tracker
# keys runs by a fingerprint of the whole search space, so anything genuinely
# already covered is skipped automatically and everything else re-runs.
#
# Usage: ./drive.sh <ciphertext-file> <dictionary> <threshold>
set -uo pipefail
cd /Users/landoncrabtree/Downloads/bo3_ciphers

CT_FILE="${1:-../thegiant.txt}"
DICT="${2:-dicts/giant.txt}"
THRESH="${3:-1.4}"
CT="$(cat "$CT_FILE")"

MCRYPT=$(python3 -c "
import core.pipeline as p
print(' '.join(sorted(x for x in p.VALID_STAGES
    if any(m in x for m in ['-ecb','-cbc','-cfb','-ofb','-ctr','-nofb'])
    or x in ('arcfour','wake','enigma'))))")

# Classical prefixes. The bare polyalpha names now sweep every alphabet and
# both normal/autokey key streams, so vigenere52/autokey/etc are covered.
PREFIXES=(
  ""                 # direct b64>mcrypt
  "caesar>"
  "affine>"
  "vigenere>"
  "beaufort>"
  "porta>"
  "trithemius>"
  "columnar>"
  "double_columnar>"
  "myszkowski>"
  "railfence>"
  "redefense>"
  "scytale>"
  "reverse>"
)

run() {
  local pipe="$1"
  local out rc
  out=$(timeout 3600 python3 run_pipeline.py \
        --pipeline "$pipe" --ciphertext "$CT" --dictionary "$DICT" \
        --vary-case --threshold "$THRESH" --max_hits 3 2>&1)
  rc=$?
  if echo "$out" | grep -q "already searched"; then
    echo "  skip  $pipe"
  elif [ $rc -ne 0 ]; then
    echo "  FAIL($rc) $pipe"
  else
    local hits
    hits=$(echo "$out" | grep -oE "hits=[0-9]+" | tail -1)
    echo "  ok    $pipe  $hits"
    if echo "$out" | grep -qE "^1\.[4-9]|^2\."; then
      echo "!!!!!!!!!! CANDIDATE !!!!!!!!!!"
      echo "$out" | grep -A1 -E "^1\.[4-9]|^2\." | head -20
    fi
  fi
}

echo "### ciphertext: $CT_FILE  dict: $DICT  threshold: $THRESH"

# Phase 1: classical-only (no mcrypt) — fast, catches a pure classical layer.
echo "== phase 1: classical > b64 =="
for pre in "${PREFIXES[@]}"; do
  [ -z "$pre" ] && continue
  run "${pre}b64"
done

# Phase 2: classical > b64 > every mcrypt stage.
echo "== phase 2: classical > b64 > mcrypt =="
for pre in "${PREFIXES[@]}"; do
  echo "-- prefix: ${pre:-<none>}"
  for m in $MCRYPT; do
    run "${pre}b64>${m}"
  done
done

echo "### DRIVE COMPLETE"
