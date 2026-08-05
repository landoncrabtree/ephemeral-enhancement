#!/usr/bin/env bash
# Full re-sweep after the --vary-case fix. Every prior run's fingerprint
# changed (axis sizes grew), so nothing is skipped incorrectly.
set -uo pipefail
cd "$(dirname "$0")"
CT="$(cat "${1:-../thegiant.txt}")"
DICT="${2:-dicts/druon.txt}"
TH="${3:-1.45}"

SYM=$(python3 -c "
import core.pipeline as p
print(' '.join(sorted(x for x in p.VALID_STAGES
  if x.startswith('std-') or any(m in x for m in ['-ecb','-cbc','-cfb','-ofb','-ctr','-nofb'])
  or x in ('arcfour','wake','enigma'))))")
CLASSICAL=(beaufort vigenere porta caesar affine atbash keyword skip amsco columnar
           double_columnar railfence redefense scytale myszkowski playfair trifid
           bifid trithemius reverse)

run() {
  local pipe="$1" out
  out=$(timeout 2700 python3 run_pipeline.py --pipeline "$pipe" --ciphertext "$CT" \
        --dictionary "$DICT" --vary-case --threshold "$TH" --max_hits 3 --workers 5 2>&1)
  if echo "$out" | grep -qE "^1\.[4-9]|^2\."; then
    echo "!!!!!!!!!! CANDIDATE: $pipe"
    echo "$out" | grep -A1 -E "^1\.[4-9]|^2\." | head -10
  fi
}

echo "### PHASE 1: direct b64 > every symmetric stage"
for m in $SYM; do run "b64>$m"; done
echo "### PHASE 2: classical > b64"
for c in "${CLASSICAL[@]}"; do run "${c}>b64"; done
echo "### PHASE 3: classical > b64 > symmetric"
for c in "${CLASSICAL[@]}"; do
  for m in $SYM; do run "${c}>b64>${m}"; done
  echo "-- done $c"
done
echo RERUN_COMPLETE
