#!/usr/bin/env bash
# The Giant's cipher texture is rendered upside down in-game, so the intended
# reading order may be reversed. Rotating a line of text 180 degrees reverses
# its character order, which is exactly what the `reverse` stage does — so
# prefix every pipeline family with it.
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
           bifid trithemius hypercube)

run() {
  local pipe="$1" out
  out=$(timeout 2700 python3 run_pipeline.py --pipeline "$pipe" --ciphertext "$CT" \
        --dictionary "$DICT" --vary-case --threshold "$TH" --max_hits 3 --workers 5 2>&1)
  if echo "$out" | grep -qE "^1\.[4-9]|^2\."; then
    echo "!!!!!!!!!! CANDIDATE: $pipe"
    echo "$out" | grep -A1 -E "^1\.[4-9]|^2\." | head -10
  fi
}

echo "### R1: reverse > b64 > symmetric"
for m in $SYM; do run "reverse>b64>$m"; done

echo "### R2: reverse > classical > b64"
for c in "${CLASSICAL[@]}"; do run "reverse>${c}>b64"; done

echo "### R3: reverse > classical > b64 > symmetric"
for c in "${CLASSICAL[@]}"; do
  for m in $SYM; do run "reverse>${c}>b64>${m}"; done
  echo "-- done reverse>$c"
done
echo REVSWEEP_COMPLETE
