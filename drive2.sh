#!/usr/bin/env bash
# Two-classical-stage chains before b64, then every symmetric stage.
# ATTEMPTS.md listed "3+ classical stages before mcrypt" as never attempted.
set -uo pipefail
cd "$(dirname "$0")"
CT="$(cat "${1:-../thegiant.txt}")"
DICT="${2:-dicts/druon.txt}"
THRESH="${3:-1.45}"

# Classical stages that preserve the base64 alphabet (transpositions permute;
# these substitutions map a b64 subset onto itself).
C1=(beaufort vigenere porta caesar atbash keyword skip amsco columnar railfence scytale myszkowski playfair trifid bifid redefense trithemius reverse)
SYM=$(python3 -c "
import core.pipeline as p
print(' '.join(sorted(x for x in p.VALID_STAGES
  if x.startswith('std-')
  or any(m in x for m in ['-ecb','-cbc','-cfb','-ofb','-ctr','-nofb'])
  or x in ('arcfour','wake','enigma'))))")

run() {
  local pipe="$1" out
  out=$(timeout 2700 python3 run_pipeline.py --pipeline "$pipe" --ciphertext "$CT" \
        --dictionary "$DICT" --vary-case --threshold "$THRESH" --max_hits 3 --workers 4 2>&1)
  if echo "$out" | grep -qE "^1\.[4-9]|^2\."; then
    echo "!!!!!!!!!! CANDIDATE: $pipe"
    echo "$out" | grep -A1 -E "^1\.[4-9]|^2\." | head -10
  fi
  echo "$out" | grep -q "already searched" && echo "  skip $pipe" || echo "  ok   $pipe"
}

echo "### two-stage classical sweep: $DICT threshold $THRESH"
for a in "${C1[@]}"; do
  for b in "${C1[@]}"; do
    [ "$a" = "$b" ] && continue
    run "${a}>${b}>b64"                    # classical pair only
  done
  echo "-- pair prefix done: $a"
done

echo "### single classical > b64 > every symmetric stage (incl. std-*)"
for a in "${C1[@]}"; do
  for m in $SYM; do run "${a}>b64>${m}"; done
  echo "-- done $a"
done
echo "DRIVE2_COMPLETE"
