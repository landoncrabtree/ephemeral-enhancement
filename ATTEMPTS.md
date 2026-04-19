# Brute-Force Attempt Log

Tracking all pipeline/dictionary/ciphertext combinations tested against the default ciphertext.

**Default ciphertext:**
```
kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvIqkZiI0KIAXAzP1U1uy1BE4UfPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xle8FOhAGJZ7g4in0wndJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1
```

## Dictionary: test_dict.txt (4 words × 3 case variants = 12 keys, --vary-case)

Words: `Zombie`, `Zombies`, `TheGiant`, `TryThis` (with --vary-case: lowercase, uppercase, title)

### Version History

- **v1**:
  - Mcrypt: 4 key derivation modes (raw, md5, sha1, sha256)
  - Mcrypt: 2 key pad strategies (null-padded, zero-string-padded)
  - Mcrypt: 4 IV strategies (null, zero-string, key-null-padded, key-zero-string-padded)
  - Output stripping: PKCS7, null bytes, trailing control chars (< 0x20)
  - Threshold: 0.7
- **v2**:
  - Updated columnar/double_columnar charset modes (Rumkin naming: letters_only, all)
  - Updated railfence/redefense with charset modes (letters_only, all) and offset support
  - Redefense now supports numeric order (CryptTool style)

### Results

| # | Pipeline | Mcrypt Stages | Total Combos | Hits | Duration | Version |
|---|----------|--------------|--------------|------|----------|---------|
| 1 | `b64>{mcrypt}` | All 99 | ~1,200 | 0 | 17s | v1 |
| 2 | `columnar>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 1.5min | v2 |
| 3 | `double_columnar>b64>{mcrypt}` | All 99 | ~120,000 | 0 | 6.7min | v2 |
| 4 | `affine>b64>{mcrypt}` | All | TODO | TODO | TODO | v1 |
| 5 | `myszkowski>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 52s | v1 |
| 6 | `railfence>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 1.8min | v2 |
| 7 | `redefense>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 1.6min | v2 |
| 8 | `caesar>b64>{mcrypt}` (alpha only) | All 99 | ~2.5M | 991* | 1.6min | v1 |
| 8b | `caesar>b64>{mcrypt}` (all 251 shifts) | All 99 | ~8.3M | 16793* | 3.0min | v1 |
| 9 | `b64>xor>{mcrypt}` | All 99 | ~300,000 | 0 | 46s | v1 |
| 10 | `autokey>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 54s | v1 |
| 11 | `autokey52>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 46s | v1 |
| 12 | `beaufort>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 54s | v1 |
| 13 | `beaufort52>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 46s | v1 |
| 14 | `porta>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 55s | v1 |
| 15 | `porta52>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 48s | v1 |
| 16 | `trithemius>b64>{mcrypt}` | All 99 | ~1,200 | 0 | 17s | v1 |
| 17 | `trithemius52>b64>{mcrypt}` | All 99 | ~1,200 | 0 | 17s | v1 |
| 18 | `vigenere>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 55s | v1 |
| 19 | `vigenere52>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 48s | v1 |
| 20 | `scytale>b64>{mcrypt}` | All 99 | ~120,000 | 0 | 1.7min | v1 |
| 21 | `columnar>b64` | — | 24 | 0 | 0.08s | v2 |
| 22 | `double_columnar>b64` | — | 288 | 0 | 0.10s | v2 |
| 23 | `railfence>b64` | — | 58 | 0 | 0.08s | v2 |
| 24 | `redefense>b64` | — | 24 | 0 | 0.08s | v2 |
| 25 | `scytale>b64` | — | 99 | 0 | 0.08s | v2 |
| 26 | `vigenere>b64` | — | 12 | 0 | 0.08s | v2 |
| 27 | `vigenere52>b64` | — | 12 | 0 | 0.08s | v2 |
| 28 | `beaufort>b64` | — | 12 | 0 | 0.08s | v2 |
| 29 | `beaufort52>b64` | — | 12 | 0 | 0.08s | v2 |
| 30 | `autokey>b64` | — | 12 | 0 | 0.09s | v2 |
| 31 | `autokey52>b64` | — | 12 | 0 | 0.08s | v2 |
| 32 | `porta>b64` | — | 12 | 0 | 0.08s | v2 |
| 33 | `porta52>b64` | — | 12 | 0 | 0.08s | v2 |
| 34 | `trithemius>b64` | — | 1 | 0 | 0.08s | v2 |
| 35 | `trithemius52>b64` | — | 1 | 0 | 0.08s | v2 |

#### dictionary.txt (9,292 words × 3 case variants = 27,879 keys, --vary-case)

| # | Pipeline | Mcrypt Stages | Total Combos | Hits | Duration | Version |
|---|----------|--------------|--------------|------|----------|---------|
| 21b | `columnar>b64` | — | 55,758 | 0 | 0.84s | v2 |
| 22b | `double_columnar>b64` | — | skipped (>777M combos) | — | — | — |
| 23b | `railfence>b64` | — | 58 | 0 | 0.14s | v2 |
| 24b | `redefense>b64` | — | 55,758 | 0 | 1.05s | v2 |
| 25b | `scytale>b64` | — | 99 | 0 | 0.14s | v2 |
| 26b | `vigenere>b64` | — | 27,879 | 0 | 0.68s | v2 |
| 27b | `vigenere52>b64` | — | 27,879 | 0 | 0.49s | v2 |
| 28b | `beaufort>b64` | — | 27,879 | 0 | 0.67s | v2 |
| 29b | `beaufort52>b64` | — | 27,879 | 0 | 0.50s | v2 |
| 30b | `autokey>b64` | — | 27,879 | 0 | 0.75s | v2 |
| 31b | `autokey52>b64` | — | 27,879 | 0 | 0.50s | v2 |
| 32b | `porta>b64` | — | 27,879 | 0 | 0.71s | v2 |
| 33b | `porta52>b64` | — | 27,879 | 0 | 0.51s | v2 |
| 34b | `trithemius>b64` | — | 1 | 0 | 0.12s | v2 |
| 35b | `trithemius52>b64` | — | 1 | 0 | 0.12s | v2 |

\* Pipeline 8 hits are false positives: caesar with `all_printable` charset corrupts b64 characters, `b64decode(validate=False)` silently strips them, producing ~5-8 byte garbage that scores above 0.7 by random chance.


---

## Notes

- All 99 mcrypt stages include 16 block ciphers × 6 modes + 3 stream ciphers

## Possible Next Steps

- [ ] Try with full `dictionary.txt` (~thousands of words)
- [ ] Try different pipeline structures (3+ classical stages before mcrypt)
- [ X ] Try a known ciphertext with known answer to validate end-to-end