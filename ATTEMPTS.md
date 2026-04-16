# Brute-Force Attempt Log

Tracking all pipeline/dictionary/ciphertext combinations tested against the default ciphertext.

**Default ciphertext:**
```
kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvIqkZiI0KIAXAzP1U1uy1BE4UfPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xle8FOhAGJZ7g4in0wndJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1
```

## Dictionary: test_dict.txt (4 words × 3 case variants = 12 keys, --vary-case)

Words: `Zombie`, `Zombies`, `TheGiant`, `TryThis` (with --vary-case: lowercase, uppercase, title)

### Version History

- **v1** (attempts 1–11): 8 key derivation modes, 2 key pad strategies, 1 IV strategy (key-derived). Threshold 1.5.
- **v2** (attempts 1r–3r): 4 key derivation modes (raw, md5, sha1, sha256), 2 key pad strategies (as-is, ascii-0 to nearest valid size), 4 IV strategies (null, ascii-0, key+null, key+ascii0). ASCII-0 key padding now rounds to nearest valid key size instead of max. Threshold 1.0.

### Results

| # | Pipeline | Mcrypt Stages | Combos/Stage (ECB/IV) | Total Combos | Hits | Duration | Version |
|---|----------|--------------|----------------------|--------------|------|----------|---------|
| 1 | `b64>{mcrypt}` | 99 | 96 / 384 | ~32,544 | 0 | ~17s | v1 |
| 2 | `columnar>b64>{mcrypt}` | 99 | 1,152 / 4,608 | ~390,528 | 0 | ~46s | v1 |
| 3 | `double_columnar>b64>{mcrypt}` | 99 | 13,824 / 55,296 | ~4,686,336 | 0 | ~3m | v1 |
| 4 | `affine>b64>{mcrypt}` | 99 | — | — | 0 | ~7 min* | v1 |
| 5 | `myszkowski>b64>{mcrypt}` | 99 | — | — | 0 | ~7 min* | v1 |
| 6 | `railfence>b64>{mcrypt}` | 99 | — | — | 0 | ~7 min* | v1 |
| 7 | `redefense>b64>{mcrypt}` | 99 | — | — | 0 | ~7 min* | v1 |
| 8 | `caesar>b64>{mcrypt}` (alpha only) | 99 | — | — | 0 | ~7 min* | v1 |
| 9 | `b64>xor>{mcrypt}` | 99 | — | — | 0 | ~7 min* | v1 |
| 10 | `caesar>b64>{mcrypt}` (3 charsets) | 99 | — | — | 0 | ~1.7 min | v1 |
| 11 | `affine>b64>{mcrypt}` (3 charsets) | 20† | — | ~1,730,304 | 0 | ~7.5 min | v1 |
| 1r | `b64>{mcrypt}` | 99 | 96 / 384 | ~32,544 | 0 | 17s | **v2** |
| 2r | `columnar>b64>{mcrypt}` | 99 | 1,152 / 4,608 | ~390,528 | 0 | 46s | **v2** |
| 3r | `double_columnar>b64>{mcrypt}` | 99 | 13,824 / 55,296 | ~4,686,336 | 0 | 3.1 min | **v2** |

\* Runs 4–9 were batched together in ~7 minutes total (594 runs).

† Affine limited to 20 stages: AES (128/192/256 ECB+CBC), DES ECB+CBC, 3DES ECB+CBC, Blowfish ECB+CBC, Twofish ECB+CBC, Arcfour, CAST-128 ECB+CBC, Serpent ECB+CBC, XTEA ECB.

### Summary

- **Total pipeline runs (v1+v2):** 1,307
- **Total hits:** 0
- **v2 key derivation:** raw, md5, sha1, sha256 (4 modes)
- **v2 key padding:** as-is (libmcrypt \x00 to nearest valid), ascii-0 to nearest valid (2 strategies)
- **v2 IV strategies:** \x00 × iv_size, "0" × iv_size, key+\x00 pad, key+"0" pad (4 strategies)
- **Combos per key per mcrypt stage:** ECB=8, IV modes=32

---

## Notes

- All 99 mcrypt stages include 16 block ciphers × 6 modes + 3 stream ciphers
- v1 used 8 key derivation modes and 1 IV strategy (key-derived only)
- v2 simplified to 4 derivations but expanded IV coverage (4 strategies)
- v2 ascii-0 key padding now pads to nearest valid key size (not max), fixing AES-128 vs AES-256 bug
- PKCS7 unpadding and null-byte stripping applied after decrypt

## Possible Next Steps

- [ ] Re-run attempts 4–11 with v2
- [ ] Try with full `dictionary.txt` (~thousands of words)
- [ ] Try different pipeline structures (3+ classical stages before mcrypt)
- [ ] Try without b64 (raw mcrypt on the ciphertext bytes)
- [ ] Try a known ciphertext with known answer to validate end-to-end
- [ ] Try different ciphertexts from other unsolved Revelations ciphers
