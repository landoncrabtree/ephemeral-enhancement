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
| 1r | `b64>{mcrypt}` | 99 | 96 / 384 | ~32,544 | 0 | 17s | **v2** |
| 2r | `columnar>b64>{mcrypt}` | 99 | 1,152 / 4,608 | ~390,528 | 0 | 46s | **v2** |
| 3r | `double_columnar>b64>{mcrypt}` | 99 | 13,824 / 55,296 | ~4,686,336 | 0 | 3.1 min | **v2** |
| 5r | `myszkowski>b64>{mcrypt}` | 99 | 1,152 / 4,608 | ~390,528 | 0 | 54s | **v2** |
| 6r | `railfence>b64>{mcrypt}` | 99 | 2,784 / 11,136 | ~945,312 | 0 | 1.4 min | **v2** |
| 7r | `redefense>b64>{mcrypt}` | 99 | 1,152 / 4,608 | ~390,528 | 0 | 48s | **v2** |
| 8r | `caesar>b64>{mcrypt}` (3 charsets) | 99 | 7,488 / 29,952 | ~2,541,408 | **18** | 1.6 min | **v2** |
| 9r | `b64>xor>{mcrypt}` | 99 | 1,152 / 4,608 | ~390,528 | 0 | 48s | **v2** |

\* Runs 4–9 were batched together in ~7 minutes total (594 runs).

† Affine limited to 20 stages: AES (128/192/256 ECB+CBC), DES ECB+CBC, 3DES ECB+CBC, Blowfish ECB+CBC, Twofish ECB+CBC, Arcfour, CAST-128 ECB+CBC, Serpent ECB+CBC, XTEA ECB.

### Pipeline 8r Hits (caesar>b64>{mcrypt}, threshold ≥ 1.0)

All 18 hits share **caesar shift=7, all_printable charset, sha256 key derivation**. Scores are low (1.0–1.7) — likely noise rather than valid decryptions.

| Score | Algorithm | Key | Key Pad | IV | Notes |
|-------|-----------|-----|---------|-----|-------|
| 1.686 | enigma | TRYTHIS | as-is / ascii-0 | none | Stream cipher, 2 hits |
| 1.675 | des-cbc | TRYTHIS | as-is / ascii-0 | key+null / key+ascii0 | 4 hits (sha256 key truncated to 8) |
| 1.666 | rc2-cbc | Trythis | as-is / ascii-0 | null | 2 hits |
| 1.666 | rc2-ecb | Trythis | as-is / ascii-0 | none | 2 hits |
| 1.506 | xtea-ctr | Trythis | as-is / ascii-0 | null | 2 hits |
| 1.506 | xtea-nofb | Trythis | as-is / ascii-0 | null | 2 hits |
| 1.000 | xtea-ctr | zombies | as-is / ascii-0 | ascii-0 | 2 hits |
| 1.000 | xtea-nofb | zombies | as-is / ascii-0 | ascii-0 | 2 hits |

### Summary

- **Total pipeline runs (v1+v2):** 1,802
- **Total hits:** 18 (all from pipeline 8r, likely noise at threshold 1.0)
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

- [ ] Re-run attempt 4 (affine) with v2
- [ ] Re-run attempts 10–11 with v2
- [ ] Try with full `dictionary.txt` (~thousands of words)
- [ ] Try different pipeline structures (3+ classical stages before mcrypt)
- [ ] Try without b64 (raw mcrypt on the ciphertext bytes)
- [ ] Try a known ciphertext with known answer to validate end-to-end
- [ ] Try different ciphertexts from other unsolved Revelations ciphers
