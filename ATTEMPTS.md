# Brute-Force Attempt Log

Tracking all pipeline/dictionary/ciphertext combinations tested against the default ciphertext.

**Default ciphertext:**
```
kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvIqkZiI0KIAXAzP1U1uy1BE4UfPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xle8FOhAGJZ7g4in0wndJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1
```

## Dictionary: test_dict.txt (4 words × 4 case variants = 16 keys, + --vary-case)

Words: `Zombie`, `Zombies`, `Trythis`, `TheGiant` (with lowercase, uppercase, mixed-case, and --vary-case flag)

### Results

| # | Pipeline | Mcrypt Stages | Combos/Stage | Total Runs | Hits | Duration | Date |
|---|----------|--------------|--------------|------------|------|----------|------|
| 1 | `b64>{mcrypt}` | 99 | ~2,304 | 99 | 0 | ~1 min | 2026-04-16 |
| 2 | `columnar>b64>{mcrypt}` | 99 | ~36,864 | 99 | 0 | ~36 min | 2026-04-16 |
| 3 | `double_columnar>b64>{mcrypt}` | 99 | ~36,864 | 99 | 0 | ~36 min | 2026-04-16 |
| 4 | `affine>b64>{mcrypt}` | 99 | ~59,904 | 99 | 0 | ~7 min* | 2026-04-16 |
| 5 | `myszkowski>b64>{mcrypt}` | 99 | ~36,864 | 99 | 0 | ~7 min* | 2026-04-16 |
| 6 | `railfence>b64>{mcrypt}` | 99 | ~36,864 | 99 | 0 | ~7 min* | 2026-04-16 |
| 7 | `redefense>b64>{mcrypt}` | 99 | ~36,864 | 99 | 0 | ~7 min* | 2026-04-16 |
| 8 | `caesar>b64>{mcrypt}` (alpha only) | 99 | ~36,864 | 99 | 0 | ~7 min* | 2026-04-16 |
| 9 | `b64>xor>{mcrypt}` | 99 | ~36,864 | 99 | 0 | ~7 min* | 2026-04-16 |
| 10 | `caesar>b64>{mcrypt}` (3 charsets) | 99 | ~14,976 | 99 | 0 | ~1.7 min | 2026-04-16 |
| 11 | `affine>b64>{mcrypt}` (3 charsets) | 20† | ~1,730,304 | 20 | 0 | ~7.5 min | 2026-04-16 |

\* Runs 4–9 were batched together in ~7 minutes total (594 runs).

† Affine limited to: AES (128/192/256 ECB+CBC), DES ECB+CBC, 3DES ECB+CBC, Blowfish ECB+CBC, Twofish ECB+CBC, Arcfour, CAST-128 ECB+CBC, Serpent ECB+CBC, XTEA ECB.

### Summary

- **Total pipeline runs:** 1,010
- **Total hits:** 0
- **Threshold:** 1.5
- **Workers:** 4

---

## Notes

- All 99 mcrypt stages include 16 block ciphers × 6 modes + 3 stream ciphers
- Key derivation: 8 modes (raw, pad_zero_16, truncate_16, repeat_16, md5, sha1, sha256, all_zeros)
- Key padding: 2 strategies (as-is, zero-pad to max_key_size)
- IV always = key (zero-padded/truncated to iv_size)
- PKCS7 unpadding and null-byte stripping applied after decrypt

## Possible Next Steps

- [ ] Try with full `dictionary.txt` (~thousands of words)
- [ ] Try different pipeline structures (3+ classical stages before mcrypt)
- [ ] Try without b64 (raw mcrypt on the ciphertext bytes)
- [ ] Try a known ciphertext with known answer to validate end-to-end
- [ ] Try different ciphertexts
