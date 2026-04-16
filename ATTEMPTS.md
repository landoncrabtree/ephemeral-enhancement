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

### Results

| # | Pipeline | Mcrypt Stages | Total Combos | Hits | Duration | Version |
|---|----------|--------------|--------------|------|----------|---------|
| 1 | `b64>{mcrypt}` | All 99 | ~1,200 | 0 | 17s | v1 |
| 2 | `columnar>b64>{mcrypt}` | All 99 | ~30,000 | 0 | 46s | v1 |
| 3 | `double_columnar>b64>{mcrypt}` | All 99 | ~120,000 | 0 | 3.1min | v1 |
| 4 | `affine>b64>{mcrypt}` | All | TODO | TODO | TODO | v1 |
| 5 | `myszkowski>b64>{mcrypt}` | All | TODO | TODO | TODO | v1 |
| 6 | `railfence>b64>{mcrypt}` | All | TODO | TODO | TODO | v1 |
| 7 | `redefense>b64>{mcrypt}` | All | TODO | TODO | TODO | v1 |
| 8 | `caesar>b64>{mcrypt}` (alpha only) | All | TODO | TODO | TODO | v1 |
| 9 | `b64>xor>{mcrypt}` | All | TODO | TODO | TODO | v1 |


---

## Notes

- All 99 mcrypt stages include 16 block ciphers × 6 modes + 3 stream ciphers

## Possible Next Steps

- [ ] Try with full `dictionary.txt` (~thousands of words)
- [ ] Try different pipeline structures (3+ classical stages before mcrypt)
- [ X ] Try a known ciphertext with known answer to validate end-to-end