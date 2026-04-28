# Supported Pipeline Stages

All cipher stages available for brute-force pipelines. Stages are chained with `>` (e.g., `vigenere>b64>rijndael-256-ecb`).

---

## Substitution Ciphers

### Caesar

| Property | Value |
|----------|-------|
| Stage name | `caesar` |
| Reference | Standard classical cipher |
| Parameters | Shift value × charset mode |
| Search space | 251 total |

**Charset modes (3):**

| Mode | Alphabet | Shifts |
|------|----------|--------|
| 0 — Alpha only | A-Z/a-z (mod 26) | 26 |
| 1 — Alphanumeric | A-Z/a-z/0-9 (letters mod 26, digits mod 10) | 130 |
| 2 — All printable | ASCII 32-126 (mod 95) | 95 |

Non-matching characters pass through unchanged.

---

### Affine

| Property | Value |
|----------|-------|
| Stage name | `affine` |
| Reference | Standard classical cipher |
| Parameters | Multiplier (a) × shift (b) × charset mode |
| Search space | Sum of valid (a, b) combos per mode |

**Charset modes (3):**

| Mode | Modulus | Valid 'a' count | Combinations |
|------|---------|-----------------|--------------|
| 0 — Alpha | 26 | 12 | 12 × 26 = 312 |
| 1 — Alphanumeric | 62 | coprime(62) | varies |
| 2 — All printable | 95 | coprime(95) | varies |

Only multipliers coprime with the modulus are valid.

---

### Vigenere

| Property | Value |
|----------|-------|
| Stage names | `vigenere`, `vigenere52` |
| Reference | **CrypTool-online** |
| Formula | P = (C − K) mod N |
| Parameters | Key × mode (normal/autokey) |
| Search space | keys × 2 |

**Alphabet modes:**
- `vigenere` — 26-char, case-insensitive A-Z with case preservation
- `vigenere52` — 52-char, case-sensitive (A-Z then a-z, Z+1 wraps to a)

**Key-stream modes (2):**
- **Normal** — Key repeats cyclically
- **Autokey** — Recovered plaintext extends the initial key

Non-alpha characters pass through unchanged and do not advance the key position.

---

### Beaufort

| Property | Value |
|----------|-------|
| Stage names | `beaufort`, `beaufort52` |
| Reference | **CrypTool-online** |
| Formula | P = (K − C) mod N |
| Parameters | Key × mode (normal/autokey) |
| Search space | keys × 2 |

Self-reciprocal in normal mode (encrypt = decrypt). Autokey mode breaks self-reciprocity.

Same alphabet and key-stream modes as Vigenere.

---

### Porta

| Property | Value |
|----------|-------|
| Stage names | `porta`, `porta52` |
| Reference | **CrypTool-online** |
| Formula | Paired half-alphabet substitution with key-driven rotation |
| Parameters | Key × mode (normal/autokey) |
| Search space | keys × 2 |

Self-reciprocal in normal mode. Key values are reduced by `// 2` (pair indices). Autokey extends key with raw plaintext values (reduced when applied).

Same alphabet and key-stream modes as Vigenere.

---

### Trithemius

| Property | Value |
|----------|-------|
| Stage names | `trithemius`, `trithemius52` |
| Reference | **CrypTool-online** |
| Formula | P = (C − position) mod N |
| Parameters | None (keyless) |
| Search space | 0 (no axis) |

Shift equals character position (0, 1, 2, ...). No key required.

---

### XOR

| Property | Value |
|----------|-------|
| Stage name | `xor` |
| Reference | Standard repeating-key XOR |
| Parameters | Key |
| Search space | keys |

Operates on raw bytes. Accepts both text and binary payloads.

---

## Transposition Ciphers

### Columnar Transposition

| Property | Value |
|----------|-------|
| Stage names | `columnar`, `double_columnar` |
| Reference | **Rumkin**, **CrypTool** |
| Parameters | Key × charset mode |
| Search space | keys × 2 (single), keys² × 2 (double) |

**Charset modes (2):**

| Mode | Behavior |
|------|----------|
| 0 — Letters only | Only transpose A-Z/a-z; spaces/digits/punctuation stay in place |
| 1 — All | Transpose every character including spaces and punctuation |

`double_columnar` applies two rounds with independent keys.

---

### Rail Fence (Zigzag)

| Property | Value |
|----------|-------|
| Stage name | `railfence` |
| Reference | **Rumkin**, **CrypTool** |
| Parameters | Rails (2-30) × charset mode |
| Search space | 29 × 2 = 58 |

**Charset modes (2):**

| Mode | Behavior |
|------|----------|
| 0 — Letters only | Only transpose A-Z/a-z |
| 1 — All | Transpose all characters |

---

### Redefense (Keyed Rail Fence)

| Property | Value |
|----------|-------|
| Stage name | `redefense` |
| Reference | **Rumkin** |
| Parameters | Key × charset mode |
| Search space | keys × 2 |

Like rail fence but with keyword-determined rail reading order. Number of rails = key length.

---

### Myszkowski Transposition

| Property | Value |
|----------|-------|
| Stage name | `myszkowski` |
| Reference | Standard classical cipher |
| Parameters | Key |
| Search space | keys |

Like columnar but duplicate key letters share the same rank; columns with the same rank are read together across rows.

---

### Scytale

| Property | Value |
|----------|-------|
| Stage name | `scytale` |
| Reference | Standard classical cipher (ancient Greek) |
| Parameters | Number of columns (2-100) |
| Search space | 99 |

Grid-based transposition simulating wrapping around a cylinder.

---

## Fractionating Ciphers

### Bifid

| Property | Value |
|----------|-------|
| Stage name | `bifid` |
| Reference | Standard classical cipher |
| Parameters | Key |
| Search space | keys |

Uses a 5×5 Polybius square (25-char alphabet, J→I). Period = message length (full-period bifid). Non-alpha characters preserved at original positions.

---

## Encoding Stages (Keyless)

| Stage | What it does | Parameters |
|-------|-------------|------------|
| `b64` | Base64 decode | None |
| `hex` | Hex decode | None |
| `reverse` | Reverse character order | None |

These stages have no search space and don't contribute a parameter axis.

---

## Mcrypt Block & Stream Ciphers

### Algorithms

**Block ciphers (16):**
`blowfish`, `blowfish-compat`, `cast-128`, `cast-256`, `des`, `gost`, `loki97`, `rc2`, `rijndael-128`, `rijndael-192`, `rijndael-256`, `saferplus`, `serpent`, `tripledes`, `twofish`, `xtea`

**Stream ciphers (3):**
`arcfour`, `wake`, `enigma`

### Block Modes (6)

`ecb`, `cbc`, `cfb`, `ofb`, `nofb`, `ctr`

Stage names are `{algorithm}-{mode}` (e.g., `rijndael-256-ecb`, `blowfish-cbc`). Stream ciphers use just the algorithm name.

### Reference

**libmcrypt** — Note: mcrypt's CFB mode is non-standard "8-bit CFB" (encrypts one byte at a time, not block-size chunks).

### IV Strategies (5)

| # | Name | Description |
|---|------|-------------|
| 0 | `IV_NULL` | All 0x00 bytes |
| 1 | `IV_ZERO_STRING` | ASCII "0" (0x30) repeated to fill block size |
| 2 | `IV_KEY_NULL_PAD` | Key bytes padded with 0x00 to IV size |
| 3 | `IV_KEY_ZERO_STRING_PAD` | Key bytes padded with ASCII "0" to IV size |
| 4 | `IV_PREPENDED` | First N bytes of ciphertext are the IV |

ECB mode does not use an IV (multiplier = 1).

### Key Padding Strategies (2)

| # | Name | Description |
|---|------|-------------|
| 0 | `KEY_PAD_NULL` | Null-padded (libmcrypt default for short keys) |
| 1 | `KEY_PAD_ZERO_STRING` | ASCII "0" (0x30) padded to nearest valid key size |

Keys longer than max_key_size are truncated first.

### Key Derivation Modes (4)

| # | Name | Description |
|---|------|-------------|
| 0 | Raw | UTF-8 encoding of the dictionary word |
| 1 | MD5 | MD5 hash of the word |
| 2 | SHA1 | SHA1 hash of the word |
| 3 | SHA256 | SHA256 hash of the word |

### Mcrypt Search Space

Per mcrypt stage: `keys × 4 (derivation) × 2 (key padding) × iv_multiplier`

Where `iv_multiplier` = 5 for modes needing IV, 1 for ECB.

---

## Search Space Summary

| Stage | Axis Size |
|-------|-----------|
| `caesar` | 251 |
| `affine` | ~sum of mode combos |
| `vigenere`, `beaufort`, `porta` (+52) | keys × 2 |
| `trithemius` (+52) | 0 (keyless) |
| `bifid`, `myszkowski`, `xor` | keys |
| `columnar` | keys × 2 |
| `double_columnar` | keys² × 2 |
| `railfence` | 58 |
| `redefense` | keys × 2 |
| `scytale` | 99 |
| `mcrypt (ECB)` | keys × 8 |
| `mcrypt (non-ECB)` | keys × 40 |
| `b64`, `hex`, `reverse` | 0 |

When `--vary-case` is enabled, each key dimension is multiplied by 3 (lower/upper/title variants).

---

## Pipeline Syntax

```
stage1>stage2>stage3
```

Stages execute left-to-right. Each stage transforms the payload for the next. The total search space is the product of all axis sizes.

**Example:** `vigenere>b64>rijndael-256-ecb` with 10,000 keys:
- vigenere: 10,000 × 2 = 20,000
- b64: 0 (no axis)
- rijndael-256-ecb: 10,000 × 4 × 2 × 5 = 400,000
- Total combinations: 20,000 × 400,000 = 8,000,000,000
