# mcrypt Integration

This project uses [libmcrypt](http://mcrypt.sourceforge.net/) — the same C library behind PHP's deprecated [`mcrypt`](https://www.php.net/manual/en/book.mcrypt.php) extension — to decrypt Black Ops 3 ciphers. Several Revelations ciphers were encoded using PHP's `mcrypt_encrypt()` with non-standard "8-bit CFB" mode, making them impossible to decrypt with standard crypto libraries.

## Building libmcrypt

We compile libmcrypt 2.5.8 from source into a local shared library (`lib/mcrypt/`). No system-wide installation is needed.

```bash
./scripts/build_mcrypt.sh
```

This script:
1. Downloads `libmcrypt-2.5.8.tar.gz` from SourceForge
2. Verifies the SHA-256 checksum
3. Patches `config.sub`/`config.guess` for modern systems (ARM64 macOS, etc.)
4. Compiles with `-Wno-implicit-function-declaration` and related flags for modern compilers
5. Installs headers and shared library to `lib/mcrypt/`

The built library lives at:
- macOS: `lib/mcrypt/lib/libmcrypt.dylib`
- Linux: `lib/mcrypt/lib/libmcrypt.so`

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Pipeline (core/pipeline.py)                            │
│  Computes parameter space:                              │
│  keys × derivations × key_pads × iv_strategies          │
└──────────────┬──────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────┐
│  Executor (core/executor.py)                            │
│  _execute_mcrypt():                                     │
│    1. Decompose param_idx → key, derivation, pad, iv    │
│    2. Derive key (raw / md5 / sha1 / sha256)            │
│    3. Apply key padding strategy                        │
│    4. Generate IV from strategy                         │
│    5. Call mcrypt_decrypt()                              │
└──────────────┬──────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────┐
│  Registry (stages/mcrypt_registry.py)                   │
│  Enumerates all algo+mode combos from libmcrypt.        │
│  Provides McryptStageInfo (key sizes, block size, IV).  │
│  16 block algos × 6 modes + 3 stream = 99 stages.      │
└──────────────┬──────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────┐
│  Wrapper (stages/mcrypt_wrapper.py)                     │
│  Python ctypes bindings to libmcrypt.                   │
│  McryptHandle: open once, decrypt many (init/deinit).   │
│  McryptHandleCache: per-worker handle pool.             │
│  Matches PHP mcrypt_decrypt() semantics exactly.        │
└──────────────┬──────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────┐
│  libmcrypt 2.5.8 (lib/mcrypt/lib/libmcrypt.dylib|.so)  │
│  C library, loaded via ctypes.CDLL.                     │
└─────────────────────────────────────────────────────────┘
```

### ctypes Wrapper Details

The wrapper (`stages/mcrypt_wrapper.py`) binds these libmcrypt functions via ctypes:

| Function | Purpose |
|---|---|
| `mcrypt_module_open` | Open an algorithm+mode handle |
| `mcrypt_module_close` | Close the handle |
| `mcrypt_generic_init` | Initialize with key + IV |
| `mcrypt_generic_deinit` | Deinitialize (reset state) |
| `mdecrypt_generic` | Decrypt data in-place |
| `mcrypt_enc_get_block_size` | Query block size |
| `mcrypt_enc_get_key_size` | Query max key size |
| `mcrypt_enc_get_iv_size` | Query IV size |
| `mcrypt_enc_is_block_algorithm` | Block vs stream check |
| `mcrypt_enc_mode_has_iv` | Whether mode needs IV |
| `mcrypt_enc_get_supported_key_sizes` | Fixed key sizes (or variable) |
| `mcrypt_list_algorithms` | Enumerate all compiled algorithms |
| `mcrypt_list_modes` | Enumerate all compiled modes |

**Performance optimization**: `McryptHandleCache` keeps algorithm+mode handles open across decrypt calls. Only `mcrypt_generic_init`/`deinit` is called per attempt — the expensive `module_open`/`close` happens once per worker.

## Key Derivation

Each dictionary word is transformed into key bytes using one of 4 derivation modes (`stages/key_derivation.py`):

| Mode | Name | Output | Size |
|---|---|---|---|
| 0 | `raw` | UTF-8 encode | variable |
| 1 | `md5` | MD5 hash digest | 16 bytes |
| 2 | `sha1` | SHA-1 hash digest | 20 bytes |
| 3 | `sha256` | SHA-256 hash digest | 32 bytes |

After derivation, the key is **truncated** if longer than the algorithm's `max_key_size`.

### Key Padding Strategies

After truncation, one of 2 padding strategies is applied:

| Strategy | Name | Behavior |
|---|---|---|
| 0 | `as-is` | Pass key directly to libmcrypt. libmcrypt internally zero-pads short keys with `\x00` to the nearest valid key size. |
| 1 | `ascii-0-pad` | Pad key with ASCII `"0"` (0x30) to `max_key_size`. |

**Example**: key `"Zombies"` (7 bytes) with `rijndael-128` (valid key sizes: 16, 24, 32):

| Strategy | Result | Effective Cipher |
|---|---|---|
| as-is | `5a6f6d62696573` (7 bytes) → libmcrypt pads with `\x00` to nearest valid size → 16 bytes | AES-128 |
| ascii-0-pad | `5a6f6d62696573303030...30` padded with `"0"` to max_key_size → 32 bytes | AES-256 |

**Important**: libmcrypt pads short keys to the **nearest valid key size**, not to `max_key_size`. For `rijndael-128`, a 7-byte key becomes 16 bytes (AES-128), while our ascii-0-pad strategy fills to 32 bytes (AES-256). These produce completely different ciphertext — both are worth trying.

### Total Key Variants per Dictionary Word

```
4 derivations × 2 key pads = 8 key variants
```

## IV Derivation

Modes that require an IV (CBC, CFB, OFB, nOFB, CTR) try 4 IV strategies. ECB and stream modes do not use an IV.

| Strategy | Name | IV Value |
|---|---|---|
| 0 | `null` | `\x00` repeated to `iv_size` |
| 1 | `ascii-0` | `"0"` (0x30) repeated to `iv_size` |
| 2 | `key+null` | Derived key bytes truncated to `iv_size`, padded with `\x00` if short |
| 3 | `key+ascii0` | Derived key bytes truncated to `iv_size`, padded with `"0"` (0x30) if short |

**Note**: The key-derived IV strategies (2, 3) use the **final derived key** (after derivation + padding), not the raw dictionary word.

**Example**: key `"Zombies"` (as-is, 7 bytes) with `iv_size=8`:

| Strategy | IV (hex) |
|---|---|
| null | `0000000000000000` |
| ascii-0 | `3030303030303030` |
| key+null | `5a6f6d6269657300` |
| key+ascii0 | `5a6f6d6269657330` |

### Total Combinations per Dictionary Word

```
ECB / stream modes:  4 derivations × 2 key_pads × 1 iv = 8 combinations
IV modes (CFB, etc): 4 derivations × 2 key_pads × 4 iv = 32 combinations
```

## Supported Algorithms

### Block Ciphers (16 algorithms × 6 modes = 96 stages)

Each block cipher is registered with all 6 modes: ECB, CBC, CFB, OFB, nOFB, CTR.

| Algorithm | Max Key Size | Block Size | Key Sizes | Notes |
|---|---|---|---|---|
| `blowfish` | 56 bytes | 8 | variable (1–56) | |
| `blowfish-compat` | 56 bytes | 8 | variable (1–56) | Big-endian compat variant |
| `cast-128` | 16 bytes | 8 | fixed: 16 | CAST5 |
| `cast-256` | 32 bytes | 16 | fixed: 16, 24, 32 | CAST6 |
| `des` | 8 bytes | 8 | fixed: 8 | |
| `gost` | 32 bytes | 8 | fixed: 32 | Soviet standard |
| `loki97` | 32 bytes | 16 | fixed: 16, 24, 32 | |
| `rc2` | 128 bytes | 8 | variable (1–128) | |
| `rijndael-128` | 32 bytes | 16 | fixed: 16, 24, 32 | AES |
| `rijndael-192` | 32 bytes | 24 | fixed: 16, 24, 32 | Non-standard AES variant |
| `rijndael-256` | 32 bytes | 32 | fixed: 16, 24, 32 | Non-standard AES variant |
| `saferplus` | 32 bytes | 16 | fixed: 16, 24, 32 | SAFER+ |
| `serpent` | 32 bytes | 16 | fixed: 16, 24, 32 | AES finalist |
| `tripledes` | 24 bytes | 8 | fixed: 24 | 3DES / DESede |
| `twofish` | 32 bytes | 16 | fixed: 16, 24, 32 | AES finalist |
| `xtea` | 16 bytes | 8 | fixed: 16 | Extended TEA |

### Stream Ciphers (3 stages)

Stream ciphers use `"stream"` mode only and do not require an IV.

| Algorithm | Max Key Size | Notes |
|---|---|---|
| `arcfour` | 256 bytes | RC4 |
| `wake` | 32 bytes | WAKE stream cipher |
| `enigma` | 13 bytes | Crypt / Enigma compat |

### Block Cipher Modes

| Mode | Needs IV | Description |
|---|---|---|
| `ecb` | No | Electronic Codebook — each block encrypted independently |
| `cbc` | Yes | Cipher Block Chaining — each block XORed with previous ciphertext |
| `cfb` | Yes | Cipher Feedback — mcrypt uses non-standard **8-bit CFB** (encrypts 1 byte at a time) |
| `ofb` | Yes | Output Feedback — generates keystream from IV |
| `nofb` | Yes | nOFB — standard OFB (full-block feedback) |
| `ctr` | Yes | Counter mode |

> **Important**: mcrypt's CFB mode is **8-bit CFB**, not standard CFB. It encrypts one byte at a time instead of using the full block size. This is a critical difference — standard crypto libraries cannot replicate mcrypt's CFB output, which is why these ciphers remained unsolved for nearly a decade.

## Relevance to Black Ops 3

Several Revelations ciphers (Rev-2, 5, 6, 8, 9, 10, 12) were encoded using PHP `mcrypt_encrypt()`:

- **Key**: `"Zombies"` (capital Z) for all
- **Mode**: CFB (8-bit CFB)
- **IV**: ASCII `"0"` (0x30) repeated to block size
- **Key padding**: libmcrypt auto-pads `"Zombies"` (7 bytes) with `\x00` to the algorithm's minimum key size
- **Algorithms vary per cipher**: RC2, Blowfish, Loki97, DES, Serpent, Twofish, Arcfour, Saferplus, Rijndael-256, XTEA, etc.

The non-standard 8-bit CFB mode made these impossible to decrypt with standard libraries (PyCryptodome, OpenSSL, etc.), which is why linking directly to libmcrypt via ctypes was necessary.
