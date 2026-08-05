# BO3 Ciphers - Multi-Stage Cipher Brute-Forcing Pipeline

A high-performance, multi-stage cipher brute-forcing tool designed to decrypt complex layered ciphers from Call of Duty: Black Ops III Zombies easter eggs.

## Overview

This project provides a comprehensive framework for decrypting classical ciphers that have been chained together in multiple stages. It's specifically designed for the complex cipher puzzles found in BO3 Zombies, but can be used for any classical cryptography challenges.

### Key Features

- **Multi-stage pipelines**: Chain multiple cipher algorithms together (e.g., `caesar>b64>rijndael-128-cbc`)
- **High performance**: Multiprocessing support for parallel brute-forcing
- **Smart filtering**: English text scoring using frequency analysis and word matching
- **Progress tracking**: Real-time progress updates and performance metrics
- **Modular design**: Easy to add new cipher stages
- **Well-tested**: Comprehensive test suite (130+ tests)

### Supported Ciphers

**Classical (text-based):**
- **Affine**: Brute-forces all valid (a,b) pairs across 3 charset modes (alpha/alphanumeric/all-printable) — 9,012 combos
- **Caesar**: Shift cipher across 3 charset modes (alpha/alphanumeric/all-printable) — 78 combos
- **Bifid**: Polybius square cipher with keyed alphabet (standard 5×5 or base64 8×8)
- **Columnar Transposition**: Column-based permutation cipher
- **Double Columnar**: Two-stage columnar transposition
- **Myszkowski Transposition**: Columnar variant where duplicate key letters share ranks
- **Railfence**: Zigzag pattern cipher (2-30 rails)
- **Redefense**: Keyed rail fence with keyword-ordered rail reading
- **XOR**: Repeating-key XOR cipher
- **Base64**: Standard base64 decoding
- **Reverse**: Simple text reversal

**Symmetric (bytes input, use after b64):**

All **libmcrypt** algorithms via native C bindings — **Rijndael (AES-128/192/256)**, **DES**, **3DES**, **Blowfish**, **Twofish**, **Serpent**, **CAST-128/256**, **RC2**, **GOST**, **Loki97**, **Saferplus**, **XTEA**, **RC4 (Arcfour)**, **WAKE**, **Enigma**, and more. All block cipher modes supported: ECB, CBC, CFB, OFB, nOFB, CTR. Uses PHP `mcrypt_decrypt()` compatible semantics (zero-padding, key handling). Use pipelines like `b64>rijndael-128-ecb` or `b64>des-cbc`.

## Project Structure

```
bo3_ciphers/
├── README.md                 # This file
├── ATTEMPTS.md              # Brute-force attempt log
├── run_pipeline.py          # Main entry point
├── dicts/                   # Key dictionaries
│   ├── full_dictionary.txt  # Full dictionary of keys to try (default)
│   └── druon.txt            # Curated BO3 / Druon ARG key list
├── pytest.ini              # Pytest configuration
│
├── core/                   # Core pipeline logic (modular architecture)
│   ├── __init__.py        # Package exports
│   ├── args.py            # Argument parsing and configuration
│   ├── pipeline.py        # Pipeline parsing and validation
│   ├── executor.py        # Stage execution logic
│   ├── worker.py          # Worker state and chunk processing
│   ├── parallel.py        # Multiprocessing orchestration
│   └── utils.py           # Utility functions
│
├── stages/                 # Cipher implementations
│   ├── __init__.py
│   ├── common.py          # Shared utilities (scoring, printable ratio)
│   ├── key_derivation.py  # Key derivation (raw, pad, md5, sha1, sha256, all_zeros)
│   ├── mcrypt_wrapper.py  # Python ctypes bindings for libmcrypt
│   ├── mcrypt_registry.py # Algorithm/mode registry (99 stages)
│   ├── mcrypt_stage.py    # Unified mcrypt decrypt stage
│   ├── affine.py          # Affine cipher (3 charset modes)
│   ├── bifid.py           # Bifid cipher
│   ├── caesar.py          # Caesar cipher (3 charset modes)
│   ├── columnar.py        # Columnar transposition
│   ├── double_columnar.py # Double columnar transposition
│   ├── myszkowski.py      # Myszkowski transposition
│   ├── railfence.py       # Railfence cipher
│   ├── redefense.py       # Redefense (keyed rail fence)
│   ├── reverse.py         # Text reversal
│   └── xor.py             # XOR cipher
│
├── tests/                  # Per-stage test files
│   ├── test_affine_myszkowski_redefense.py
│   ├── test_base64.py
│   ├── test_bifid.py
│   ├── test_caesar.py
│   ├── test_columnar.py
│   ├── test_key_derivation.py
│   ├── test_mcrypt.py
│   ├── test_railfence.py
│   ├── test_reverse.py
│   ├── test_scoring.py
│   └── test_xor.py
│
├── scripts/                # Build scripts
│   └── build_mcrypt.sh   # Build libmcrypt from source
│
└── docs/                   # Documentation
    ├── CONTEXT.md         # Project background and sources
    ├── CIPHERS/           # Cipher solutions by map
    │   ├── DE.MD          # Der Eisendrache
    │   ├── GK.md          # Gorod Krovi
    │   ├── REVELATIONS.md # Revelations
    │   ├── SOE.MD         # Shadows of Evil
    │   ├── THEGIANT.md    # The Giant
    │   └── ZNS.md         # Zetsubou No Shima
    └── CONTRIBUTING/
        └── ADDING_A_STAGE.md
```

## Installation

### Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- C compiler (gcc/clang) for building libmcrypt

### Building libmcrypt (required for symmetric ciphers)

```bash
./scripts/build_mcrypt.sh
```

This downloads libmcrypt 2.5.8, compiles it, and installs to `lib/mcrypt/`. Only needs to be run once. Requires `curl`, `tar`, `make`, and a C compiler.

### Setup with uv (Recommended)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
cd bo3_ciphers
uv run run_pipeline --pipeline "caesar" --ciphertext "KHOOR ZRUOG"
```

### Setup with pip

```bash
cd bo3_ciphers
pip install -e .
python3 run_pipeline.py --pipeline "caesar" --ciphertext "KHOOR ZRUOG"
```

## Usage

### Basic Usage

```bash
python run_pipeline.py \
    --pipeline "caesar>b64>rijndael-128-cbc" \
    --ciphertext "YOUR_CIPHERTEXT_HERE" \
    --dictionary dicts/full_dictionary.txt \
    --vary-case \
    --threshold 1.7 \
    --workers 4
```

### Command-Line Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--pipeline` | str | *required* | Cipher stages separated by `>` (e.g., `caesar>b64>rijndael-128-cbc`) |
| `--ciphertext` | str | *(TG-1)* | The ciphertext to decrypt |
| `--dictionary` | str | `dicts/full_dictionary.txt` | Path to dictionary file for keys |
| `--key_limit` | int | `0` | Limit dictionary to first N keys (0 = all, WARNING: huge search space) |
| `--threshold` | float | `0.80` | Minimum score to report results (recommend 1.5-1.7 for English) |
| `--max_hits` | int | `50` | Maximum number of results to display (0 = unlimited) |
| `--workers` | int | `1` | Number of parallel worker processes |
| `--chunk_size` | int | `10000` | Parameter combinations per worker task |
| `--progress_every` | int | `50` | Show progress every N completed tasks |
| `--bifid_alphabet` | str | `standard` | Bifid alphabet: `standard` (5×5) or `base64` (8×8) |
| `--vary-case` | flag | `false` | Try lowercase, uppercase, and title case per word (3× key space) |
| `--dry-run` | flag | `false` | Show parameter space size without running |

### Examples

#### Example 1: Single Stage (Caesar)

```bash
python run_pipeline.py \
    --pipeline "caesar" \
    --ciphertext "URYYB JBEYQ" \
    --key_limit 1 \
    --threshold 0.9
```

#### Example 2: mcrypt Pipeline

```bash
python run_pipeline.py \
    --pipeline "b64>rijndael-128-cbc" \
    --dictionary dicts/full_dictionary.txt \
    --vary-case \
    --threshold 1.5 \
    --workers 4
```

#### Example 3: Multi-Stage Pipeline

```bash
python run_pipeline.py \
    --pipeline "caesar>b64>des-ecb" \
    --dictionary dicts/druon.txt \
    --vary-case \
    --threshold 1.5 \
    --workers 8
```

#### Example 4: Dry Run (Estimate Search Space)

```bash
python run_pipeline.py \
    --pipeline "affine>b64>rijndael-128-cbc" \
    --dictionary dicts/druon.txt \
    --vary-case \
    --dry-run
```

### Understanding Output

When a potential decryption is found:

```
1.910 meta={'rijndael-128-cbc_key': 'THEGIANTTHEGIANT', 'rijndael-128-cbc_deriv': 0, 'rijndael-128-cbc_key_pad': 'as-is'}
```

- **Score** (1.910): Combines printable ratio + English quality (max ~2.0)
- **meta**: Shows which keys/parameters were used at each stage

## Development

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_mcrypt.py -v

# Run specific test class
python -m pytest tests/test_caesar.py::TestCaesarCipher -v
```

### Score Interpretation

| Score | Meaning |
|-------|---------|
| < 1.0 | Contains non-printable bytes |
| = 1.0 | Fully printable but no English characteristics |
| > 1.0 | Printable + English-like (frequency analysis + word matching) |
| → 2.0 | Perfect English with common words |

### Contributing

Want to add a new cipher stage? See **[docs/CONTRIBUTING/ADDING_A_STAGE.md](docs/CONTRIBUTING/ADDING_A_STAGE.md)**.

## Performance Tips

1. **Estimate first**: `--dry-run` shows parameter space size
2. **Limit dictionary**: `--key_limit 100` to start small
3. **Use workers**: `--workers 4` (or your core count)
4. **Adjust threshold**: `--threshold 1.7` for strong English filtering
5. **Vary case**: `--vary-case` triples key space but catches case-sensitive keys

## Cipher Documentation

Detailed solutions for each BO3 Zombies map:

- **[Shadows of Evil](docs/CIPHERS/SOE.MD)** (5 ciphers — all solved)
- **[The Giant](docs/CIPHERS/THEGIANT.md)** (5 ciphers — 1 unsolved)
- **[Der Eisendrache](docs/CIPHERS/DE.MD)** (12 ciphers — all solved)
- **[Zetsubou No Shima](docs/CIPHERS/ZNS.md)** (14 ciphers — all solved)
- **[Gorod Krovi](docs/CIPHERS/GK.md)** (14 ciphers — all solved)
- **[Revelations](docs/CIPHERS/REVELATIONS.md)** (14 ciphers — 10 unsolved)

## Credits

### Sources

- [Reddit: Treyarch Ciphers Wiki](https://www.reddit.com/r/CODZombies/wiki/treyarch-ciphers/)
- [BlackOpsCiphers by waterkh](https://waterkh.github.io/BlackOpsCiphers/)
- [Community Cipher Spreadsheet](https://docs.google.com/spreadsheets/u/1/d/e/2PACX-1vQvv8MxIGK-4KJb9e6QU3mWnI0knNsv8AMj75bdyCv3oMgtyXXZyY-3-6GBI1THZDQVIbllIKYGhJFV/pubhtml)

## License

This project is provided as-is for educational and research purposes related to Call of Duty: Black Ops III Zombies easter eggs.
