# BO3 Ciphers - Multi-Stage Cipher Brute-Forcing Pipeline

A high-performance, multi-stage cipher brute-forcing tool designed to decrypt complex layered ciphers from Call of Duty: Black Ops III Zombies easter eggs.

## Overview

This project provides a comprehensive framework for decrypting classical ciphers that have been chained together in multiple stages. It's specifically designed for the complex cipher puzzles found in BO3 Zombies, but can be used for any classical cryptography challenges.

### Key Features

- 🔗 **Multi-stage pipelines**: Chain multiple cipher algorithms together (e.g., `caesar>bifid>b64>xor`)
- ⚡ **High performance**: Multiprocessing support for parallel brute-forcing
- 🎯 **Smart filtering**: English text scoring using frequency analysis and word matching
- 📊 **Progress tracking**: Real-time progress updates and performance metrics
- 🧩 **Modular design**: Easy to add new cipher stages
- 🧪 **Well-tested**: Comprehensive test suite with 67+ tests

### Supported Ciphers

- **Caesar**: Simple shift cipher (26 possible shifts)
- **Bifid**: Polybius square cipher with keyed alphabet (standard 5×5 or base64 8×8)
- **Columnar Transposition**: Column-based permutation cipher
- **Double Columnar**: Two-stage columnar transposition
- **Railfence**: Zigzag pattern cipher (2-30 rails)
- **XOR**: Repeating-key XOR cipher
- **Base64**: Standard base64 decoding
- **Reverse**: Simple text reversal

## Project Structure

```
bo3_ciphers/
├── README.md                 # This file
├── run_pipeline.py          # Main entry point
├── dictionary.txt           # Dictionary of keys to try
├── common.txt               # Common English words for scoring
├── pytest.ini              # Pytest configuration
├── test_stages.py          # Unit tests for all cipher stages
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
├── stages/                 # Cipher implementations (pure functions)
│   ├── __init__.py
│   ├── common.py          # Shared utilities (scoring, printable ratio)
│   ├── bifid.py           # Bifid cipher
│   ├── caesar.py          # Caesar cipher
│   ├── columnar.py        # Columnar transposition
│   ├── double_columnar.py # Double columnar transposition
│   ├── railfence.py       # Railfence cipher
│   ├── reverse.py         # Text reversal
│   └── xor.py             # XOR cipher
│
└── docs/                   # Documentation
    ├── CONTEXT.md         # Project background and sources
    ├── ADDING_A_STAGE.md  # Guide for adding new cipher stages
    ├── DE.MD              # Der Eisendrache ciphers
    ├── GK.md              # Gorod Krovi ciphers
    ├── REVELATIONS.md     # Revelations ciphers
    ├── SOE.MD             # Shadows of Evil ciphers
    ├── THEGIANT.md        # The Giant ciphers
    └── ZNS.md             # Zetsubou No Shima ciphers
```

## Installation

### Requirements

- Python 3.10+
- pytest (for running tests)

### Setup

```bash
# Clone or download the repository
cd bo3_ciphers

# Install pytest (optional, for testing)
pip install pytest

# Verify installation
python run_pipeline.py --pipeline "caesar" --dry_run
```

## Usage

### Basic Usage

```bash
python run_pipeline.py \
    --pipeline "caesar>bifid>b64>xor" \
    --ciphertext "YOUR_CIPHERTEXT_HERE" \
    --key_limit 100 \
    --threshold 0.8
```

### Command-Line Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--pipeline` | str | *required* | Cipher stages separated by `>` (e.g., `caesar>bifid>b64>xor`) |
| `--ciphertext` | str | *(sample)* | The ciphertext to decrypt |
| `--dictionary` | str | `dictionary.txt` | Path to dictionary file for keys |
| `--key_limit` | int | `0` | Limit number of keys to try (0 = all, WARNING: can be huge) |
| `--threshold` | float | `0.80` | Minimum printable ratio (0.0-1.0) to consider a hit |
| `--max_hits` | int | `50` | Maximum number of results to return |
| `--workers` | int | `1` | Number of parallel worker processes |
| `--chunk_size` | int | `10000` | Parameter tuples per worker task |
| `--progress_every` | int | `50` | Show progress every N completed tasks |
| `--bifid_alphabet` | str | `standard` | Bifid alphabet: `standard` (5×5) or `base64` (8×8) |
| `--dry_run` | flag | `false` | Show parameters without running |

### Examples

#### Example 1: Single Stage (Caesar)

```bash
python run_pipeline.py \
    --pipeline "caesar" \
    --ciphertext "URYYB JBEYQ" \
    --key_limit 1 \
    --threshold 0.9
```

Output:
```
[pipeline] caesar
[keys] 1
[axes] caesar=26
[estimate] param_tuples=26
1.000 meta={'caesar_shift': 13}
[done] attempts=26 hits=1 time=0.00s
```

#### Example 2: Multi-Stage Pipeline

```bash
python run_pipeline.py \
    --pipeline "bifid>b64>xor" \
    --ciphertext "YOUR_COMPLEX_CIPHERTEXT" \
    --key_limit 100 \
    --threshold 0.85 \
    --workers 4
```

#### Example 3: Dry Run (Test Parameters)

```bash
python run_pipeline.py \
    --pipeline "caesar>bifid>columnar>b64>xor" \
    --key_limit 50 \
    --dry_run
```

Output:
```
[pipeline] caesar>bifid>columnar>b64>xor
[keys] 50
[axes] caesar=26 bifid=50 columnar=50 xor=50
[estimate] param_tuples=3,250,000
```

### Understanding Output

When a potential decryption is found, the output shows:

```
0.950 meta={'caesar_shift': 7, 'bifid_key': 'ZOMBIE', 'xor_key': 'SECRET'}
```

- `0.950`: Printable ratio (95% of output bytes are printable ASCII)
- `meta`: Dictionary showing which keys/parameters were used at each stage

Use these parameters to manually decrypt the ciphertext or verify the result.

## Testing

### Run All Tests

```bash
pytest test_stages.py -v
```

### Run Tests for Specific Cipher

```bash
# Test Caesar cipher
pytest test_stages.py::TestCaesar -v

# Test Bifid cipher
pytest test_stages.py::TestBifid -v

# Test XOR cipher
pytest test_stages.py::TestXOR -v
```

### Test Coverage

```bash
pytest test_stages.py --cov=stages --cov-report=html
```

## Performance Tips

### 1. Limit Your Dictionary

The dictionary contains 9,000+ words. Start small:

```bash
--key_limit 100  # Try only first 100 keys
```

### 2. Optimize Workers and Chunk Size

#### Finding the Ideal Worker Count

The optimal number of workers depends on your CPU:

```bash
# Check your CPU core count
python -c "import multiprocessing; print(f'CPU cores: {multiprocessing.cpu_count()}')"
```

**Guidelines:**
- **Start with:** `--workers <number_of_cores>`
- **For CPU-bound tasks:** Use `cores - 1` (leave one for system)
- **For small search spaces:** Use fewer workers (overhead isn't worth it)
- **For large search spaces:** Use all cores

**Examples:**
```bash
# 4-core system
--workers 4

# 8-core system with hyperthreading (16 logical cores)
--workers 8  # Use physical cores, not logical

# 16+ core system
--workers 12  # Diminishing returns after ~12 workers for most pipelines
```

#### Finding the Ideal Chunk Size

Chunk size controls how many parameter combinations each worker processes before reporting back:

**Trade-offs:**
- **Small chunks** (1,000-5,000): More frequent progress updates, higher overhead
- **Large chunks** (50,000-100,000): Less overhead, infrequent progress updates

**Guidelines:**
```bash
# Small search space (< 100,000 combinations)
--chunk_size 1000

# Medium search space (100,000 - 1,000,000)
--chunk_size 10000  # Default

# Large search space (> 1,000,000)
--chunk_size 50000

# Huge search space (> 10,000,000)
--chunk_size 100000
```

**Formula:** Aim for `total_combinations / (workers * 100)` chunks

**Example optimization:**
```bash
# Check search space first
python run_pipeline.py --pipeline "caesar>bifid>xor" --key_limit 100 --dry_run
# Output: param_tuples=260,000

# Optimize for 8-core system
python run_pipeline.py \
    --pipeline "caesar>bifid>xor" \
    --key_limit 100 \
    --workers 8 \
    --chunk_size 5000 \
    --progress_every 10
# This creates 52 chunks (260,000 / 5,000)
# Each worker gets ~6-7 chunks
# Progress updates every 10 chunks
```

### 3. Adjust Threshold

The threshold controls the minimum score required to report a result. With the new English scoring system:

```bash
--threshold 1.0   # Accept any printable ASCII (may have many false positives)
--threshold 1.5   # Require some English characteristics
--threshold 1.7   # Require good English (recommended for most cases)
--threshold 1.85  # Require very good English (fewer false positives)
```

**Tip:** Start with `1.7` for XOR/Base64 pipelines to filter out gibberish.

### 4. Estimate First

Always do a dry run to see the search space size:

```bash
--dry_run  # Shows parameter space without running
```

### 5. Monitor Performance

Watch the rate metric to tune your settings:

```
[progress] tasks=50/520 attempts=500,000 hits=3 rate=125,000/s
```

- **Low rate** (< 50,000/s): Try larger chunk size or fewer workers
- **High rate** (> 200,000/s): Well optimized!
- **Inconsistent rate**: Adjust chunk size for more consistent performance

## Adding New Cipher Stages

Want to add a new cipher? See the comprehensive guide:

📖 **[docs/ADDING_A_STAGE.md](docs/ADDING_A_STAGE.md)**

The guide includes:
- Step-by-step instructions
- Complete code examples
- Integration checklist
- Testing guidelines

## Architecture

### Overview

The project uses a **modular, direct execution architecture** optimized for parallel processing:

```
┌─────────────────────────────────────────────────────────────┐
│                     run_pipeline.py                         │
│                    (Entry Point)                            │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
    ┌────▼─────┐                  ┌─────▼──────┐
    │ core/    │                  │  stages/   │
    │ modules  │◄─────────────────┤  ciphers   │
    └──────────┘                  └────────────┘
```

**Core Modules** (`core/`):
- `args.py` - Argument parsing and configuration
- `pipeline.py` - Pipeline parsing and validation
- `executor.py` - Direct stage execution (sequential transformation)
- `worker.py` - Worker state and chunk processing
- `parallel.py` - Multiprocessing orchestration
- `utils.py` - Utility functions (dictionary loading, etc.)

**Stage Modules** (`stages/`):
- Pure functions implementing cipher algorithms
- No generators or iterators - direct execution only
- Simple API: `decrypt(payload, key) -> result`

### Pipeline Processing

The pipeline processes ciphertext through multiple stages using **direct execution**:

```
Ciphertext → Stage 1 → Stage 2 → Stage 3 → ... → Plaintext
              (text)    (text)    (bytes)         (bytes)
```

**Direct Execution Model:**
1. Each parameter combination is tested independently
2. Payload flows through stages sequentially
4. Optimized for parallel processing

**Example:**
```python
# For combination: caesar_shift=3, bifid_key="ZOMBIE", xor_key="KEY"
payload = ciphertext
payload = caesar_shift_text(payload, 3)
payload = bifid_decrypt(payload, "ZOMBIE", period=len(payload))
payload = base64.b64decode(payload)
payload = repeating_xor(payload, b"KEY")
score = combined_score(payload)
if score >= threshold:
    report_result(score, metadata)
```

### Scoring System

The pipeline uses a **combined scoring system** to identify valid English plaintext:

#### Score Range: 0.0 to 2.0

```
< 1.0  = Contains non-printable bytes (ratio of printable characters)
= 1.0  = Fully printable ASCII but no English characteristics
> 1.0  = Fully printable + English-like text
→ 2.0  = Perfect English (common words + proper frequency)
```

#### Scoring Components

**1. Printable Ratio (0.0 to 1.0)**
- Checks if bytes are printable ASCII (32-126, plus tab/newline/CR)
- Returns ratio of printable characters

**2. English Score (0.0 to 1.0)**
- **Chi-squared frequency analysis** (70% weight): Compares letter frequency distribution to English
- **Common word matching** (30% weight): Checks against ~600 most common English words from `common.txt`
- **Space ratio bonus** (up to 0.2): Rewards proper word spacing (15-20% spaces)

**3. Combined Score**
```python
if printable_ratio < 1.0:
    return printable_ratio  # Partially printable
else:
    return 1.0 + english_score  # Fully printable + English quality
```

#### Example Scores

```bash
# Non-printable bytes
b"\x00\x01\xff\xfe"              → 0.000

# Printable gibberish
b"WOAGGI;YNP(O^\\J"              → 1.575

# Good English
b"THE QUICK BROWN FOX"           → 1.857

# Perfect English (common words)
b"THE MAN WAS HERE"              → 2.000
```

#### Threshold Usage

```bash
# Accept any printable ASCII
--threshold 1.0

# Require some English characteristics
--threshold 1.5

# Require good English
--threshold 1.7

# Require very good English (fewer false positives)
--threshold 1.85
```

### Brute-Force Strategy

The engine uses a **mixed-radix enumeration** to efficiently explore the parameter space:

```python
# For pipeline: caesar>bifid>xor with 100 keys
# Parameter space: 26 × 100 × 100 = 260,000 combinations

for caesar_shift in range(26):
    for bifid_key in keys:
        for xor_key in keys:
            # Try this combination
            score = combined_score(result)
            if score >= threshold:
                print(f"{score:.3f} meta={...}")
```

**Result Sorting:**
- All results above threshold are collected
- Sorted by score (highest first)
- Top N results displayed (controlled by `--max_hits`)

### Multiprocessing Architecture

The `core/parallel.py` module orchestrates work distribution:

**Task Creation:**
```python
# Divide parameter space into chunks
total_combinations = 260,000
chunk_size = 10,000
chunks = [(0, 10000), (10000, 20000), ..., (250000, 260000)]
```

**Worker Processing:**
```
Main Process (core/parallel.py)
    │
    ├─> Worker 1 (core/worker.py): combinations 0-10,000
    │   └─> StageExecutor (core/executor.py): execute pipeline
    │       └─> Cipher functions (stages/*.py): decrypt
    │
    ├─> Worker 2: combinations 10,001-20,000
    ├─> Worker 3: combinations 20,001-30,000
    └─> Worker 4: combinations 30,001-40,000
    
After all workers complete:
    → Collect all hits
    → Sort by score (descending)
    → Display top N results
```

## Cipher Documentation

Detailed documentation for solved ciphers from each BO3 Zombies map:

- **[docs/DE.MD](docs/DE.MD)** - Der Eisendrache (12 ciphers)
- **[docs/GK.md](docs/GK.md)** - Gorod Krovi
- **[docs/REVELATIONS.md](docs/REVELATIONS.md)** - Revelations
- **[docs/SOE.MD](docs/SOE.MD)** - Shadows of Evil
- **[docs/THEGIANT.md](docs/THEGIANT.md)** - The Giant
- **[docs/ZNS.md](docs/ZNS.md)** - Zetsubou No Shima

Each document includes:
- Cipher type
- Keys used
- Plaintext solutions
- Solver credits

## Limitations

- **Classical cryptography only**: No modern encryption (AES, RSA, etc.)
- **ASCII-focused**: Designed for English text
- **Brute-force approach**: Not optimized for cryptanalysis
- **Dictionary-dependent**: Key-based ciphers require good dictionary

## Credits

### Sources

- [Reddit: Treyarch Ciphers Wiki](https://www.reddit.com/r/CODZombies/wiki/treyarch-ciphers/)
- [BlackOpsCiphers by waterkh](https://waterkh.github.io/BlackOpsCiphers/)
- [Community Cipher Spreadsheet](https://docs.google.com/spreadsheets/u/1/d/e/2PACX-1vQvv8MxIGK-4KJb9e6QU3mWnI0knNsv8AMj75bdyCv3oMgtyXXZyY-3-6GBI1THZDQVIbllIKYGhJFV/pubhtml)

### Tools Referenced

- [PracticalCryptography](http://practicalcryptography.com/)
- [Rumkin Cipher Tools](https://rumkin.com/)
- [CrypTool Online](http://cryptool-online.org/)
- [Cryptii V2](https://v2.cryptii.com/)

## License

This project is provided as-is for educational and research purposes related to Call of Duty: Black Ops III Zombies easter eggs.

## FAQ

### Q: How do I know which pipeline to use?

**A:** Start with single stages, then combine based on the cipher characteristics. Check the `docs/` folder for examples from solved BO3 ciphers.

### Q: Why is my search taking forever?

**A:** Use `--dry_run` to check the parameter space size. Use `--key_limit` to reduce it. Enable `--workers` for parallelization.

### Q: What does the score mean?

**A:** The score combines printable ratio and English text quality:
- **< 1.0**: Contains non-printable bytes (shows ratio of printable characters)
- **= 1.0**: Fully printable ASCII but no English characteristics
- **> 1.0**: Fully printable + English-like (uses frequency analysis and word matching)
- **→ 2.0**: Perfect English with common words

Higher scores indicate better English text. Use `--threshold 1.7` or higher to filter out gibberish.

### Q: Can I add my own dictionary?

**A:** Yes! Use `--dictionary path/to/your/dict.txt`. One word per line.

### Q: How do I decrypt with known parameters?

**A:** The individual cipher functions are available in `stages/*.py`. Import and use them directly in Python.

---

**Happy cipher breaking! 🔐🧩**

