
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