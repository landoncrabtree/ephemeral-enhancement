# Copilot Instructions

## Project Overview

Multi-stage cipher brute-forcing pipeline for decrypting layered ciphers from Call of Duty: Black Ops III Zombies easter eggs. Chains classical ciphers (Vigenere, Caesar, Rail Fence, etc.) with symmetric block ciphers (AES, DES, Blowfish via libmcrypt) and tests all parameter combinations against an English-language scoring function.

## Commands

```bash
# Run all tests
python -m pytest

# Run a single test file
python -m pytest tests/test_polyalpha.py -v

# Run a specific test class or function
python -m pytest tests/test_polyalpha.py::TestVigenere26::test_known_vector

# Run the pipeline (brute-force)
python run_pipeline.py --pipeline "vigenere>b64>rijndael-256-ecb" --ciphertext "..." --dictionary dicts/full_dictionary.txt

# Dry run (show search space size without executing)
python run_pipeline.py --pipeline "caesar>b64" --ciphertext "..." --dry-run

# Build libmcrypt (required once for symmetric cipher stages)
./scripts/build_mcrypt.sh
```

No linter or formatter is configured.

## Architecture

### Pipeline Execution Flow

1. **`run_pipeline.py`** — Entry point, parses args
2. **`core/pipeline.py`** — Validates stage names, computes parameter axes (search space dimensions)
3. **`core/parallel.py`** — Splits search space into chunks, dispatches to worker processes via `multiprocessing.Pool`
4. **`core/worker.py`** — Each worker holds state (`WorkerState`) and processes chunks of parameter indices
5. **`core/executor.py`** — `StageExecutor` applies stages sequentially to a payload, converting a flat parameter index into per-stage parameters via mixed-radix unranking

### Parameter Space Model

The brute-force enumerates a Cartesian product of per-stage axes. Each stage contributes an axis with a size (e.g., Caesar = 251, Vigenere = keys × 2). A flat integer index is converted to per-axis indices using mixed-radix decomposition (`core/utils.py:mixed_radix_unrank`).

When a stage has multiple modes (charset modes, normal vs autokey, etc.), modes are encoded into the flat axis index. The convention is `mode * n_keys + key_idx` — mode is the high-order component, key is the low-order. This keeps mode 0 (normal) occupying indices `0..k-1`.

### Payload Types

The pipeline tracks payload as either `"text"` (str) or `"bytes"`. Stages declare what they accept:
- Text stages (Caesar, Vigenere, etc.) return `None` if `kind != "text"`
- Bytes stages (mcrypt, XOR) work on bytes
- Encoding stages (`b64`, `hex`) convert text→bytes

### Scoring

`stages/common.py:combined_score()` returns 0.0–2.0:
- < 1.0 = non-printable content
- 1.0 = printable but not English
- \> 1.0 = English-like (frequency analysis + common word matching)
- → 2.0 = strong English

`printable_ratio()` decodes UTF-8 when possible and counts characters, so
typographic punctuation (em/en dashes, curly quotes, ellipsis) and Latin-1
accented letters count as printable (`EXTENDED_PRINTABLE`). Non-Latin scripts
and undecodable bytes still fall below 1.0. Executor stages gate text
conversion on `decode("utf-8")`, not ASCII, so such plaintexts stay `"text"`
and remain usable by downstream text stages.

## Key Conventions

### Adding/Modifying Cipher Stages

Every cipher stage touches exactly 3 files (see `docs/CONTRIBUTING/ADDING_A_STAGE.md`):
1. **`stages/{cipher}.py`** — Pure decrypt function, no side effects
2. **`core/pipeline.py`** — Register in `_CLASSICAL_STAGES`, define axis size in `axes_for_pipeline()`
3. **`core/executor.py`** — Import, add to `_execute_stage()` dispatch, implement `_execute_{cipher}()` method

### Polyalphabetic Ciphers (Vigenere, Beaufort, Porta)

Each has two alphabet modes (26-char case-preserving, 52-char case-sensitive). The bare stage name (`vigenere`) sweeps **both** alphabets as part of its axis; the `26`/`52` suffixed names (`vigenere26`, `vigenere52`) pin one alphabet and halve the search space. Each also tries normal + autokey key-stream modes (2×) as part of the same axis. Constants `N_POLYALPHA_MODES`, `POLYALPHA_MODE_NAMES`, `N_POLYALPHA_ALPHABETS` and `POLYALPHA_ALPHABET_NAMES` are defined in `stages/polyalpha.py`.

The flat axis index packs three components, coarsest first: `(alphabet * N_POLYALPHA_MODES + mode) * n_keys + key_idx`. This keeps alphabet 0 (26-char) + mode 0 (normal) at indices `0..k-1`, so pinned variants encode identically to the pre-merge behaviour. `core/executor.py:_split_alphabet_suffix()` maps a stage name to `(base_name, pinned_alphabet_or_None)`.

Non-alpha characters always pass through unchanged and do not advance the key position — this preserves base64 structure for downstream `b64` stages.

### Transposition Ciphers (Columnar, Rail Fence, Redefense)

Have charset modes: `CHARSET_LETTERS_ONLY` (only letters move, punctuation stays in place) and `CHARSET_ALL` (everything moves). Named after Rumkin/CrypTool conventions.

### Mcrypt Integration

`stages/mcrypt_wrapper.py` provides ctypes bindings to libmcrypt (built to `lib/mcrypt/`). PHP `mcrypt_decrypt()` compatible semantics. Key facts:
- mcrypt's CFB mode is non-standard "8-bit CFB" (one byte at a time)
- BO3 Revelations ciphers use IV = ASCII "0" (0x30) repeated to fill block size, NOT null bytes
- Key padding strategies and IV strategies are iterated as part of the axis

### Executor Method Pattern

All `_execute_*` methods follow the same signature and return convention:
```python
def _execute_foo(self, payload, kind, param_idxs, axis_pos, meta) -> tuple[str|bytes, Kind, int] | None:
    if kind != "text":  # or "bytes"
        return None
    # ... decode params from param_idxs[axis_pos] ...
    meta["foo_key"] = key  # always record in metadata
    result = foo_decrypt(payload, key)
    return (result, kind, axis_pos + 1)  # +1 per axis consumed
```

Keyless stages (reverse, trithemius, b64) don't increment `axis_pos`.

### Testing

- One test file per cipher module in `tests/`
- Tests use known vectors from CrypTool-online where possible
- Roundtrip tests verify encrypt→decrypt for self-reciprocal ciphers (Beaufort, Porta in normal mode)
- Passthrough tests verify non-alpha characters are preserved at correct positions

### Dictionary and Keys

- `dicts/full_dictionary.txt` — Full key dictionary (one word per line), the `--dictionary` default
- `dicts/druon.txt` — curated BO3 / Druon ARG key list (source of truth)
- Relative `--dictionary` paths that don't exist in the cwd are resolved against the project root (`core/utils.py:resolve_data_path`)
- Non-alphabetic entries exist in dictionary files; ciphers with alpha-only keys handle empty effective keys by returning `None`
- `--vary-case` multiplies key space ×3 (lower/upper/title)
