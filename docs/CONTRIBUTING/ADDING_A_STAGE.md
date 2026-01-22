# Adding a New Cipher Stage

This guide explains how to add a new cipher stage to the pipeline.

---

## Overview

The pipeline uses a **direct execution model** where:
1. Each stage is a simple decrypt/encrypt function
2. The `core/executor.py` applies stages sequentially
3. The `core/parallel.py` tests different parameter combinations in parallel

**Key Concepts:**
- **Stage**: A cipher algorithm (e.g., Caesar, Bifid, XOR)
- **Pipeline**: A sequence of stages (e.g., `caesar>bifid>b64>xor`)
- **Direct Execution**: Each parameter combination is tested independently
- **Metadata**: Dictionary tracking which parameters were used

---

## Architecture

### File Structure

```
stages/
├── __init__.py          # Package initialization
├── common.py            # Shared utilities (scoring, printable ratio)
├── caesar.py            # Example: parameter-based stage (26 shifts)
├── bifid.py             # Example: key-based stage (dictionary keys)
├── xor.py               # Example: bytes-processing stage
└── your_stage.py        # Your new stage

core/
├── pipeline.py          # Pipeline parsing and validation
├── executor.py          # Stage execution logic
├── worker.py            # Worker state and processing
├── parallel.py          # Multiprocessing orchestration
└── args.py              # Argument parsing
```

### Core Components

Every stage module should contain:

1. **Core Algorithm Function(s)**: The actual cipher implementation
   - Simple, pure functions (no side effects)
   - Takes plaintext/ciphertext and parameters
   - Returns decrypted/encrypted result

2. **Type Handling**: Proper handling of text vs bytes
   - Text stages: `str` → `str`
   - Bytes stages: `bytes` → `bytes`
   - Mixed stages: Handle both with type checks

---

## Step-by-Step Guide

### Step 1: Create Your Stage Module

Create a new file in `stages/` named after your cipher (e.g., `stages/substitution.py`).

### Step 2: Implement the Core Algorithm

```python
# stages/substitution.py
from __future__ import annotations


def substitution_decrypt(text: str, key: str) -> str:
    """
    Decrypt text using a substitution cipher.
    
    Args:
        text: The encrypted text
        key: The decryption key
        
    Returns:
        The decrypted plaintext
    """
    # Your implementation here
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    sub_alphabet = create_substitution_from_key(key)
    
    # Build reverse mapping for decryption
    mapping = {sub_alphabet[i]: alphabet[i] for i in range(26)}
    
    # Decrypt
    result = []
    for c in text.upper():
        result.append(mapping.get(c, c))
    return "".join(result)


def create_substitution_from_key(key: str) -> str:
    """Create a substitution alphabet from a key."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    seen = set()
    result = []
    
    # Add unique key characters first
    for c in key.upper():
        if c in alphabet and c not in seen:
            result.append(c)
            seen.add(c)
    
    # Fill with remaining alphabet
    for c in alphabet:
        if c not in seen:
            result.append(c)
    
    return "".join(result)
```

**Guidelines:**
- Keep functions pure (no side effects)
- Handle edge cases (empty strings, invalid keys, etc.)
- Add comprehensive docstrings
- Return the same type as input (str→str, bytes→bytes)
- Preserve non-alphabet characters when appropriate

### Step 3: Add to Valid Stages

In `core/pipeline.py`, add your stage to the `VALID_STAGES` set:

```python
# core/pipeline.py

VALID_STAGES = {
    "caesar",
    "bifid",
    "columnar",
    "double_columnar",
    "b64",
    "xor",
    "railfence",
    "reverse",
    "substitution",  # Add your stage here
}
```

### Step 4: Define Parameter Space

In `core/pipeline.py`, update the `axes_for_pipeline()` function to define how many parameter combinations your stage has:

```python
def axes_for_pipeline(stages: list[str], n_keys: int) -> list[StageAxis]:
    axes: list[StageAxis] = []
    for st in stages:
        if st == "caesar":
            axes.append(StageAxis("caesar", 26))  # 26 possible shifts
        elif st == "railfence":
            axes.append(StageAxis("railfence", 29))  # 2-30 rails
        elif st == "substitution":
            # Dictionary-based: try all keys from dictionary
            axes.append(StageAxis("substitution", n_keys))
        elif st in ("bifid", "columnar", "xor"):
            axes.append(StageAxis(st, n_keys))
        elif st in ("b64", "reverse"):
            continue  # No parameters - only one possibility
    return axes
```

**Parameter Space Guidelines:**
- **Dictionary-based**: Use `n_keys` (number of words in dictionary)
- **Fixed parameters**: Use the number of possible values (e.g., 26 for Caesar shifts)
- **No parameters**: Don't add an axis (like `b64` or `reverse`)
- **Multiple parameters**: Multiply the possibilities (e.g., `n_keys * n_keys` for double keys)

### Step 5: Add Execution Logic

In `core/executor.py`, add your stage to the `StageExecutor` class:

#### 5.1: Import your function

```python
# core/executor.py (at the top)
from stages.substitution import substitution_decrypt
```

#### 5.2: Add to `_execute_stage()` method

```python
def _execute_stage(
    self,
    stage: str,
    payload: str | bytes,
    kind: Kind,
    param_idxs: list[int],
    axis_pos: int,
    meta: Dict[str, Any],
) -> tuple[str | bytes, Kind, int] | None:
    """Execute a single stage."""
    if stage == "b64":
        return self._execute_b64(payload, kind, axis_pos)
    
    elif stage == "substitution":
        return self._execute_substitution(payload, kind, param_idxs, axis_pos, meta)
    
    # ... other stages ...
```

#### 5.3: Implement the execution method

```python
def _execute_substitution(
    self,
    payload: str | bytes,
    kind: Kind,
    param_idxs: list[int],
    axis_pos: int,
    meta: Dict[str, Any],
) -> tuple[str | bytes, Kind, int] | None:
    """Execute substitution cipher stage."""
    # Check input type
    if kind != "text":
        return None
    
    # Get parameter from parameter space
    ki = param_idxs[axis_pos]
    key = self.keys[ki]
    
    # Store in metadata for result display
    meta["substitution_key"] = key
    
    # Apply cipher
    result = substitution_decrypt(payload, key)  # type: ignore[arg-type]
    
    # Return (new_payload, new_kind, new_axis_pos)
    return (result, kind, axis_pos + 1)
```

**Execution Method Guidelines:**
- Always check `kind` matches what your cipher expects
- Return `None` if the input type is wrong (early exit)
- Get parameters from `param_idxs[axis_pos]`
- Increment `axis_pos` by 1 for each parameter consumed
- Store all parameters in `meta` for debugging
- Return `(new_payload, new_kind, new_axis_pos)`

### Step 6: Add Tests

Create test cases in `test_stages.py`:

```python
class TestSubstitutionCipher:
    """Tests for Substitution cipher."""
    
    def test_decrypt_valid_key(self):
        """Test decryption with a valid key."""
        from stages.substitution import substitution_decrypt
        
        ciphertext = "IFMMP"
        key = "BCDEFGHIJKLMNOPQRSTUVWXYZA"  # A→B, B→C, etc.
        result = substitution_decrypt(ciphertext, key)
        assert result == "HELLO"
    
    def test_wrong_key_produces_gibberish(self):
        """Test that wrong key produces gibberish."""
        from stages.substitution import substitution_decrypt
        
        ciphertext = "IFMMP"
        wrong_key = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
        result = substitution_decrypt(ciphertext, wrong_key)
        assert result != "HELLO"
    
    def test_empty_string(self):
        """Test empty string handling."""
        from stages.substitution import substitution_decrypt
        
        result = substitution_decrypt("", "KEY")
        assert result == ""
    
    def test_preserves_non_alpha(self):
        """Test that non-alphabetic characters are preserved."""
        from stages.substitution import substitution_decrypt
        
        ciphertext = "IFMMP, XPSME!"
        key = "BCDEFGHIJKLMNOPQRSTUVWXYZA"
        result = substitution_decrypt(ciphertext, key)
        assert result == "HELLO, WORLD!"
```

---

## Integration Checklist

Use this checklist to ensure complete integration:

- [ ] **Stage Module Created** (`stages/your_stage.py`)
  - [ ] Core algorithm function(s) implemented
  - [ ] Proper type hints added
  - [ ] Comprehensive docstrings written
  - [ ] Edge cases handled

- [ ] **core/pipeline.py Updated**
  - [ ] Stage added to `VALID_STAGES` set
  - [ ] Axis defined in `axes_for_pipeline()`

- [ ] **core/executor.py Updated**
  - [ ] Import statement added at top
  - [ ] Stage added to `_execute_stage()` method
  - [ ] Execution method implemented (`_execute_your_stage()`)

- [ ] **Tests Written** (`test_stages.py`)
  - [ ] Valid decryption test
  - [ ] Wrong key test
  - [ ] Empty string test
  - [ ] Edge cases tested

- [ ] **Tests Pass**
  - [ ] Run `pytest test_stages.py -v`
  - [ ] All tests pass

- [ ] **Pipeline Test**
  - [ ] Test stage in isolation
  - [ ] Test in combination with other stages

---

## Examples

### Example 1: Parameter-Based Stage (No Keys)

A ROT-N cipher that rotates characters by a fixed amount:

```python
# stages/rotn.py
from __future__ import annotations


def rotn_decrypt(text: str, n: int) -> str:
    """Rotate each character by n positions."""
    return "".join(chr((ord(c) - n) % 256) for c in text)
```

**Integration:**

```python
# core/pipeline.py
VALID_STAGES = {..., "rotn"}

def axes_for_pipeline(...):
    # ...
    elif st == "rotn":
        axes.append(StageAxis("rotn", 256))  # 0-255 rotations

# core/executor.py
from stages.rotn import rotn_decrypt

def _execute_stage(...):
    # ...
    elif stage == "rotn":
        return self._execute_rotn(payload, kind, param_idxs, axis_pos, meta)

def _execute_rotn(self, payload, kind, param_idxs, axis_pos, meta):
    if kind != "text":
        return None
    
    rotation = param_idxs[axis_pos]
    meta["rotn_shift"] = rotation
    result = rotn_decrypt(payload, rotation)  # type: ignore[arg-type]
    return (result, kind, axis_pos + 1)
```

### Example 2: Key-Based Stage (Dictionary Keys)

A simple substitution cipher using dictionary keys:

```python
# stages/simple_sub.py
from __future__ import annotations


def simple_sub_decrypt(text: str, key: str) -> str:
    """
    Decrypt using a simple substitution based on key.
    The key is hashed to create a substitution alphabet.
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    sub_alphabet = create_sub_alphabet(key)
    
    # Build reverse mapping
    mapping = {sub_alphabet[i]: alphabet[i] for i in range(26)}
    
    result = []
    for c in text.upper():
        result.append(mapping.get(c, c))
    return "".join(result)


def create_sub_alphabet(key: str) -> str:
    """Create substitution alphabet from key."""
    # Implementation details...
    pass
```

**Integration:**

```python
# core/pipeline.py
elif st == "simple_sub":
    axes.append(StageAxis("simple_sub", n_keys))

# core/executor.py
from stages.simple_sub import simple_sub_decrypt

def _execute_simple_sub(self, payload, kind, param_idxs, axis_pos, meta):
    if kind != "text":
        return None
    
    ki = param_idxs[axis_pos]
    key = self.keys[ki]
    meta["simple_sub_key"] = key
    result = simple_sub_decrypt(payload, key)  # type: ignore[arg-type]
    return (result, kind, axis_pos + 1)
```

### Example 3: Bytes-Processing Stage

A stage that works with bytes instead of text:

```python
# stages/byte_reverse.py
from __future__ import annotations


def byte_reverse(data: bytes) -> bytes:
    """Reverse the byte order."""
    return bytes(reversed(data))
```

**Integration:**

```python
# core/pipeline.py
elif st == "byte_reverse":
    continue  # No parameters

# core/executor.py
from stages.byte_reverse import byte_reverse

def _execute_byte_reverse(self, payload, kind, meta, axis_pos):
    if kind != "bytes":
        return None
    
    meta["byte_reverse_applied"] = True
    result = byte_reverse(payload)  # type: ignore[arg-type]
    return (result, kind, axis_pos)  # Note: axis_pos unchanged (no parameters)
```

### Example 4: Multi-Parameter Stage

A stage with multiple parameters (like double columnar):

```python
# stages/double_xor.py
from __future__ import annotations

from .xor import repeating_xor


def double_xor_decrypt(data: bytes, key1: str, key2: str) -> bytes:
    """Apply XOR twice with two different keys."""
    kb1 = key1.encode("utf-8", "ignore")
    kb2 = key2.encode("utf-8", "ignore")
    temp = repeating_xor(data, kb2)
    return repeating_xor(temp, kb1)
```

**Integration:**

```python
# core/pipeline.py
elif st == "double_xor":
    # n_keys * n_keys combinations (ordered pairs)
    axes.append(StageAxis("double_xor", n_keys * n_keys))

# core/executor.py
from stages.double_xor import double_xor_decrypt

def _execute_double_xor(self, payload, kind, param_idxs, axis_pos, meta):
    if kind != "bytes":
        return None
    
    pi = param_idxs[axis_pos]
    n = len(self.keys)
    k1 = self.keys[pi // n]
    k2 = self.keys[pi % n]
    meta["double_xor_key1"] = k1
    meta["double_xor_key2"] = k2
    result = double_xor_decrypt(payload, k1, k2)  # type: ignore[arg-type]
    return (result, kind, axis_pos + 1)
```

---

## Testing

### Running Tests (with uv)

```bash
uv run pytest test_stages.py -v

# Run tests for specific stage
uv run pytest test_stages.py::TestYourCipher -v

# Run with coverage
uv run pytest test_stages.py --cov=stages --cov-report=html
```

### Pipeline Testing

```bash
# Test stage recognition
uv run run_pipeline --pipeline "your_stage" --ciphertext "TEST" --threshold 1.0

# Test in combination
uv run run_pipeline --pipeline "caesar>your_stage>b64" --ciphertext "..." --threshold 1.5

# Test with limited keys for faster testing
uv run run_pipeline --pipeline "your_stage" --ciphertext "..." --key_limit 10
```

---

## Advanced Topics

### Custom Parameter Spaces

If your stage has a complex parameter space (not just keys or simple ranges), you can encode it in the axis:

```python
# Example: Stage with 3 modes × 10 levels = 30 combinations
elif st == "complex_stage":
    axes.append(StageAxis("complex_stage", 30))

# In executor:
def _execute_complex_stage(self, payload, kind, param_idxs, axis_pos, meta):
    param_idx = param_idxs[axis_pos]
    mode = param_idx // 10  # 0, 1, or 2
    level = param_idx % 10  # 0-9
    meta["complex_stage_mode"] = mode
    meta["complex_stage_level"] = level
    result = complex_stage_decrypt(payload, mode, level)
    return (result, kind, axis_pos + 1)
```

### Performance Optimization

For expensive operations:

1. **Early exit**: Return `None` as soon as you know a combination won't work
2. **Caching**: Cache expensive computations (e.g., keyed squares in Bifid)
3. **Type checking first**: Check `kind` before doing any work
4. **Efficient algorithms**: Use optimized implementations

### Type Conversion

If your stage can accept both text and bytes:

```python
def _execute_flexible_stage(self, payload, kind, param_idxs, axis_pos, meta):
    # Convert to bytes if needed
    if kind == "text":
        data = payload.encode("utf-8")  # type: ignore[union-attr]
    else:
        data = payload  # type: ignore[assignment]
    
    # Process as bytes
    result_bytes = your_cipher_decrypt(data, key)
    
    # Try to convert back to text if fully printable
    if printable_ratio(result_bytes) == 1.0:
        try:
            result_text = result_bytes.decode("ascii")
            return (result_text, "text", axis_pos + 1)
        except Exception:
            pass
    
    return (result_bytes, "bytes", axis_pos + 1)
```

---

## Common Pitfalls

1. **Forgetting to increment `axis_pos`**: Always increment by the number of parameters consumed
2. **Not checking `kind`**: Always validate input type before processing
4. **Not handling edge cases**: Empty strings, invalid keys, etc.
5. **Type annotation errors**: Use `# type: ignore[arg-type]` when needed for union types
6. **Forgetting to add to `VALID_STAGES`**: Stage won't be recognized in pipeline

---

## Summary

Adding a new stage requires:

1. **Create** `stages/your_stage.py` with core algorithm
2. **Update** `core/pipeline.py` (VALID_STAGES and axes)
3. **Update** `core/executor.py` (import, _execute_stage, _execute_your_stage)
4. **Test** with `test_stages.py` and pipeline tests

The direct execution model is simple and efficient - each stage is just a function that transforms the payload!

