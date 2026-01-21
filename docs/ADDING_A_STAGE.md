# Adding a New Cipher Stage

**Key Concepts:**
- **Stages**: Individual cipher algorithms (e.g., Caesar, Bifid, XOR)
- **Pipeline**: A sequence of stages (e.g., `caesar>bifid>b64>xor`)
- **Candidate**: A data structure carrying payload, type (text/bytes), and metadata
- **Bruteforce Function**: A generator that tries all possible keys/parameters for a cipher

---

## Stage Architecture

### File Structure
Each stage is implemented as a Python module in the `stages/` directory:

```
stages/
├── __init__.py          # Exports common utilities
├── common.py            # Shared types and utilities
├── caesar.py            # Example: parameter-based stage
├── bifid.py             # Example: key-based stage
├── xor.py               # Example: bytes-processing stage
└── your_stage.py        # Your new stage
```

### Core Components

Every stage module should contain:

1. **Core Algorithm Function(s)**: The actual cipher implementation
2. **Bruteforce Function**: A generator that yields all possible decryptions
3. **Type Handling**: Proper handling of text vs bytes payloads

### The Candidate Data Structure

Defined in `stages/common.py`:

```python
@dataclass(slots=True)
class Candidate:
    payload: str | bytes      # The actual data
    kind: PayloadKind         # "text" or "bytes"
    meta: Dict[str, Any]      # Metadata about transformations
```

---

## Step-by-Step Guide

### Step 1: Create Your Stage Module

Create a new file in `stages/` named after your cipher (e.g., `stages/substitution.py`).

### Step 2: Import Required Dependencies

```python
from __future__ import annotations

from typing import Iterator, Iterable
from .common import Candidate
```

### Step 3: Implement the Core Algorithm

Create the encryption/decryption function(s):

```python
def your_cipher_decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypt ciphertext using your cipher algorithm.
    
    Args:
        ciphertext: The encrypted text
        key: The decryption key
        
    Returns:
        The decrypted plaintext
    """
    # Your implementation here
    pass
```

**Guidelines:**
- Keep functions pure (no side effects)
- Handle edge cases (empty strings, invalid keys, etc.)
- Add docstrings explaining the algorithm
- Return the same type as input (str→str, bytes→bytes)

### Step 4: Implement the Bruteforce Function

This is the key integration point. The function signature follows this pattern:

```python
def your_cipher_bruteforce(
    cands: Iterator[Candidate],
    keys: Iterable[str],  # Optional: only if your cipher uses keys
    *,
    # Add any stage-specific parameters here
    param1: int = default_value,
) -> Iterator[Candidate]:
    """
    Bruteforce your cipher across all candidates and keys/parameters.
    
    Args:
        cands: Iterator of input candidates
        keys: Iterable of keys to try (if applicable)
        param1: Stage-specific parameter
        
    Yields:
        Candidate objects with decrypted payloads
    """
    for c in cands:
        # 1. Check payload type
        if c.kind != "text":  # or "bytes" depending on your cipher
            continue
            
        # 2. Extract payload
        s = c.payload
        assert isinstance(s, str)  # or bytes
        
        # 3. Try all keys/parameters
        for key in keys:
            # 4. Apply your cipher
            out = your_cipher_decrypt(s, key)
            
            # 5. Copy and update metadata
            meta = dict(c.meta)
            meta["your_cipher_key"] = key
            meta["your_cipher_param"] = param1
            
            # 6. Yield new candidate
            yield Candidate(out, "text", meta)  # or "bytes"
```

**Key Points:**
- **Type checking**: Always check `c.kind` matches what your cipher expects
- **Metadata**: Copy existing metadata with `dict(c.meta)` and add your stage's info
- **Generator pattern**: Use `yield` to return candidates lazily
- **Naming convention**: Metadata keys should be `{stage_name}_{parameter}`

### Step 5: Integrate into `run_pipeline.py`

You need to modify three locations in `run_pipeline.py`:

#### 5.1: Add to Valid Stages List

In the `parse_pipeline()` function (around line 52):

```python
def parse_pipeline(pipeline: str) -> list[str]:
    stages = [s.strip() for s in pipeline.split(">") if s.strip()]
    valid = {
        "caesar",
        "bifid",
        "columnar",
        "double_columnar",
        "b64",
        "xor",
        "railfence",
        "your_stage",  # Add your stage here
    }
    bad = [s for s in stages if s not in valid]
    if bad:
        raise SystemExit(f"Unknown stages in pipeline: {bad}. Valid: {sorted(valid)}")
    return stages
```

#### 5.2: Define Axis Size

In the `axes_for_pipeline()` function (around line 67):

```python
def axes_for_pipeline(stages: list[str], n_keys: int) -> list[StageAxis]:
    axes: list[StageAxis] = []
    for st in stages:
        if st == "caesar":
            axes.append(StageAxis("caesar", 26))
        elif st == "railfence":
            axes.append(StageAxis("railfence", 29))  # 2-30 rails
        elif st == "your_stage":
            # If your stage uses dictionary keys:
            axes.append(StageAxis("your_stage", n_keys))
            # If your stage has fixed parameters (e.g., 10 possible values):
            # axes.append(StageAxis("your_stage", 10))
        elif st in ("bifid", "columnar", "xor"):
            axes.append(StageAxis(st, n_keys))
        # ... rest of function
```

**Axis Size Guidelines:**
- **Dictionary-based**: Use `n_keys` (number of words in dictionary)
- **Fixed parameters**: Use the number of possible values (e.g., 26 for Caesar shifts)
- **No parameters**: Don't add an axis (like `b64`)

#### 5.3: Add Processing Logic

In the `run_one_combo()` function (around line 114), add your stage's processing:

```python
def run_one_combo(param_idxs: list[int]) -> tuple[float | None, Dict[str, Any] | None]:
    # ... existing code ...
    
    for st in _W_STAGES:
        # ... existing stages ...
        
        if st == "your_stage":
            # Get parameter index
            param_idx = param_idxs[axis_pos]
            axis_pos += 1
            
            # Get the key/parameter
            key = _W_KEYS[param_idx]  # For dictionary-based
            # OR
            # param_value = param_idx + offset  # For numeric parameters
            
            # Store in metadata
            meta["your_stage_key"] = key
            
            # Check payload type
            if kind != "text":  # or "bytes"
                return (None, None)
            
            # Apply your cipher
            payload = your_cipher_decrypt(payload, key)
            continue
        
        # ... rest of function
```

#### 5.4: Import Your Functions

At the top of `run_pipeline.py` (around line 10):

```python
from stages.your_stage import your_cipher_decrypt
```

### Step 6: Add Tests

Create test cases in `test_stages.py`:

```python
class TestYourCipher:
    """Tests for Your Cipher."""
    
    def test_basic_decrypt(self):
        """Test basic decryption."""
        from stages.your_stage import your_cipher_decrypt
        
        ciphertext = "ENCRYPTED"
        key = "KEY"
        result = your_cipher_decrypt(ciphertext, key)
        assert result == "EXPECTED"
    
    def test_edge_case_empty(self):
        """Test empty string."""
        from stages.your_stage import your_cipher_decrypt
        
        result = your_cipher_decrypt("", "KEY")
        assert result == ""
    
    def test_round_trip(self):
        """Test encryption and decryption round trip."""
        from stages.your_stage import your_cipher_encrypt, your_cipher_decrypt
        
        plaintext = "HELLO"
        key = "KEY"
        encrypted = your_cipher_encrypt(plaintext, key)
        decrypted = your_cipher_decrypt(encrypted, key)
        assert decrypted == plaintext
```

---

## Integration Checklist

Use this checklist to ensure complete integration:

- [ ] **Stage Module Created** (`stages/your_stage.py`)
  - [ ] Core algorithm function(s) implemented
  - [ ] Bruteforce function implemented
  - [ ] Proper type hints added
  - [ ] Docstrings written

- [ ] **run_pipeline.py Updated**
  - [ ] Stage added to `valid` set in `parse_pipeline()`
  - [ ] Axis defined in `axes_for_pipeline()`
  - [ ] Processing logic added to `run_one_combo()`
  - [ ] Import statement added at top

- [ ] **Tests Written** (`test_stages.py`)
  - [ ] Basic functionality test
  - [ ] Edge cases tested
  - [ ] Round-trip test (if applicable)

- [ ] **Tests Pass**
  - [ ] Run `pytest test_stages.py -v`
  - [ ] All tests pass

- [ ] **Pipeline Test**
  - [ ] Test stage in isolation: `python run_pipeline.py --pipeline "your_stage" --dry_run`
  - [ ] Test in combination: `python run_pipeline.py --pipeline "caesar>your_stage>b64" --dry_run`

---

## Examples

### Example 1: Parameter-Based Stage (No Keys)

A simple ROT-N cipher that doesn't use dictionary keys:

```python
# stages/rotn.py
from __future__ import annotations
from typing import Iterator
from .common import Candidate

def rotn_decrypt(text: str, n: int) -> str:
    """Rotate each character by n positions."""
    return "".join(chr((ord(c) - n) % 256) for c in text)

def rotn_bruteforce(
    cands: Iterator[Candidate],
    *,
    max_rotation: int = 255,
) -> Iterator[Candidate]:
    """Try all rotations from 0 to max_rotation."""
    for c in cands:
        if c.kind != "text":
            continue
        s = c.payload
        assert isinstance(s, str)
        
        for n in range(max_rotation + 1):
            out = rotn_decrypt(s, n)
            meta = dict(c.meta)
            meta["rotn_shift"] = n
            yield Candidate(out, "text", meta)
```

**Integration in `run_pipeline.py`:**

```python
# In axes_for_pipeline():
elif st == "rotn":
    axes.append(StageAxis("rotn", 256))  # 0-255 rotations

# In run_one_combo():
if st == "rotn":
    rotation = param_idxs[axis_pos]
    axis_pos += 1
    meta["rotn_shift"] = rotation
    if kind != "text":
        return (None, None)
    payload = rotn_decrypt(payload, rotation)
    continue
```

### Example 2: Key-Based Stage (Dictionary Keys)

A simple substitution cipher using dictionary keys:

```python
# stages/substitution.py
from __future__ import annotations
from typing import Iterator, Iterable
from .common import Candidate

def substitution_decrypt(text: str, key: str) -> str:
    """
    Decrypt using a substitution alphabet derived from key.
    Key is hashed to create a substitution mapping.
    """
    # Create substitution alphabet from key
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    sub_alphabet = create_substitution_from_key(key)
    
    # Build reverse mapping for decryption
    mapping = {sub_alphabet[i]: alphabet[i] for i in range(26)}
    
    # Decrypt
    result = []
    for c in text.upper():
        if c in mapping:
            result.append(mapping[c])
        else:
            result.append(c)
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

def substitution_bruteforce(
    cands: Iterator[Candidate],
    keys: Iterable[str],
) -> Iterator[Candidate]:
    """Bruteforce substitution cipher with dictionary keys."""
    for c in cands:
        if c.kind != "text":
            continue
        s = c.payload
        assert isinstance(s, str)
        
        for key in keys:
            out = substitution_decrypt(s, key)
            meta = dict(c.meta)
            meta["substitution_key"] = key
            yield Candidate(out, "text", meta)
```

**Integration in `run_pipeline.py`:**

```python
# In axes_for_pipeline():
elif st == "substitution":
    axes.append(StageAxis("substitution", n_keys))

# In run_one_combo():
if st == "substitution":
    ki = param_idxs[axis_pos]
    axis_pos += 1
    key = _W_KEYS[ki]
    meta["substitution_key"] = key
    if kind != "text":
        return (None, None)
    payload = substitution_decrypt(payload, key)
    continue
```

### Example 3: Bytes-Processing Stage

A stage that works with bytes instead of text:

```python
# stages/reverse_bytes.py
from __future__ import annotations
from typing import Iterator
from .common import Candidate

def reverse_bytes(data: bytes) -> bytes:
    """Reverse the byte order."""
    return bytes(reversed(data))

def reverse_bytes_bruteforce(
    cands: Iterator[Candidate],
) -> Iterator[Candidate]:
    """
    Reverse bytes of each candidate.
    No keys needed - only one possibility.
    """
    for c in cands:
        if c.kind != "bytes":
            continue
        data = c.payload
        assert isinstance(data, bytes)
        
        out = reverse_bytes(data)
        meta = dict(c.meta)
        meta["reverse_bytes_applied"] = True
        yield Candidate(out, "bytes", meta)
```

**Integration in `run_pipeline.py`:**

```python
# In axes_for_pipeline():
elif st == "reverse_bytes":
    # No axis needed - only one possibility
    continue

# In run_one_combo():
if st == "reverse_bytes":
    # No parameter needed
    if kind != "bytes":
        return (None, None)
    payload = reverse_bytes(payload)
    meta["reverse_bytes_applied"] = True
    continue
```

### Example 4: Multi-Parameter Stage

A stage with multiple parameters (like double columnar):

```python
# stages/double_xor.py
from __future__ import annotations
from typing import Iterator
from .common import Candidate
from .xor import repeating_xor

def double_xor_decrypt(data: bytes, key1: str, key2: str) -> bytes:
    """Apply XOR twice with two different keys."""
    kb1 = key1.encode("utf-8", "ignore")
    kb2 = key2.encode("utf-8", "ignore")
    temp = repeating_xor(data, kb2)
    return repeating_xor(temp, kb1)

def double_xor_bruteforce(
    cands: Iterator[Candidate],
    keys: list[str],
) -> Iterator[Candidate]:
    """Bruteforce double XOR with all key pairs."""
    for c in cands:
        if c.kind != "bytes":
            continue
        data = c.payload
        assert isinstance(data, bytes)
        
        # Try all ordered pairs
        for k1 in keys:
            for k2 in keys:
                out = double_xor_decrypt(data, k1, k2)
                meta = dict(c.meta)
                meta["double_xor_key1"] = k1
                meta["double_xor_key2"] = k2
                yield Candidate(out, "bytes", meta)
```

**Integration in `run_pipeline.py`:**

```python
# In axes_for_pipeline():
elif st == "double_xor":
    # n_keys * n_keys combinations (ordered pairs)
    axes.append(StageAxis("double_xor", n_keys * n_keys))

# In run_one_combo():
if st == "double_xor":
    pi = param_idxs[axis_pos]
    axis_pos += 1
    n = len(_W_KEYS)
    k1 = _W_KEYS[pi // n]
    k2 = _W_KEYS[pi % n]
    meta["double_xor_key1"] = k1
    meta["double_xor_key2"] = k2
    if kind != "bytes":
        return (None, None)
    payload = double_xor_decrypt(payload, k1, k2)
    continue
```

---

## Testing

### Running Tests

```bash
# Run all tests
pytest test_stages.py -v

# Run tests for specific stage
pytest test_stages.py::TestYourCipher -v

# Run with coverage
pytest test_stages.py --cov=stages --cov-report=html
```

### Dry Run Testing

Test your stage without actually running the brute force:

```bash
# Test stage is recognized
python run_pipeline.py --pipeline "your_stage" --dry_run

# Test in a pipeline
python run_pipeline.py --pipeline "caesar>your_stage>b64>xor" --dry_run --key_limit 10

# Check axis calculations
python run_pipeline.py --pipeline "your_stage" --dry_run --key_limit 100
```

## Advanced Topics

### Custom Parameter Spaces

If your stage has a complex parameter space (not just keys or simple ranges), you can encode it in the axis:

```python
# Example: Stage with 3 modes × 10 levels = 30 combinations
elif st == "complex_stage":
    axes.append(StageAxis("complex_stage", 30))

# In run_one_combo():
if st == "complex_stage":
    param_idx = param_idxs[axis_pos]
    axis_pos += 1
    mode = param_idx // 10  # 0, 1, or 2
    level = param_idx % 10  # 0-9
    meta["complex_stage_mode"] = mode
    meta["complex_stage_level"] = level
    payload = complex_stage_decrypt(payload, mode, level)
```

### Performance Optimization

For expensive operations, consider:

1. **Caching**: Cache expensive computations (e.g., keyed squares in Bifid)
2. **Early exit**: Return `(None, None)` as soon as you know a combination won't work
3. **Vectorization**: Use numpy for byte operations if applicable

---