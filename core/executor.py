"""
Stage execution logic.

This module contains the core logic for executing individual cipher stages
and evaluating results against the scoring threshold.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Literal

from stages.affine import (
    VALID_A_BY_MODE,
    MOD_BY_MODE,
    N_AFFINE_COMBOS_BY_MODE,
    affine_decrypt,
)
from stages.bifid import bifid_decrypt
from stages.caesar import N_CAESAR_CHARSET_MODES, caesar_shift_text
from stages.columnar import columnar_decrypt
from stages.common import combined_score, printable_ratio
from stages.double_columnar import double_columnar_decrypt
from stages.key_derivation import DERIVATION_NAMES, N_KEY_DERIVATION_MODES, derive_key
from stages.mcrypt_registry import (
    IV_KEY_NULL_PAD,
    IV_KEY_ZERO_STRING_PAD,
    IV_NULL,
    IV_PREPENDED,
    IV_ZERO_STRING,
    KEY_PAD_ZERO_STRING,
    N_IV_STRATEGIES,
    N_KEY_PAD_STRATEGIES,
    get_stage_info,
    is_mcrypt_stage,
)
from stages.mcrypt_stage import mcrypt_decrypt_stage
from stages.mcrypt_wrapper import McryptHandleCache
from stages.myszkowski import myszkowski_decrypt
from stages.polyalpha import (
    autokey_decrypt,
    beaufort_decrypt,
    porta_decrypt,
    trithemius_decrypt,
    vigenere_decrypt,
)
from stages.railfence import railfence_decrypt
from stages.redefense import redefense_decrypt
from stages.reverse import reverse_text
from stages.scytale import scytale_decrypt
from stages.xor import repeating_xor

from .utils import N_CASE_VARIANTS, apply_case_variant

Kind = Literal["text", "bytes"]


def _nearest_valid_key_size(key_len: int, info: "McryptStageInfo") -> int:
    """Find the nearest valid key size >= key_len for the algorithm.

    For fixed-size algorithms (e.g. [16, 24, 32]), returns the smallest
    valid size >= key_len. For variable-size algorithms, returns key_len
    (any size up to max is valid). Never exceeds max_key_size.
    """
    if info.key_sizes is None:
        return key_len
    for size in sorted(info.key_sizes):
        if size >= key_len:
            return size
    return info.max_key_size


def _plaintext_preview(data: bytes) -> str:
    """Create a printable preview of decrypted bytes."""
    stripped = data.rstrip(b"\x00")
    return stripped.decode("utf-8", errors="replace")


class StageExecutor:
    """
    Executes cipher stages in a pipeline.

    This class maintains the state of the current payload and its type
    (text or bytes) as it flows through the pipeline stages.
    """

    def __init__(
        self,
        ciphertext: str,
        keys: list[str],
        stages: list[str],
        bifid_alphabet: str,
        common_words: set[str] | None = None,
        vary_case: bool = False,
        handle_cache: McryptHandleCache | None = None,
    ):
        """
        Initialize the stage executor.

        Args:
            ciphertext: Input ciphertext
            keys: Dictionary of keys
            stages: List of stage names
            bifid_alphabet: Alphabet for bifid cipher
            common_words: Common words for English scoring
            vary_case: If True, try lower/upper/title case per word (key index is combined)
            handle_cache: Mcrypt handle cache for brute-force performance
        """
        self.ciphertext = ciphertext
        self.keys = keys
        self.stages = stages
        self.bifid_alphabet = bifid_alphabet
        self.common_words = common_words
        self.vary_case = vary_case
        self.handle_cache = handle_cache

    def _get_effective_key(self, ki_combined: int) -> str:
        """Resolve key string from combined key index (word index + optional case variant)."""
        if self.vary_case:
            ki = ki_combined // N_CASE_VARIANTS
            case_idx = ki_combined % N_CASE_VARIANTS
            return apply_case_variant(self.keys[ki], case_idx)
        return self.keys[ki_combined]

    def execute_pipeline(
        self, param_idxs: list[int], threshold: float
    ) -> tuple[float | None, Dict[str, Any] | None]:
        """
        Execute the full pipeline with given parameters.

        Args:
            param_idxs: Parameter indices for each stage
            threshold: Minimum score to accept result

        Returns:
            (score, metadata) if result meets threshold, else (None, None)
        """
        meta: Dict[str, Any] = {}
        axis_pos = 0

        kind: Kind = "text"
        payload: str | bytes = self.ciphertext

        for st in self.stages:
            result = self._execute_stage(st, payload, kind, param_idxs, axis_pos, meta)

            if result is None:
                return (None, None)

            payload, kind, axis_pos = result

        # Evaluate final result
        return self._evaluate_result(payload, kind, meta, threshold)

    def _execute_stage(
        self,
        stage: str,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """
        Execute a single stage.

        Returns:
            (new_payload, new_kind, new_axis_pos) or None if stage fails
        """
        if stage == "b64":
            return self._execute_b64(payload, kind, axis_pos)

        elif stage == "hex":
            return self._execute_hex(payload, kind, axis_pos)

        elif stage == "affine":
            return self._execute_affine(payload, kind, param_idxs, axis_pos, meta)

        elif stage == "caesar":
            return self._execute_caesar(payload, kind, param_idxs, axis_pos, meta)

        elif stage == "railfence":
            return self._execute_railfence(payload, kind, param_idxs, axis_pos, meta)

        elif stage == "bifid":
            return self._execute_bifid(payload, kind, param_idxs, axis_pos, meta)

        elif stage == "columnar":
            return self._execute_columnar(payload, kind, param_idxs, axis_pos, meta)

        elif stage == "double_columnar":
            return self._execute_double_columnar(
                payload, kind, param_idxs, axis_pos, meta
            )

        elif stage == "myszkowski":
            return self._execute_myszkowski(payload, kind, param_idxs, axis_pos, meta)

        elif stage == "redefense":
            return self._execute_redefense(payload, kind, param_idxs, axis_pos, meta)

        elif stage == "xor":
            return self._execute_xor(payload, kind, param_idxs, axis_pos, meta)

        elif stage in ("vigenere", "beaufort", "autokey", "porta",
                      "vigenere52", "beaufort52", "autokey52", "porta52"):
            return self._execute_polyalpha(
                stage, payload, kind, param_idxs, axis_pos, meta
            )

        elif stage in ("trithemius", "trithemius52"):
            return self._execute_trithemius(
                stage, payload, kind, meta, axis_pos
            )

        elif stage == "reverse":
            return self._execute_reverse(payload, kind, meta, axis_pos)

        elif stage == "scytale":
            return self._execute_scytale(payload, kind, param_idxs, axis_pos, meta)

        elif is_mcrypt_stage(stage):
            return self._execute_mcrypt(stage, payload, kind, param_idxs, axis_pos, meta)

        else:
            raise ValueError(f"Unhandled stage: {stage}")

    def _execute_b64(
        self, payload: str | bytes, kind: Kind, axis_pos: int
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute Base64 decode stage."""
        if kind != "text":
            return None

        try:
            # Pad to multiple of 4 if needed (some sources omit trailing '=')
            padded = payload + "=" * ((4 - len(payload) % 4) % 4)  # type: ignore[operator]
            decoded = base64.b64decode(padded, validate=False)
        except Exception:
            return None

        # If fully printable, try to decode as text
        if printable_ratio(decoded) == 1.0:
            try:
                return (decoded.decode("ascii"), "text", axis_pos)
            except (UnicodeDecodeError, AttributeError):
                return (decoded, "bytes", axis_pos)
        else:
            return (decoded, "bytes", axis_pos)

    def _execute_hex(
        self, payload: str | bytes, kind: Kind, axis_pos: int
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute hex decode stage (e.g. 'd865ec...' → bytes)."""
        if kind != "text":
            return None

        try:
            hex_str = payload.strip()  # type: ignore[union-attr]
            # Pad leading '0' for odd-length hex strings
            if len(hex_str) % 2 != 0:
                hex_str = "0" + hex_str
            decoded = bytes.fromhex(hex_str)
        except (ValueError, AttributeError):
            return None

        if printable_ratio(decoded) == 1.0:
            try:
                return (decoded.decode("ascii"), "text", axis_pos)
            except (UnicodeDecodeError, AttributeError):
                return (decoded, "bytes", axis_pos)
        else:
            return (decoded, "bytes", axis_pos)

    def _execute_caesar(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute Caesar cipher stage."""
        if kind != "text":
            return None

        from stages.caesar import CAESAR_SHIFTS_PER_MODE

        idx = param_idxs[axis_pos]
        # Decode (charset_mode, shift) from flat index
        # Ranges: [0..25]=alpha, [26..155]=alphanumeric, [156..250]=all_printable
        charset_mode = 0
        for mode, n_shifts in enumerate(CAESAR_SHIFTS_PER_MODE):
            if idx < n_shifts:
                charset_mode = mode
                shift = idx
                break
            idx -= n_shifts
        else:
            return None

        charset_names = ["alpha", "alphanumeric", "all_printable"]
        meta["caesar_shift"] = shift
        meta["caesar_charset"] = charset_names[charset_mode]
        result = caesar_shift_text(payload, shift, charset_mode)  # type: ignore[arg-type]
        return (result, kind, axis_pos + 1)

    def _execute_railfence(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute Railfence cipher stage."""
        if kind != "text":
            return None

        rails_idx = param_idxs[axis_pos]
        num_rails = rails_idx + 2  # 0-28 maps to 2-30 rails
        meta["railfence_rails"] = num_rails
        result = railfence_decrypt(payload, num_rails)  # type: ignore[arg-type]
        return (result, kind, axis_pos + 1)

    def _execute_scytale(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute Scytale transposition cipher stage."""
        if kind != "text":
            return None

        cols_idx = param_idxs[axis_pos]
        n_cols = cols_idx + 2  # 0-based index maps to 2..N columns
        meta["scytale_cols"] = n_cols
        result = scytale_decrypt(payload, n_cols)  # type: ignore[arg-type]
        return (result, kind, axis_pos + 1)

    def _execute_bifid(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute Bifid cipher stage."""
        if kind != "text":
            return None

        ki_combined = param_idxs[axis_pos]
        key = self._get_effective_key(ki_combined)
        meta["bifid_key"] = key
        result = bifid_decrypt(
            payload,
            key,
            period=len(payload),
            alphabet=self.bifid_alphabet,  # type: ignore[arg-type]
        )
        return (result, kind, axis_pos + 1)

    def _execute_columnar(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute Columnar Transposition stage."""
        if kind != "text":
            return None

        ki_combined = param_idxs[axis_pos]
        key = self._get_effective_key(ki_combined)
        meta["columnar_key"] = key
        result = columnar_decrypt(payload, key)  # type: ignore[arg-type]
        return (result, kind, axis_pos + 1)

    def _execute_double_columnar(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute Double Columnar Transposition stage."""
        if kind != "text":
            return None

        pi = param_idxs[axis_pos]
        n = len(self.keys) * (N_CASE_VARIANTS if self.vary_case else 1)
        k1 = self._get_effective_key(pi // n)
        k2 = self._get_effective_key(pi % n)
        meta["double_columnar_key1"] = k1
        meta["double_columnar_key2"] = k2
        result = double_columnar_decrypt(payload, k1, k2)  # type: ignore[arg-type]
        return (result, kind, axis_pos + 1)

    def _execute_affine(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute Affine cipher stage (brute-force a,b)."""
        if kind != "text":
            return None

        idx = param_idxs[axis_pos]
        # Decompose: iterate through charset modes, find which mode this idx falls in
        charset_mode = 0
        remaining = idx
        for mode_idx, combo_count in enumerate(N_AFFINE_COMBOS_BY_MODE):
            if remaining < combo_count:
                charset_mode = mode_idx
                break
            remaining -= combo_count

        valid_a = VALID_A_BY_MODE[charset_mode]
        mod = MOD_BY_MODE[charset_mode]
        a = valid_a[remaining // mod]
        b = remaining % mod

        charset_names = ["alpha", "alphanumeric", "all_printable"]
        meta["affine_a"] = a
        meta["affine_b"] = b
        meta["affine_charset"] = charset_names[charset_mode]
        result = affine_decrypt(payload, a, b, charset_mode)  # type: ignore[arg-type]
        return (result, kind, axis_pos + 1)

    def _execute_myszkowski(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute Myszkowski Transposition stage."""
        if kind != "text":
            return None

        ki_combined = param_idxs[axis_pos]
        key = self._get_effective_key(ki_combined)
        meta["myszkowski_key"] = key
        result = myszkowski_decrypt(payload, key)  # type: ignore[arg-type]
        return (result, kind, axis_pos + 1)

    def _execute_redefense(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute Redefense (keyed rail fence) stage."""
        if kind != "text":
            return None

        ki_combined = param_idxs[axis_pos]
        key = self._get_effective_key(ki_combined)
        meta["redefense_key"] = key
        result = redefense_decrypt(payload, key)  # type: ignore[arg-type]
        return (result, kind, axis_pos + 1)

    def _execute_xor(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute XOR cipher stage."""
        ki_combined = param_idxs[axis_pos]
        key = self._get_effective_key(ki_combined)
        meta["xor_key"] = key

        # Convert to bytes if needed
        if kind == "text":
            data = payload.encode("utf-8")  # type: ignore[union-attr]
        else:
            data = payload  # type: ignore[assignment]

        # Perform XOR
        xor_result = repeating_xor(data, key.encode("utf-8", "ignore"))

        # If fully printable, try to decode as text
        if printable_ratio(xor_result) == 1.0:
            try:
                return (xor_result.decode("ascii"), "text", axis_pos + 1)
            except (UnicodeDecodeError, AttributeError):
                return (xor_result, "bytes", axis_pos + 1)
        else:
            return (xor_result, "bytes", axis_pos + 1)

    _POLYALPHA_FNS = {
        "vigenere": vigenere_decrypt,
        "beaufort": beaufort_decrypt,
        "autokey": autokey_decrypt,
        "porta": porta_decrypt,
        "vigenere52": vigenere_decrypt,
        "beaufort52": beaufort_decrypt,
        "autokey52": autokey_decrypt,
        "porta52": porta_decrypt,
    }

    def _execute_polyalpha(
        self,
        stage: str,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute a polyalphabetic cipher stage (vigenere/beaufort/autokey/porta)."""
        if kind != "text":
            return None

        ki_combined = param_idxs[axis_pos]
        key = self._get_effective_key(ki_combined)
        base_name = stage.removesuffix("52")
        meta[f"{base_name}_key"] = key
        alpha52 = stage.endswith("52")

        fn = self._POLYALPHA_FNS[stage]
        result = fn(payload, key, alpha52=alpha52)  # type: ignore[arg-type]
        if result is None:
            return None
        return (result, kind, axis_pos + 1)

    def _execute_trithemius(
        self,
        stage: str,
        payload: str | bytes,
        kind: Kind,
        meta: Dict[str, Any],
        axis_pos: int,
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute Trithemius cipher stage (keyless)."""
        if kind != "text":
            return None
        alpha52 = stage.endswith("52")
        meta["trithemius_applied"] = True
        result = trithemius_decrypt(payload, alpha52=alpha52)  # type: ignore[arg-type]
        return (result, kind, axis_pos)

    def _execute_reverse(
        self,
        payload: str | bytes,
        kind: Kind,
        meta: Dict[str, Any],
        axis_pos: int,
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute Reverse cipher stage."""
        if kind != "text":
            return None

        meta["reverse_applied"] = True
        result = reverse_text(payload)  # type: ignore[arg-type]
        return (result, kind, axis_pos)

    def _execute_mcrypt(
        self,
        stage: str,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """
        Execute any mcrypt-based cipher stage.

        Requires bytes input (e.g. from b64 stage), or text that will be
        encoded to bytes.
        Decomposes param_idx into key index, derivation mode, and IV strategy
        based on the stage's registry info.
        """
        if kind == "text":
            try:
                payload = payload.encode("utf-8")  # type: ignore[union-attr]
            except (UnicodeEncodeError, AttributeError):
                return None
        elif kind != "bytes":
            return None

        info = get_stage_info(stage)
        if info is None:
            return None

        data = payload  # type: ignore[assignment]
        param_idx = param_idxs[axis_pos]

        # Decompose param_idx: ki * N_KEY_DERIVATION_MODES * N_KEY_PAD_STRATEGIES * N_IV_STRATEGIES
        iv_mult = N_IV_STRATEGIES if info.needs_iv else 1

        iv_idx = param_idx % iv_mult
        rest = param_idx // iv_mult

        key_pad_idx = rest % N_KEY_PAD_STRATEGIES
        rest = rest // N_KEY_PAD_STRATEGIES

        deriv_idx = rest % N_KEY_DERIVATION_MODES
        ki_combined = rest // N_KEY_DERIVATION_MODES

        key_str = self._get_effective_key(ki_combined)

        # Key derivation: transform dictionary word into key bytes
        key = derive_key(key_str, deriv_idx)

        # Truncate if longer than algorithm's max key size
        if len(key) > info.max_key_size:
            key = key[: info.max_key_size]

        # Key padding strategy:
        # 0 = null-padded: libmcrypt auto-pads short keys with \x00 to nearest valid size
        # 1 = zero-string-padded: pad with ASCII "0" (0x30) to nearest valid key size
        if key_pad_idx == KEY_PAD_ZERO_STRING:
            target_size = _nearest_valid_key_size(len(key), info)
            if len(key) < target_size:
                key = key + b"0" * (target_size - len(key))
            meta[f"{stage}_key_pad"] = "zero-string-padded"
        else:
            meta[f"{stage}_key_pad"] = "null-padded"

        # IV strategy
        iv: bytes | None = None
        iv_label = "none"
        if info.needs_iv:
            if iv_idx == IV_NULL:
                iv = b"\x00" * info.iv_size
                iv_label = "null"
            elif iv_idx == IV_ZERO_STRING:
                iv = b"0" * info.iv_size
                iv_label = "zero-string"
            elif iv_idx == IV_KEY_NULL_PAD:
                iv = key[: info.iv_size]
                if len(iv) < info.iv_size:
                    iv = iv + b"\x00" * (info.iv_size - len(iv))
                iv_label = "key-null-padded"
            elif iv_idx == IV_KEY_ZERO_STRING_PAD:
                iv = key[: info.iv_size]
                if len(iv) < info.iv_size:
                    iv = iv + b"0" * (info.iv_size - len(iv))
                iv_label = "key-zero-string-padded"
            elif iv_idx == IV_PREPENDED:
                if len(data) <= info.iv_size:
                    return None  # not enough data for IV + ciphertext
                iv = data[: info.iv_size]
                data = data[info.iv_size :]
                iv_label = "prepended"

        # Record metadata
        meta[f"{stage}_key"] = key_str
        meta[f"{stage}_deriv"] = DERIVATION_NAMES.get(deriv_idx, f"unknown-{deriv_idx}")
        meta[f"{stage}_iv"] = iv_label

        input_len = len(data)

        result = mcrypt_decrypt_stage(
            data, info.algo, info.mode, key, iv,
            handle_cache=self.handle_cache,
        )
        if result is None:
            return None

        # Stream-like modes (cfb, ofb, nofb, ctr) produce output matching
        # input length.  libmcrypt may pad the input to a block boundary,
        # creating extra garbage bytes — truncate them away.
        if info.mode in ("cfb", "ofb", "nofb", "ctr", "stream"):
            result = result[:input_len]

        # Try PKCS5/7 unpadding (common when encryption tool added padding)
        if info.is_block and len(result) > 0:
            pad_byte = result[-1]
            if 0 < pad_byte <= info.block_size and len(result) >= pad_byte:
                if result[-pad_byte:] == bytes([pad_byte]) * pad_byte:
                    result = result[:-pad_byte]

        # Strip trailing null bytes (zero-padding from libmcrypt)
        result = result.rstrip(b"\x00")

        # Strip trailing control characters (< 0x20) that commonly appear
        # as block cipher padding residue
        while result and result[-1] < 0x20:
            result = result[:-1]

        if not result:
            return None

        # If fully printable, try to decode as text
        if printable_ratio(result) == 1.0:
            try:
                return (result.decode("ascii"), "text", axis_pos + 1)
            except (UnicodeDecodeError, AttributeError):
                pass
        return (result, "bytes", axis_pos + 1)

    def _evaluate_result(
        self,
        payload: str | bytes,
        kind: Kind,
        meta: Dict[str, Any],
        threshold: float,
    ) -> tuple[float | None, Dict[str, Any] | None]:
        """
        Evaluate the final result against threshold.

        Returns:
            (score, metadata) if score >= threshold, else (None, None)
        """
        if kind == "bytes":
            score = combined_score(payload, self.common_words)  # type: ignore[arg-type]
            if score >= threshold:
                meta["preview"] = _plaintext_preview(payload)  # type: ignore[arg-type]
                return (score, meta)
        elif kind == "text":
            try:
                payload_bytes = payload.encode("utf-8")  # type: ignore[union-attr]
                score = combined_score(payload_bytes, self.common_words)
                if score >= threshold:
                    meta["preview"] = payload  # type: ignore[index]
                    return (score, meta)
            except Exception:
                return (None, None)

        return (None, None)
