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
from stages.key_derivation import N_KEY_DERIVATION_MODES, derive_key
from stages.mcrypt_registry import (
    N_KEY_PAD_STRATEGIES,
    get_stage_info,
    is_mcrypt_stage,
)
from stages.mcrypt_stage import mcrypt_decrypt_stage
from stages.mcrypt_wrapper import McryptHandleCache
from stages.myszkowski import myszkowski_decrypt
from stages.railfence import railfence_decrypt
from stages.redefense import redefense_decrypt
from stages.reverse import reverse_text
from stages.xor import repeating_xor

from .utils import N_CASE_VARIANTS, apply_case_variant

Kind = Literal["text", "bytes"]


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

        elif stage == "reverse":
            return self._execute_reverse(payload, kind, meta, axis_pos)

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
            decoded = base64.b64decode(payload, validate=False)
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

        idx = param_idxs[axis_pos]
        charset_mode = idx // 26
        shift = idx % 26
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

        Requires bytes input (e.g. from b64 stage).
        Decomposes param_idx into key index, derivation mode, and IV strategy
        based on the stage's registry info.
        """
        if kind != "bytes":
            return None

        info = get_stage_info(stage)
        if info is None:
            return None

        data = payload  # type: ignore[assignment]
        param_idx = param_idxs[axis_pos]

        # Decompose param_idx: ki_combined * N_KEY_DERIVATION_MODES * N_KEY_PAD_STRATEGIES
        key_pad_idx = param_idx % N_KEY_PAD_STRATEGIES
        rest = param_idx // N_KEY_PAD_STRATEGIES

        deriv_idx = rest % N_KEY_DERIVATION_MODES
        ki_combined = rest // N_KEY_DERIVATION_MODES

        key_str = self._get_effective_key(ki_combined)

        # Key padding strategy:
        # 0 = as-is: derive key without forcing size, only truncate if > max
        # 1 = zero-pad: derive and force to exactly max_key_size
        if key_pad_idx == 1:
            key = derive_key(key_str, deriv_idx, size=info.max_key_size)
        else:
            key = derive_key(key_str, deriv_idx)
            if len(key) > info.max_key_size:
                key = key[: info.max_key_size]

        # IV always derived from key (zero-padded/truncated to iv_size)
        iv: bytes | None = None
        if info.needs_iv:
            iv = key[: info.iv_size]
            if len(iv) < info.iv_size:
                iv = iv + b"\x00" * (info.iv_size - len(iv))

        # Record metadata
        meta[f"{stage}_key"] = key_str
        meta[f"{stage}_deriv"] = deriv_idx
        meta[f"{stage}_key_pad"] = "zero-pad" if key_pad_idx == 1 else "as-is"

        result = mcrypt_decrypt_stage(
            data, info.algo, info.mode, key, iv,
            handle_cache=self.handle_cache,
        )
        if result is None:
            return None

        # Try PKCS5/7 unpadding (common when encryption tool added padding)
        if info.is_block and len(result) > 0:
            pad_byte = result[-1]
            if 0 < pad_byte <= info.block_size and len(result) >= pad_byte:
                if result[-pad_byte:] == bytes([pad_byte]) * pad_byte:
                    result = result[:-pad_byte]

        # Strip trailing null bytes (zero-padding from PHP mcrypt)
        result = result.rstrip(b"\x00")

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
                return (score, meta)
        elif kind == "text":
            try:
                payload_bytes = payload.encode("utf-8")  # type: ignore[union-attr]
                score = combined_score(payload_bytes, self.common_words)
                if score >= threshold:
                    return (score, meta)
            except Exception:
                return (None, None)

        return (None, None)
