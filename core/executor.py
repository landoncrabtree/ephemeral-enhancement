"""
Stage execution logic.

This module contains the core logic for executing individual cipher stages
and evaluating results against the scoring threshold.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Literal

from stages.aes_cbc import N_IV_MODES, aes_cbc_decrypt
from stages.aes_ecb import aes_ecb_decrypt
from stages.bifid import bifid_decrypt
from stages.caesar import caesar_shift_text
from stages.columnar import columnar_decrypt
from stages.common import combined_score, printable_ratio
from stages.des_cbc import N_IV_MODES as DES_CBC_IV_MODES, des_cbc_decrypt
from stages.des_ecb import des_ecb_decrypt
from stages.des3 import des3_decrypt
from stages.double_columnar import double_columnar_decrypt
from stages.key_derivation import N_KEY_DERIVATION_MODES, derive_key
from stages.railfence import railfence_decrypt
from stages.rc4 import rc4_decrypt
from stages.reverse import reverse_text
from stages.xor import repeating_xor
from stages.xtea import xtea_decrypt

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
        """
        self.ciphertext = ciphertext
        self.keys = keys
        self.stages = stages
        self.bifid_alphabet = bifid_alphabet
        self.common_words = common_words
        self.vary_case = vary_case

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

        elif stage == "xor":
            return self._execute_xor(payload, kind, param_idxs, axis_pos, meta)

        elif stage == "reverse":
            return self._execute_reverse(payload, kind, meta, axis_pos)

        elif stage == "rc4":
            return self._execute_rc4(payload, kind, param_idxs, axis_pos, meta)
        elif stage == "aes_ecb":
            return self._execute_aes_ecb(
                payload, kind, param_idxs, axis_pos, meta
            )
        elif stage == "aes_cbc":
            return self._execute_aes_cbc(
                payload, kind, param_idxs, axis_pos, meta
            )
        elif stage == "des_ecb":
            return self._execute_des_ecb(
                payload, kind, param_idxs, axis_pos, meta
            )
        elif stage == "des_cbc":
            return self._execute_des_cbc(
                payload, kind, param_idxs, axis_pos, meta
            )
        elif stage == "des3":
            return self._execute_des3(
                payload, kind, param_idxs, axis_pos, meta
            )
        elif stage == "xtea":
            return self._execute_xtea(
                payload, kind, param_idxs, axis_pos, meta
            )

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

        shift = param_idxs[axis_pos]
        meta["caesar_shift"] = shift
        result = caesar_shift_text(payload, shift)  # type: ignore[arg-type]
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

    def _execute_rc4(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute RC4 stage. Requires bytes input (e.g. from b64)."""
        if kind != "bytes":
            return None
        data = payload  # type: ignore[assignment]
        param_idx = param_idxs[axis_pos]
        ki_combined = param_idx // N_KEY_DERIVATION_MODES
        deriv_idx = param_idx % N_KEY_DERIVATION_MODES
        key_str = self._get_effective_key(ki_combined)
        key = derive_key(key_str, deriv_idx)
        meta["rc4_key"] = key_str
        meta["rc4_deriv"] = deriv_idx
        try:
            result = rc4_decrypt(data, key)
        except Exception:
            return None
        if printable_ratio(result) == 1.0:
            try:
                return (result.decode("ascii"), "text", axis_pos + 1)
            except (UnicodeDecodeError, AttributeError):
                pass
        return (result, "bytes", axis_pos + 1)

    def _execute_aes_ecb(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute AES-ECB stage. Requires bytes input (e.g. from b64)."""
        if kind != "bytes":
            return None
        data = payload  # type: ignore[assignment]
        param_idx = param_idxs[axis_pos]
        padding_idx = param_idx % 2
        rest = param_idx // 2
        deriv_idx = rest % N_KEY_DERIVATION_MODES
        ki_combined = rest // N_KEY_DERIVATION_MODES
        key_str = self._get_effective_key(ki_combined)
        key = derive_key(key_str, deriv_idx, size=16)
        padding: str = "pkcs7" if padding_idx == 0 else "nopadding"
        meta["aes_ecb_key"] = key_str
        meta["aes_ecb_deriv"] = deriv_idx
        meta["aes_ecb_padding"] = padding
        result = aes_ecb_decrypt(data, key, padding=padding)
        if result is None:
            return None
        if printable_ratio(result) == 1.0:
            try:
                return (result.decode("ascii"), "text", axis_pos + 1)
            except (UnicodeDecodeError, AttributeError):
                pass
        return (result, "bytes", axis_pos + 1)

    def _execute_aes_cbc(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute AES-CBC stage. Requires bytes input (e.g. from b64)."""
        if kind != "bytes":
            return None
        data = payload  # type: ignore[assignment]
        param_idx = param_idxs[axis_pos]
        padding_idx = param_idx % 2
        rest = param_idx // 2
        iv_idx = rest % N_IV_MODES
        rest = rest // N_IV_MODES
        deriv_idx = rest % N_KEY_DERIVATION_MODES
        ki_combined = rest // N_KEY_DERIVATION_MODES
        key_str = self._get_effective_key(ki_combined)
        key = derive_key(key_str, deriv_idx, size=16)
        padding = "pkcs7" if padding_idx == 0 else "nopadding"
        meta["aes_cbc_key"] = key_str
        meta["aes_cbc_deriv"] = deriv_idx
        meta["aes_cbc_iv_mode"] = iv_idx
        meta["aes_cbc_padding"] = padding
        result = aes_cbc_decrypt(data, key, iv_idx, padding=padding)
        if result is None:
            return None
        if printable_ratio(result) == 1.0:
            try:
                return (result.decode("ascii"), "text", axis_pos + 1)
            except (UnicodeDecodeError, AttributeError):
                pass
        return (result, "bytes", axis_pos + 1)

    def _execute_des_ecb(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute DES-ECB stage. Requires bytes input (e.g. from b64)."""
        if kind != "bytes":
            return None
        data = payload  # type: ignore[assignment]
        param_idx = param_idxs[axis_pos]
        padding_idx = param_idx % 2
        rest = param_idx // 2
        deriv_idx = rest % N_KEY_DERIVATION_MODES
        ki_combined = rest // N_KEY_DERIVATION_MODES
        key_str = self._get_effective_key(ki_combined)
        key = derive_key(key_str, deriv_idx, size=8)
        padding = "pkcs7" if padding_idx == 0 else "nopadding"
        meta["des_ecb_key"] = key_str
        meta["des_ecb_deriv"] = deriv_idx
        meta["des_ecb_padding"] = padding
        result = des_ecb_decrypt(data, key, padding=padding)
        if result is None:
            return None
        if printable_ratio(result) == 1.0:
            try:
                return (result.decode("ascii"), "text", axis_pos + 1)
            except (UnicodeDecodeError, AttributeError):
                pass
        return (result, "bytes", axis_pos + 1)

    def _execute_des_cbc(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute DES-CBC stage. Requires bytes input (e.g. from b64)."""
        if kind != "bytes":
            return None
        data = payload  # type: ignore[assignment]
        param_idx = param_idxs[axis_pos]
        padding_idx = param_idx % 2
        rest = param_idx // 2
        iv_idx = rest % DES_CBC_IV_MODES
        rest = rest // DES_CBC_IV_MODES
        deriv_idx = rest % N_KEY_DERIVATION_MODES
        ki_combined = rest // N_KEY_DERIVATION_MODES
        key_str = self._get_effective_key(ki_combined)
        key = derive_key(key_str, deriv_idx, size=8)
        padding = "pkcs7" if padding_idx == 0 else "nopadding"
        meta["des_cbc_key"] = key_str
        meta["des_cbc_deriv"] = deriv_idx
        meta["des_cbc_iv_mode"] = iv_idx
        meta["des_cbc_padding"] = padding
        result = des_cbc_decrypt(data, key, iv_idx, padding=padding)
        if result is None:
            return None
        if printable_ratio(result) == 1.0:
            try:
                return (result.decode("ascii"), "text", axis_pos + 1)
            except (UnicodeDecodeError, AttributeError):
                pass
        return (result, "bytes", axis_pos + 1)

    def _execute_des3(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute 3DES stage. Requires bytes input (e.g. from b64)."""
        if kind != "bytes":
            return None
        data = payload  # type: ignore[assignment]
        param_idx = param_idxs[axis_pos]
        ki_combined = param_idx // N_KEY_DERIVATION_MODES
        deriv_idx = param_idx % N_KEY_DERIVATION_MODES
        key_str = self._get_effective_key(ki_combined)
        key = derive_key(key_str, deriv_idx, size=16)
        meta["des3_key"] = key_str
        meta["des3_deriv"] = deriv_idx
        result = des3_decrypt(data, key)
        if result is None:
            return None
        if printable_ratio(result) == 1.0:
            try:
                return (result.decode("ascii"), "text", axis_pos + 1)
            except (UnicodeDecodeError, AttributeError):
                pass
        return (result, "bytes", axis_pos + 1)

    def _execute_xtea(
        self,
        payload: str | bytes,
        kind: Kind,
        param_idxs: list[int],
        axis_pos: int,
        meta: Dict[str, Any],
    ) -> tuple[str | bytes, Kind, int] | None:
        """Execute XTEA stage. Requires bytes input (e.g. from b64)."""
        if kind != "bytes":
            return None
        data = payload  # type: ignore[assignment]
        param_idx = param_idxs[axis_pos]
        ki_combined = param_idx // N_KEY_DERIVATION_MODES
        deriv_idx = param_idx % N_KEY_DERIVATION_MODES
        key_str = self._get_effective_key(ki_combined)
        key = derive_key(key_str, deriv_idx, size=16)
        meta["xtea_key"] = key_str
        meta["xtea_deriv"] = deriv_idx
        result = xtea_decrypt(data, key)
        if result is None:
            return None
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
