"""
Stage execution logic.

This module contains the core logic for executing individual cipher stages
and evaluating results against the scoring threshold.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Literal

from stages.bifid import bifid_decrypt
from stages.caesar import caesar_shift_text
from stages.columnar import columnar_decrypt
from stages.common import combined_score, printable_ratio
from stages.double_columnar import double_columnar_decrypt
from stages.railfence import railfence_decrypt
from stages.reverse import reverse_text
from stages.xor import repeating_xor

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
    ):
        """
        Initialize the stage executor.

        Args:
            ciphertext: Input ciphertext
            keys: Dictionary of keys
            stages: List of stage names
            bifid_alphabet: Alphabet for bifid cipher
            common_words: Common words for English scoring
        """
        self.ciphertext = ciphertext
        self.keys = keys
        self.stages = stages
        self.bifid_alphabet = bifid_alphabet
        self.common_words = common_words

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

        ki = param_idxs[axis_pos]
        key = self.keys[ki]
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

        ki = param_idxs[axis_pos]
        key = self.keys[ki]
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
        n = len(self.keys)
        k1 = self.keys[pi // n]
        k2 = self.keys[pi % n]
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
        ki = param_idxs[axis_pos]
        key = self.keys[ki]
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
