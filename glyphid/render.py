"""Render reference text with a TrueType font at controllable metrics.

Glyphs are rasterised once per (character, size) on a supersampled grid and then
composited at explicit sub-pixel pen positions, so size, tracking, origin and baseline
are all free continuous parameters. The supersampled canvas is finally box-filtered
down, which approximates exact area coverage and is therefore directly comparable to
the linear-coverage antialiasing used by the original authoring tool.
"""

from __future__ import annotations

import functools

import numpy as np
from fontTools.pens.areaPen import AreaPen
from fontTools.pens.boundsPen import BoundsPen
from fontTools.ttLib import TTFont
from PIL import Image, ImageDraw, ImageFont

SUPERSAMPLE = 8


class FontRenderer:
    """Rasterises glyphs and whole lines for a given TrueType face."""

    def __init__(self, path: str, supersample: int = SUPERSAMPLE):
        self.path = path
        self.supersample = supersample
        self._tt = TTFont(path, lazy=True)
        self._glyph_set = self._tt.getGlyphSet()
        self._upem = self._tt["head"].unitsPerEm
        self._cmap = self._tt.getBestCmap()
        self._hmtx = self._tt["hmtx"]
        self._stamps: dict[tuple[str, int], tuple[np.ndarray, int, int]] = {}

    # ------------------------------------------------------------------ metrics

    @property
    def units_per_em(self) -> int:
        return self._upem

    def has_glyph(self, char: str) -> bool:
        return ord(char) in self._cmap

    def glyph_name(self, char: str) -> str | None:
        return self._cmap.get(ord(char))

    def advance_units(self, char: str) -> float:
        name = self.glyph_name(char)
        return 0.0 if name is None else float(self._hmtx[name][0])

    @functools.lru_cache(maxsize=512)
    def ink_bounds_units(self, char: str) -> tuple[float, float, float, float] | None:
        """(xMin, yMin, xMax, yMax) of the glyph outline, in font units."""
        name = self.glyph_name(char)
        if name is None:
            return None
        pen = BoundsPen(self._glyph_set)
        self._glyph_set[name].draw(pen)
        return pen.bounds

    @functools.lru_cache(maxsize=512)
    def ink_area_units(self, char: str) -> float:
        """Signed-area magnitude of the glyph outline, in square font units."""
        name = self.glyph_name(char)
        if name is None:
            return 0.0
        pen = AreaPen(self._glyph_set)
        self._glyph_set[name].draw(pen)
        return abs(pen.value)

    def advance_px(self, char: str, size_px: float) -> float:
        return self.advance_units(char) * size_px / self._upem

    def ink_size_px(self, char: str, size_px: float) -> tuple[float, float]:
        """(width, height) of the glyph's ink box in pixels at ``size_px``."""
        bounds = self.ink_bounds_units(char)
        if bounds is None:
            return (0.0, 0.0)
        scale = size_px / self._upem
        return ((bounds[2] - bounds[0]) * scale, (bounds[3] - bounds[1]) * scale)

    def ink_area_px(self, char: str, size_px: float) -> float:
        return self.ink_area_units(char) * (size_px / self._upem) ** 2

    # ------------------------------------------------------------------ layout

    def pen_positions(
        self, text: str, size_px: float, tracking_px: float, x0: float
    ) -> list[float]:
        """Left origin of every glyph in ``text``."""
        positions: list[float] = []
        pen = x0
        for char in text:
            positions.append(pen)
            pen += self.advance_px(char, size_px) + tracking_px
        return positions

    def advance_total(self, text: str, size_px: float, tracking_px: float) -> float:
        """Total advance of ``text``, including tracking after the last glyph."""
        return sum(self.advance_px(c, size_px) + tracking_px for c in text)

    # ------------------------------------------------------------- rasterising

    @functools.lru_cache(maxsize=64)
    def _pil_font(self, pixel_size: int) -> ImageFont.FreeTypeFont:
        return ImageFont.truetype(self.path, pixel_size)

    def _stamp(self, char: str, size_key: int) -> tuple[np.ndarray, int, int]:
        """Supersampled glyph bitmap plus its offset from the (pen, baseline) origin."""
        cached = self._stamps.get((char, size_key))
        if cached is not None:
            return cached
        font = self._pil_font(size_key)
        left, top, right, bottom = font.getbbox(char, anchor="ls")
        width, height = max(1, right - left), max(1, bottom - top)
        tile = Image.new("L", (width, height), 0)
        ImageDraw.Draw(tile).text((-left, -top), char, font=font, fill=255, anchor="ls")
        cached = (np.asarray(tile, dtype=np.uint8), int(left), int(top))
        self._stamps[(char, size_key)] = cached
        return cached

    def _composite(
        self,
        chars: list[str],
        pens: list[float],
        size_px: float,
        baseline_y: float,
        width: int,
        height: int,
    ) -> np.ndarray:
        scale = self.supersample
        width, height = max(1, int(width)), max(1, int(height))
        size_key = int(round(size_px * scale))
        canvas = np.zeros((height * scale, width * scale), dtype=np.uint8)
        base = int(round(baseline_y * scale))
        for char, pen in zip(chars, pens):
            if char == " " or not self.has_glyph(char):
                continue
            bitmap, left, top = self._stamp(char, size_key)
            y0 = base + top
            x0 = int(round(pen * scale)) + left
            y1, x1 = y0 + bitmap.shape[0], x0 + bitmap.shape[1]
            src_y, src_x = max(0, -y0), max(0, -x0)
            y0, x0 = max(0, y0), max(0, x0)
            y1, x1 = min(canvas.shape[0], y1), min(canvas.shape[1], x1)
            if y1 <= y0 or x1 <= x0:
                continue
            patch = bitmap[src_y : src_y + (y1 - y0), src_x : src_x + (x1 - x0)]
            np.maximum(canvas[y0:y1, x0:x1], patch, out=canvas[y0:y1, x0:x1])
        block = canvas.reshape(height, scale, width, scale)
        return block.mean(axis=(1, 3), dtype=np.float32) / 255.0

    def render_line(
        self,
        text: str,
        size_px: float,
        tracking_px: float,
        x0: float,
        baseline_y: float,
        width: int,
        height: int,
    ) -> np.ndarray:
        """Rasterise ``text`` into a ``height`` x ``width`` coverage map in 0..1."""
        pens = self.pen_positions(text, size_px, tracking_px, x0)
        return self._composite(list(text), pens, size_px, baseline_y, width, height)

    def render_placed(
        self,
        chars: list[str],
        pens: list[float],
        size_px: float,
        baseline_y: float,
        width: int,
        height: int,
    ) -> np.ndarray:
        """Rasterise glyphs at explicit per-glyph pen positions."""
        return self._composite(chars, pens, size_px, baseline_y, width, height)

    def render_glyph(self, char: str, size_px: float, pad: int = 6) -> np.ndarray:
        """Rasterise one glyph with padding, returning a coverage map in 0..1."""
        width_px, height_px = self.ink_size_px(char, size_px)
        width = int(width_px) + 2 * pad + 2
        height = int(height_px) + 2 * pad + 2
        bounds = self.ink_bounds_units(char)
        left_bearing = 0.0 if bounds is None else bounds[0] * size_px / self._upem
        descent = 0.0 if bounds is None else bounds[1] * size_px / self._upem
        return self._composite(
            [char],
            [pad - left_bearing],
            size_px,
            height - pad + descent,
            width,
            height,
        )
