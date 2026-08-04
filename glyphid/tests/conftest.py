"""Pytest configuration for the standalone glyphid component.

``glyphid`` is self-contained: its tests are excluded from the main cipher suite (which
pins ``testpaths = tests``) and are run on their own with::

    python -m pytest glyphid/tests
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
