#!/usr/bin/env python3
"""Validate evaluation JSONL datasets against the frozen contract (fail-closed)."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.eval.validate import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
