#!/usr/bin/env python3
"""Validate evaluation JSONL datasets against the frozen contract (fail-closed)."""

from __future__ import annotations

from src.eval.validate import main

if __name__ == "__main__":
    raise SystemExit(main())
