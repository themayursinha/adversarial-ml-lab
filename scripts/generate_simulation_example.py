#!/usr/bin/env python3
"""Write evals/examples/baseline_simulation_report.json from the live simulation pipeline."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from src.eval.simulate import run_simulate  # noqa: E402
from src.eval.simulation import stable_simulation_snapshot  # noqa: E402

OUT = REPO / "evals/examples/baseline_simulation_report.json"


def main() -> None:
    report = run_simulate(None, suite_name="baseline", include_case_results=False)
    snapshot = stable_simulation_snapshot(report)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
