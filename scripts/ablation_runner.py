"""Run the defense ablation harness and write the report (board t_145d47d5)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.eval.ablation import AblationError, run_ablation  # noqa: E402

DEFAULT_DATASET = REPO_ROOT / "evals/datasets/baseline_v2.jsonl"
DEFAULT_OUT = REPO_ROOT / "evals/examples/baseline_v2_ablation_report.json"


def main(argv: list[str] | None = None) -> int:
    """Run the ablation grid and write the deterministic report."""
    parser = argparse.ArgumentParser(
        prog="ablation_runner",
        description=(
            "Measure per-control contribution (canonicalization, filter, anomaly, "
            "uncertainty, isolation, redaction) over a governed dataset in simulation "
            "mode. Simulation-only; no production-efficacy claims."
        ),
    )
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)

    try:
        report = run_ablation(Path(args.dataset))
    except AblationError as exc:
        print(f"ablation failed: {exc}", file=sys.stderr)
        return 2

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for name, entry in sorted(report["configs"].items()):
        blocked = entry["blocked_rates"]
        print(
            f"{name:28s} miss={_fmt(blocked['miss_rate'])} "
            f"fp={_fmt(blocked['false_block_rate'])} pass={_fmt(blocked['pass_rate'])}"
        )
    print(f"report: {out_path}")
    return 0


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"


if __name__ == "__main__":
    raise SystemExit(main())
