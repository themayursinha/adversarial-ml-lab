"""Run the deterministic regression gate (board t_8fd3d263).

Exit codes: 0 = PASS, 1 = FAIL, 2 = configuration error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.eval.digest import compute_dataset_file_digest  # noqa: E402
from src.eval.regression import (  # noqa: E402
    RegressionGateError,
    build_baseline_snapshot,
    run_regression_gate,
    write_gate_artifacts,
)

DEFAULT_DATASET = REPO_ROOT / "evals/datasets/baseline_v2.jsonl"
DEFAULT_THRESHOLDS = REPO_ROOT / "evals/thresholds/baseline_v2.thresholds.json"
DEFAULT_BASELINE = REPO_ROOT / "evals/examples/baseline_v2_regression_baseline.json"
DEFAULT_OUT = REPO_ROOT / "evals/examples/regression_gate_artifacts"


def build_parser() -> argparse.ArgumentParser:
    """Build the regression gate CLI parser."""
    parser = argparse.ArgumentParser(
        prog="regression_gate",
        description=(
            "Run the simulation pipeline on a governed dataset and enforce a reviewed "
            "threshold policy. Fails closed on threshold violations, per-case outcome "
            "drift, or dataset/policy digest mismatches."
        ),
    )
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--thresholds", default=str(DEFAULT_THRESHOLDS))
    parser.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Write/refresh the per-case baseline snapshot (a reviewed change).",
    )
    parser.add_argument("--suite", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: run the gate, emit artifacts, and report the decision."""
    args = build_parser().parse_args(argv)
    dataset_path = Path(args.dataset)
    thresholds_path = Path(args.thresholds)
    baseline_path = Path(args.baseline)
    out_dir = Path(args.out_dir)

    try:
        # When regenerating the snapshot, a stale snapshot must not block the run.
        use_snapshot = baseline_path.is_file() and not args.write_baseline
        gate = run_regression_gate(
            dataset_path,
            thresholds_path,
            baseline_path if use_snapshot else None,
            suite_name=args.suite,
        )
    except RegressionGateError as exc:
        print(f"regression gate configuration error: {exc}", file=sys.stderr)
        return 2

    write_gate_artifacts(gate, out_dir)
    if args.write_baseline:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps(build_baseline_snapshot(gate), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    failures = gate["threshold_results"]["failures"]
    print(f"decision: {gate['decision']}")
    print(f"dataset: {gate['dataset_filename']} digest {gate['dataset_digest_sha256'][:12]}…")
    print(f"cases: {gate['case_count']}; failing metrics: {len(failures)}")
    for failure in failures:
        print(f"  FAIL {failure}")
    diff = gate["case_diff"]
    print(
        f"case diff vs baseline: changed={len(diff['changed'])} "
        f"added={len(diff['added'])} removed={len(diff['removed'])}"
    )
    for case_id in sorted(diff["changed"]):
        print(f"  CHANGED {case_id}")
    print(f"artifacts: {out_dir}")
    return 0 if gate["decision"] == "PASS" else 1


def dataset_digest(path: str | Path) -> str:
    """Helper for policy authors: raw dataset digest."""
    return compute_dataset_file_digest(Path(path))


if __name__ == "__main__":
    raise SystemExit(main())
