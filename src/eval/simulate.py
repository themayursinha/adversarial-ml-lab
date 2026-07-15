"""CLI entrypoints for offline evaluation simulation runs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from src.eval.contract import EvaluationContractError
from src.eval.simulation import run_simulation_evaluation
from src.services.evaluator import default_evaluation_dataset


def run_simulate(
    dataset_path: Path | None,
    *,
    suite_name: str | None = None,
    check_packaged_parity: bool = True,
    include_case_results: bool = False,
) -> dict[str, Any]:
    """Run the simulation pipeline on a dataset path or the packaged baseline."""
    if dataset_path is None:
        with default_evaluation_dataset() as packaged:
            return run_simulation_evaluation(
                packaged,
                suite_name=suite_name or "baseline",
                check_packaged_parity=check_packaged_parity,
                include_case_results=include_case_results,
            )
    return run_simulation_evaluation(
        Path(dataset_path),
        suite_name=suite_name,
        check_packaged_parity=check_packaged_parity,
        include_case_results=include_case_results,
    )


def build_simulate_parser(prog: str | None = None) -> argparse.ArgumentParser:
    """Build an argparse parser for offline simulation runs."""
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Run the evaluation harness in simulation mode (no LLM API). "
            "Validates the dataset against the frozen contract, executes cases, "
            "and emits a JSON report with schema-checked provenance."
        ),
    )
    parser.add_argument(
        "dataset",
        nargs="?",
        help="Path to evaluation JSONL (default: packaged baseline).",
    )
    parser.add_argument(
        "--dataset",
        dest="dataset_opt",
        help="Path to evaluation JSONL (alternative to positional).",
    )
    parser.add_argument(
        "--suite",
        default=None,
        help="Suite name for reporting (default: manifest suite_name or dataset stem).",
    )
    parser.add_argument(
        "--show-cases",
        action="store_true",
        help="Include per-case results in the JSON report.",
    )
    parser.add_argument(
        "--no-packaged-parity",
        action="store_true",
        help="Skip packaged_resource byte parity check for governed datasets.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reserved for parity with other CLIs (report always goes to stdout).",
    )
    return parser


def run_simulate_command(args: argparse.Namespace) -> int:
    """argparse handler: run simulation and print JSON report to stdout."""
    dataset_arg = args.dataset_opt or args.dataset
    dataset_path = Path(dataset_arg) if dataset_arg else None
    if dataset_path is not None and not dataset_path.is_file():
        print(f"error: dataset not found: {dataset_path}", file=sys.stderr)
        return 1

    try:
        report = run_simulate(
            dataset_path,
            suite_name=args.suite,
            check_packaged_parity=not args.no_packaged_parity,
            include_case_results=args.show_cases,
        )
    except EvaluationContractError as exc:
        print(f"simulation failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Standalone CLI entrypoint."""
    parser = build_simulate_parser(prog="simulate")
    args = parser.parse_args(argv)
    return run_simulate_command(args)


if __name__ == "__main__":
    raise SystemExit(main())
