"""CLI entrypoints for fail-closed evaluation JSONL validation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from src.eval.contract import EvaluationContractError, load_dataset_manifest
from src.eval.validator import validate_dataset


def run_validate(
    dataset_path: Path,
    *,
    manifest_path: Path | None = None,
    check_packaged_parity: bool = True,
) -> dict[str, Any] | None:
    """
    Validate a JSONL evaluation dataset against the frozen schema and manifest rules.

    Raises EvaluationContractError on any malformed row, schema violation, duplicate id,
    family/ordering mismatch, or digest failure.
    """
    manifest: dict[str, Any] | None = None
    if manifest_path is not None:
        manifest = load_dataset_manifest(manifest_path)
    return validate_dataset(
        dataset_path,
        manifest,
        check_packaged_parity=check_packaged_parity,
    )


def build_validate_parser(prog: str | None = None) -> argparse.ArgumentParser:
    """Build an argparse parser for dataset validation."""
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Validate an evaluation JSONL file against evaluation_case.v1 and an optional "
            "manifest (unique case_ids, required fields, family_counts, ordering). "
            "Exits non-zero on the first contract violation."
        ),
    )
    parser.add_argument(
        "dataset",
        nargs="?",
        help="Path to the evaluation JSONL dataset.",
    )
    parser.add_argument(
        "--dataset",
        dest="dataset_opt",
        help="Path to the evaluation JSONL dataset (alternative to positional).",
    )
    parser.add_argument(
        "--manifest",
        help="Path to evaluation_manifest.v1 JSON (default: sibling .manifest.json or digest match).",
    )
    parser.add_argument(
        "--no-packaged-parity",
        action="store_true",
        help="Skip byte-for-byte check against packaged_resource in the manifest.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="On success, print a short JSON summary to stdout.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress success message on stdout.",
    )
    return parser


def run_validate_command(args: argparse.Namespace) -> int:
    """argparse handler: validate dataset and map contract errors to exit code 1."""
    dataset_arg = args.dataset_opt or args.dataset
    if not dataset_arg:
        print("error: dataset path is required", file=sys.stderr)
        return 1

    dataset_path = Path(dataset_arg)
    if not dataset_path.is_file():
        print(f"error: dataset not found: {dataset_path}", file=sys.stderr)
        return 1

    manifest_path = Path(args.manifest) if args.manifest else None
    if manifest_path is not None and not manifest_path.is_file():
        print(f"error: manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    try:
        manifest = run_validate(
            dataset_path,
            manifest_path=manifest_path,
            check_packaged_parity=not args.no_packaged_parity,
        )
    except EvaluationContractError as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        summary: dict[str, Any] = {
            "status": "ok",
            "dataset": str(dataset_path.resolve()),
            "governed": manifest is not None,
        }
        if manifest is not None:
            summary["case_count"] = manifest.get("case_count")
            summary["suite_name"] = manifest.get("suite_name")
            summary["content_digest_sha256"] = manifest.get("content_digest_sha256")
        print(json.dumps(summary, indent=2))
    elif not args.quiet:
        if manifest is not None:
            print(
                f"ok: {dataset_path.name} "
                f"({manifest.get('case_count')} cases, manifest {manifest.get('suite_name')!r})"
            )
        else:
            print(f"ok: {dataset_path.name} (schema + unique case_ids)")

    return 0


def main(argv: list[str] | None = None) -> int:
    """Standalone CLI entrypoint (scripts/validate.py and python -m)."""
    parser = build_validate_parser(prog="validate")
    args = parser.parse_args(argv)
    return run_validate_command(args)


if __name__ == "__main__":
    raise SystemExit(main())
