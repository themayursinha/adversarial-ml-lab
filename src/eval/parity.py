"""Source/package parity and baseline gate checks for evaluation datasets."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.eval.contract import (
    EvaluationContractError,
    compute_dataset_digest,
    load_dataset_manifest,
)
from src.eval.validator import validate_dataset


@dataclass(frozen=True)
class BaselineLocations:
    """Repo paths for the canonical baseline source and packaged copies."""

    source_jsonl: Path
    source_manifest: Path
    packaged_jsonl: Path
    packaged_manifest: Path


def default_baseline_locations(repo_root: Path | None = None) -> BaselineLocations:
    root = repo_root or Path(__file__).resolve().parents[2]
    return BaselineLocations(
        source_jsonl=root / "evals/datasets/baseline.jsonl",
        source_manifest=root / "evals/datasets/baseline.manifest.json",
        packaged_jsonl=root / "src/resources/datasets/baseline.jsonl",
        packaged_manifest=root / "src/resources/datasets/baseline.manifest.json",
    )


def extract_ordered_case_ids(dataset_path: Path) -> list[str]:
    """Return case_id values in JSONL row order (no blank lines allowed)."""
    case_ids: list[str] = []
    with dataset_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                raise EvaluationContractError(f"line {line_number}: empty line is not allowed")
            row = json.loads(stripped)
            if not isinstance(row, dict) or "case_id" not in row:
                raise EvaluationContractError(
                    f"line {line_number}: row must be an object with case_id"
                )
            case_ids.append(str(row["case_id"]))
    return case_ids


def assert_case_id_ordering_matches_manifest(
    dataset_path: Path,
    manifest: dict[str, Any],
) -> None:
    """Fail closed when JSONL row order diverges from manifest.case_ids."""
    expected = manifest.get("case_ids")
    if not isinstance(expected, list):
        raise EvaluationContractError("manifest case_ids must be a list")
    observed = extract_ordered_case_ids(dataset_path)
    if observed != list(expected):
        raise EvaluationContractError("case_id ordering does not match manifest")


def assert_manifest_digest_matches_dataset(
    dataset_path: Path,
    manifest: dict[str, Any],
) -> None:
    """Fail closed when manifest digest does not match dataset bytes."""
    expected = manifest.get("content_digest_sha256")
    if not isinstance(expected, str):
        raise EvaluationContractError("manifest content_digest_sha256 must be a string")
    digest = compute_dataset_digest(dataset_path)
    if digest != expected:
        raise EvaluationContractError(
            f"dataset digest mismatch: expected {expected}, got {digest}"
        )


def assert_manifest_documents_equal(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    left_label: str = "source",
    right_label: str = "packaged",
) -> None:
    """Fail closed when two manifest documents differ."""
    if left == right:
        return
    keys = sorted(set(left) | set(right))
    diffs: list[str] = []
    for key in keys:
        lv, rv = left.get(key), right.get(key)
        if lv != rv:
            diffs.append(f"{key}: {left_label}={lv!r} {right_label}={rv!r}")
    detail = "; ".join(diffs) if diffs else "manifest objects differ"
    raise EvaluationContractError(f"manifest mismatch between {left_label} and {right_label}: {detail}")


def assert_dataset_bytes_equal(left: Path, right: Path) -> None:
    """Fail closed when two dataset files are not byte-identical."""
    lb, rb = left.read_bytes(), right.read_bytes()
    if lb != rb:
        raise EvaluationContractError(
            f"dataset bytes differ: {left} ({len(lb)} bytes) vs {right} ({len(rb)} bytes)"
        )


def check_baseline_pair(
    locations: BaselineLocations,
    *,
    check_packaged_parity: bool = True,
) -> dict[str, Any]:
    """
    Run source/package parity and ordering gate checks for the baseline copies.

    Validates each JSONL against its manifest (schema, digest, families, ordering),
    ensures repo and packaged manifests match, dataset bytes match, and optional
    packaged_resource parity holds for both paths.
    """
    for path in (
        locations.source_jsonl,
        locations.source_manifest,
        locations.packaged_jsonl,
        locations.packaged_manifest,
    ):
        if not path.is_file():
            raise EvaluationContractError(f"missing baseline artifact: {path}")

    source_manifest = load_dataset_manifest(locations.source_manifest)
    packaged_manifest = load_dataset_manifest(locations.packaged_manifest)

    validate_dataset(
        locations.source_jsonl,
        source_manifest,
        check_packaged_parity=check_packaged_parity,
    )
    validate_dataset(
        locations.packaged_jsonl,
        packaged_manifest,
        check_packaged_parity=check_packaged_parity,
    )

    assert_manifest_documents_equal(source_manifest, packaged_manifest)
    assert_dataset_bytes_equal(locations.source_jsonl, locations.packaged_jsonl)

    assert_case_id_ordering_matches_manifest(locations.source_jsonl, source_manifest)
    assert_case_id_ordering_matches_manifest(locations.packaged_jsonl, packaged_manifest)
    assert_manifest_digest_matches_dataset(locations.source_jsonl, source_manifest)
    assert_manifest_digest_matches_dataset(locations.packaged_jsonl, packaged_manifest)

    digest = compute_dataset_digest(locations.source_jsonl)
    return {
        "status": "ok",
        "suite_name": source_manifest.get("suite_name"),
        "case_count": source_manifest.get("case_count"),
        "content_digest_sha256": digest,
        "source_jsonl": str(locations.source_jsonl.resolve()),
        "packaged_jsonl": str(locations.packaged_jsonl.resolve()),
    }


def build_parity_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Gate check: baseline evals/datasets copy must match packaged "
            "src/resources copy (manifest fields, digests, row ordering, bytes)."
        ),
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Repository root (default: auto-detect from package layout).",
    )
    parser.add_argument(
        "--no-packaged-parity",
        action="store_true",
        help="Skip byte check against installed packaged_resource.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="On success, print a JSON summary to stdout.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress success message on stdout.",
    )
    return parser


def run_parity_command(args: argparse.Namespace) -> int:
    locations = default_baseline_locations(args.repo_root)
    try:
        summary = check_baseline_pair(
            locations,
            check_packaged_parity=not args.no_packaged_parity,
        )
    except EvaluationContractError as exc:
        print(f"parity gate failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(summary, indent=2))
    elif not args.quiet:
        print(
            "ok: baseline source/package parity "
            f"({summary.get('case_count')} cases, digest {summary.get('content_digest_sha256')})"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parity_parser(prog="parity")
    args = parser.parse_args(argv)
    return run_parity_command(args)


if __name__ == "__main__":
    raise SystemExit(main())
