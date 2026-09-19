"""Fail-closed deterministic regression gate over the simulation pipeline.

The gate runs the frozen simulation pipeline on a governed dataset, computes
deterministic outcome metrics (global and per family), evaluates them against
a reviewed threshold policy pinned to the dataset digest, diffs per-case
outcomes against a committed baseline snapshot, and emits machine-readable
artifacts. Deterministic by construction: the only randomness source (none)
is absent, Wilson intervals are closed-form, and artifacts carry no
timestamps (provenance keeps only stable fields).
"""

from __future__ import annotations

import json
import math
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

from src.eval.contract import EvaluationContractError, validate_json_document
from src.eval.corpus_governance import sha256_hex
from src.eval.digest import compute_dataset_file_digest
from src.eval.simulate import run_simulate
from src.eval.simulation import stable_simulation_snapshot

REGRESSION_GATE_PIPELINE_ID = "regression_gate_v1"
REGRESSION_THRESHOLDS_SCHEMA_REF = "regression_thresholds.v1"
GATE_ARTIFACT_FILES = (
    "aggregate_metrics.json",
    "regression_gate.json",
    "case_diff.json",
    "regression_report.md",
)
BASELINE_SNAPSHOT_FIELDS = (
    "blocked",
    "needs_human_review",
    "risk_level",
    "matched_block_expectation",
)


class RegressionGateError(EvaluationContractError):
    """Raised when the regression gate is misconfigured or fails closed."""


def load_regression_thresholds_schema() -> dict[str, Any]:
    """Load the packaged regression_thresholds.v1 JSON Schema."""
    resource = files("src.resources").joinpath("schemas/regression_thresholds.v1.json")
    with as_file(resource) as schema_path:
        data: Any = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RegressionGateError("regression_thresholds.v1.json must be a JSON object")
    return data


def load_threshold_policy(path: Path) -> dict[str, Any]:
    """Load and schema-validate a threshold policy document."""
    policy: Any
    try:
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RegressionGateError(f"invalid threshold policy JSON: {exc}") from exc
    if not isinstance(policy, dict):
        raise RegressionGateError("threshold policy must be a JSON object")
    validate_json_document(
        policy,
        load_regression_thresholds_schema(),
        label="threshold policy",
    )
    return policy


def wilson_interval(successes: int, total: int, z: float) -> tuple[float, float]:
    """Closed-form Wilson score interval for a binomial proportion."""
    if total <= 0:
        raise RegressionGateError("Wilson interval requires a positive denominator")
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, center - spread), min(1.0, center + spread))


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator


def compute_gate_metrics(case_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute deterministic gate metrics from per-case simulation results."""
    total = len(case_results)
    if total == 0:
        raise RegressionGateError("simulation produced no case results")

    matched = sum(1 for row in case_results if row["matched_block_expectation"])
    adv_expected = [
        row
        for row in case_results
        if row["case_type"] == "adversarial" and row["expected_blocked"]
    ]
    adv_missed = sum(1 for row in adv_expected if not row["blocked"])
    benign = [row for row in case_results if row["case_type"] == "benign"]
    benign_blocked = sum(1 for row in benign if row["blocked"])
    review_rows = [row for row in case_results if row.get("expected_review") is not None]
    review_matched = sum(1 for row in review_rows if row["matched_review_expectation"])
    risk_rows = [row for row in case_results if row.get("expected_risk_level") is not None]
    risk_matched = sum(1 for row in risk_rows if row["matched_risk_expectation"])

    raw_metrics: dict[str, dict[str, Any] | None] = {
        "pass_rate": _rate_dict(matched, total),
        "adversarial_miss_rate": _rate_dict(adv_missed, len(adv_expected)),
        "benign_false_block_rate": _rate_dict(benign_blocked, len(benign)),
        "review_match_rate": _rate_dict(review_matched, len(review_rows)),
        "risk_match_rate": _rate_dict(risk_matched, len(risk_rows)),
    }
    metrics: dict[str, dict[str, Any]] = {
        name: value for name, value in raw_metrics.items() if value is not None
    }

    families: dict[str, dict[str, Any]] = {}
    family_names = sorted({str(row["attack_family"]) for row in case_results})
    for family in family_names:
        rows = [row for row in case_results if row["attack_family"] == family]
        fam_matched = sum(1 for row in rows if row["matched_block_expectation"])
        fam_adv = [
            row for row in rows if row["case_type"] == "adversarial" and row["expected_blocked"]
        ]
        fam_missed = sum(1 for row in fam_adv if not row["blocked"])
        fam_benign = [row for row in rows if row["case_type"] == "benign"]
        fam_blocked_benign = sum(1 for row in fam_benign if row["blocked"])
        raw_family: dict[str, dict[str, Any] | None] = {
            "pass_rate": _rate_dict(fam_matched, len(rows)),
            "adversarial_miss_rate": _rate_dict(fam_missed, len(fam_adv)),
            "benign_false_block_rate": _rate_dict(fam_blocked_benign, len(fam_benign)),
        }
        families[family] = {
            name: value for name, value in raw_family.items() if value is not None
        }

    return {"metrics": metrics, "families": families, "case_count": total}


def _rate_dict(numerator: int, denominator: int) -> dict[str, Any] | None:
    rate = _rate(numerator, denominator)
    if rate is None:
        return None
    return {"numerator": numerator, "denominator": denominator, "value": rate}


def _evaluate_threshold(
    metric_id: str,
    entry: dict[str, Any],
    value: dict[str, Any],
    z: float,
) -> dict[str, Any]:
    """Evaluate one metric against one threshold entry with Wilson uncertainty."""
    direction = entry["direction"]
    threshold = float(entry["threshold"])
    point = float(value["value"])
    low, high = wilson_interval(value["numerator"], value["denominator"], z)
    if direction == "max":
        passed = point >= threshold and low >= threshold
        bound = low
    elif direction == "min":
        passed = point <= threshold and high <= threshold
        bound = high
    else:
        raise RegressionGateError(f"metric {metric_id}: unknown direction {direction!r}")
    return {
        "value": point,
        "numerator": value["numerator"],
        "denominator": value["denominator"],
        "direction": direction,
        "threshold": threshold,
        "wilson_bound": round(bound, 6),
        "status": "PASS" if passed else "FAIL",
    }


def evaluate_thresholds(
    gate_metrics: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate all policy metrics; returns per-metric statuses and failures."""
    z = float(policy["z"])
    results: dict[str, Any] = {}
    failures: list[str] = []

    for metric_id, entry in policy["metrics"].items():
        if metric_id not in gate_metrics["metrics"]:
            raise RegressionGateError(f"policy metric {metric_id} missing from run metrics")
        outcome = _evaluate_threshold(metric_id, entry, gate_metrics["metrics"][metric_id], z)
        results[metric_id] = outcome
        if outcome["status"] == "FAIL":
            failures.append(f"global.{metric_id}")

    family_results: dict[str, dict[str, Any]] = {}
    for family, family_policy in policy.get("families", {}).items():
        if family not in gate_metrics["families"]:
            raise RegressionGateError(f"policy family {family} missing from run metrics")
        family_results[family] = {}
        for metric_id, entry in family_policy["metrics"].items():
            if metric_id not in gate_metrics["families"][family]:
                raise RegressionGateError(
                    f"policy metric {family}.{metric_id} missing from run metrics"
                )
            outcome = _evaluate_threshold(
                metric_id,
                entry,
                gate_metrics["families"][family][metric_id],
                z,
            )
            family_results[family][metric_id] = outcome
            if outcome["status"] == "FAIL":
                failures.append(f"{family}.{metric_id}")

    return {"results": results, "families": family_results, "failures": failures}


def case_outcome_map(case_results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Deterministic per-case outcome map used for case-diffing."""
    outcomes: dict[str, dict[str, Any]] = {}
    for row in case_results:
        outcomes[row["case_id"]] = {field: row[field] for field in BASELINE_SNAPSHOT_FIELDS}
    return outcomes


def diff_case_outcomes(
    baseline: dict[str, dict[str, Any]],
    current: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Identify changed, added, and removed case outcomes vs the baseline."""
    changed: dict[str, dict[str, Any]] = {}
    for case_id in sorted(set(baseline) & set(current)):
        if baseline[case_id] != current[case_id]:
            changed[case_id] = {
                "baseline": baseline[case_id],
                "current": current[case_id],
            }
    added = sorted(set(current) - set(baseline))
    removed = sorted(set(baseline) - set(current))
    return {
        "changed": changed,
        "added": added,
        "removed": removed,
        "changed_count": len(changed) + len(added) + len(removed),
    }


def build_regression_report(gate: dict[str, Any]) -> str:
    """Render a compact Markdown summary of the gate decision."""
    lines = [
        "# Regression gate report",
        "",
        f"- pipeline: `{gate['pipeline']}`",
        f"- dataset: `{gate['dataset_filename']}` (digest `{gate['dataset_digest_sha256'][:12]}…`)",
        f"- policy: `{gate['policy_id']}` v{gate['policy_version']}",
        f"- case count: {gate['case_count']}",
        f"- gate decision: **{gate['decision']}**",
        "",
        "## Global metrics",
        "",
        "| metric | value | threshold | wilson bound | status |",
        "|---|---:|---:|---:|---|",
    ]
    for metric_id, outcome in gate["threshold_results"]["results"].items():
        lines.append(
            f"| {metric_id} | {outcome['value']:.4f} | {outcome['threshold']:.4f} "
            f"({outcome['direction']}) | {outcome['wilson_bound']:.4f} | {outcome['status']} |"
        )
    lines += ["", "## Family metrics", ""]
    for family, outcomes in gate["threshold_results"]["families"].items():
        for metric_id, outcome in outcomes.items():
            lines.append(
                f"- {family}.{metric_id}: {outcome['value']:.4f} vs {outcome['threshold']:.4f} "
                f"→ {outcome['status']}"
            )
    diff = gate["case_diff"]
    lines += [
        "",
        "## Case diff vs baseline snapshot",
        "",
        f"- changed: {len(diff['changed'])}, added: {len(diff['added'])}, "
        f"removed: {len(diff['removed'])}",
    ]
    if diff["changed"]:
        lines.append("")
        lines.append("Changed case ids: " + ", ".join(sorted(diff["changed"])))
    if gate["threshold_results"]["failures"]:
        lines.append("")
        lines.append("Failing metrics: " + ", ".join(gate["threshold_results"]["failures"]))
    return "\n".join(lines) + "\n"


def run_regression_gate(
    dataset_path: Path,
    thresholds_path: Path,
    baseline_snapshot_path: Path | None = None,
    *,
    suite_name: str | None = None,
) -> dict[str, Any]:
    """Run the deterministic regression gate and return all artifact payloads.

    Raises RegressionGateError on configuration problems. The gate decision is
    PASS only when every threshold passes and no per-case outcome changed vs
    the committed baseline snapshot.
    """
    path = Path(dataset_path)
    policy = load_threshold_policy(Path(thresholds_path))

    dataset_digest = compute_dataset_file_digest(path)
    if dataset_digest != policy["dataset_digest_sha256"]:
        raise RegressionGateError(
            "threshold policy is pinned to a different dataset digest: "
            f"policy {policy['dataset_digest_sha256']}, dataset {dataset_digest}; "
            "regenerate the policy through review when the corpus changes"
        )
    if policy["dataset_filename"] != path.name:
        raise RegressionGateError(
            f"threshold policy targets {policy['dataset_filename']!r}, got {path.name!r}"
        )

    sim_report = run_simulate(
        path,
        suite_name=suite_name,
        include_case_results=True,
    )
    stable_report = stable_simulation_snapshot(sim_report)
    gate_metrics = compute_gate_metrics(stable_report["case_results"])
    threshold_results = evaluate_thresholds(gate_metrics, policy)
    current_outcomes = case_outcome_map(stable_report["case_results"])

    if baseline_snapshot_path is not None and Path(baseline_snapshot_path).is_file():
        snapshot = json.loads(Path(baseline_snapshot_path).read_text(encoding="utf-8"))
        if snapshot.get("dataset_digest_sha256") != dataset_digest:
            raise RegressionGateError(
                "baseline snapshot digest does not match the dataset; regenerate the snapshot"
            )
        case_diff = diff_case_outcomes(snapshot.get("case_outcomes", {}), current_outcomes)
    else:
        case_diff = {"changed": {}, "added": [], "removed": [], "changed_count": 0}

    decision = "PASS" if not threshold_results["failures"] and case_diff["changed_count"] == 0 else "FAIL"

    return {
        "pipeline": REGRESSION_GATE_PIPELINE_ID,
        "schema_ref": REGRESSION_THRESHOLDS_SCHEMA_REF,
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "dataset_filename": path.name,
        "dataset_digest_sha256": dataset_digest,
        "case_count": gate_metrics["case_count"],
        "metrics": gate_metrics["metrics"],
        "family_metrics": gate_metrics["families"],
        "threshold_results": threshold_results,
        "case_diff": case_diff,
        "case_outcomes": current_outcomes,
        "provenance": stable_report["provenance"],
        "decision": decision,
    }


def write_gate_artifacts(gate: dict[str, Any], out_dir: Path) -> list[Path]:
    """Write the machine-readable artifact set and the Markdown report."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    aggregate = {
        "pipeline": gate["pipeline"],
        "policy_id": gate["policy_id"],
        "policy_version": gate["policy_version"],
        "dataset_filename": gate["dataset_filename"],
        "dataset_digest_sha256": gate["dataset_digest_sha256"],
        "case_count": gate["case_count"],
        "metrics": gate["metrics"],
        "family_metrics": gate["family_metrics"],
        "code": {
            "package_version": gate["provenance"]["code"].get("package_version"),
            "config_fingerprint_sha256": gate["provenance"]["code"].get(
                "config_fingerprint_sha256"
            ),
            "pipeline": gate["provenance"].get("contract_id"),
        },
        "runtime": gate["provenance"].get("runtime"),
    }
    gate_doc = {
        "pipeline": gate["pipeline"],
        "policy_id": gate["policy_id"],
        "policy_version": gate["policy_version"],
        "dataset_filename": gate["dataset_filename"],
        "dataset_digest_sha256": gate["dataset_digest_sha256"],
        "case_count": gate["case_count"],
        "decision": gate["decision"],
        "threshold_results": {
            "results": gate["threshold_results"]["results"],
            "families": gate["threshold_results"]["families"],
            "failures": gate["threshold_results"]["failures"],
        },
        "case_diff": {
            "changed": gate["case_diff"]["changed"],
            "added": gate["case_diff"]["added"],
            "removed": gate["case_diff"]["removed"],
            "changed_count": gate["case_diff"]["changed_count"],
        },
    }
    case_diff_doc = {
        "dataset_digest_sha256": gate["dataset_digest_sha256"],
        "changed": gate["case_diff"]["changed"],
        "added": gate["case_diff"]["added"],
        "removed": gate["case_diff"]["removed"],
    }

    written = [
        out_dir / "aggregate_metrics.json",
        out_dir / "regression_gate.json",
        out_dir / "case_diff.json",
        out_dir / "regression_report.md",
    ]
    (out_dir / "aggregate_metrics.json").write_text(
        json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "regression_gate.json").write_text(
        json.dumps(gate_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "case_diff.json").write_text(
        json.dumps(case_diff_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "regression_report.md").write_text(
        build_regression_report(gate), encoding="utf-8"
    )
    return written


def build_baseline_snapshot(gate: dict[str, Any]) -> dict[str, Any]:
    """Build the committed per-case baseline snapshot from a gate run."""
    return {
        "pipeline": REGRESSION_GATE_PIPELINE_ID,
        "dataset_filename": gate["dataset_filename"],
        "dataset_digest_sha256": gate["dataset_digest_sha256"],
        "case_count": gate["case_count"],
        "case_outcomes": gate["case_outcomes"],
        "note": (
            "Per-case outcome snapshot for case-diffing. Regenerate via "
            "scripts/regression_gate.py --write-baseline; changes require review because "
            "any outcome drift fails the gate."
        ),
    }


def baseline_snapshot_fingerprint(snapshot: dict[str, Any]) -> str:
    """Stable fingerprint of a baseline snapshot payload (audit helper)."""
    return sha256_hex(json.dumps(snapshot, sort_keys=True, separators=(",", ":")))
