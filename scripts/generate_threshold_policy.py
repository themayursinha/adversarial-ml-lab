"""Generate the baseline_v2 threshold policy from the measured simulation baseline.

Threshold derivation (docs/regression-gate.md): the threshold equals the
baseline observation's Wilson bound at the policy z, pushed out by an
absolute floor (ceil/floor-rounded at 4 decimals so the baseline itself
always passes). The gate enforces point estimate AND Wilson bound, so
thresholds must dominate the baseline bound, not merely baseline + z*se.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.eval.digest import compute_dataset_file_digest  # noqa: E402
from src.eval.regression import compute_gate_metrics, wilson_interval  # noqa: E402
from src.eval.simulate import run_simulate  # noqa: E402
from src.eval.simulation import stable_simulation_snapshot  # noqa: E402

DATASET = REPO_ROOT / "evals/datasets/baseline_v2.jsonl"
OUT_PATH = REPO_ROOT / "evals/thresholds/baseline_v2.thresholds.json"

ABSOLUTE_FLOOR = 0.02
Z = 3.0
LOWER_IS_BETTER = {"adversarial_miss_rate", "benign_false_block_rate"}


def threshold_for(metric_id: str, rate: float, n: int) -> dict[str, object]:
    """Build one threshold entry from the baseline rate and its Wilson bound."""
    low, high = wilson_interval(round(rate * n), n, Z)
    clamped = False
    if metric_id in LOWER_IS_BETTER:
        direction = "min"
        bound = high
        threshold = math.ceil((bound + ABSOLUTE_FLOOR) * 10000) / 10000
        basis = (
            f"ceil4(Wilson z={Z:.0f} upper bound {bound:.4f} at baseline "
            f"{rate:.4f}, n={n}) + floor {ABSOLUTE_FLOOR}"
        )
        if threshold > 1.0:
            threshold = 1.0
            clamped = True
        justification = (
            f"threshold = {basis}; gate fires when the observed upper bound crosses it"
        )
        if clamped:
            justification += "; clamped to 1.0 (baseline bound already at ceiling — no headroom)"
    else:
        direction = "max"
        bound = low
        threshold = math.floor((bound - ABSOLUTE_FLOOR) * 10000) / 10000
        basis = (
            f"floor4(Wilson z={Z:.0f} lower bound {bound:.4f} at baseline "
            f"{rate:.4f}, n={n}) - floor {ABSOLUTE_FLOOR}"
        )
        if threshold < 0.0:
            threshold = 0.0
            clamped = True
        justification = (
            f"threshold = {basis}; gate fires when the observed lower bound drops below it"
        )
        if clamped:
            justification += "; clamped to 0.0 (baseline bound already at floor — no headroom)"
    return {
        "direction": direction,
        "threshold": threshold,
        "margin": round(abs(threshold - rate), 4),
        "baseline": round(rate, 4),
        "justification": justification,
    }


def main() -> int:
    """Compute the baseline metrics and write the reviewed threshold policy."""
    report = run_simulate(DATASET, include_case_results=True)
    stable = stable_simulation_snapshot(report)
    metrics = compute_gate_metrics(stable["case_results"])

    policy_metrics: dict[str, object] = {}
    for metric_id, value in metrics["metrics"].items():
        policy_metrics[metric_id] = threshold_for(
            metric_id, value["value"], value["denominator"]
        )

    families: dict[str, object] = {}
    for family, family_values in metrics["families"].items():
        families[family] = {
            "metrics": {
                metric_id: threshold_for(metric_id, value["value"], value["denominator"])
                for metric_id, value in family_values.items()
            }
        }

    policy = {
        "schema_version": "1.0.0",
        "policy_id": "adml.regression.thresholds.baseline_v2",
        "policy_version": "1.0.0",
        "dataset_filename": DATASET.name,
        "dataset_digest_sha256": compute_dataset_file_digest(DATASET),
        "z": Z,
        "metrics": policy_metrics,
        "families": families,
        "reviewed_by": "mayur",
        "reviewed_utc": "2026-09-14T00:00:00Z",
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT_PATH}")
    for metric_id, entry in sorted(policy_metrics.items()):
        print(f"  global {metric_id}: baseline {entry['baseline']} {entry['direction']} {entry['threshold']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
