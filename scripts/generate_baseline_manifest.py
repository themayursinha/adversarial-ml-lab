"""Generate baseline.manifest.json from baseline.jsonl (dev maintenance)."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "evals/datasets/baseline.jsonl"
OUT_EVALS = REPO_ROOT / "evals/datasets/baseline.manifest.json"
OUT_PKG = REPO_ROOT / "src/resources/datasets/baseline.manifest.json"

data = DATASET.read_bytes()
case_ids: list[str] = []
families: Counter[str] = Counter()
for line in DATASET.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    row = json.loads(line)
    case_ids.append(row["case_id"])
    families[row["attack_family"]] += 1

manifest = {
    "manifest_version": "1.0.0",
    "contract_id": "adml.evaluation.dataset.v1",
    "suite_name": "baseline",
    "dataset_filename": "baseline.jsonl",
    "content_digest_sha256": hashlib.sha256(data).hexdigest(),
    "case_count": len(case_ids),
    "case_ids": case_ids,
    "family_counts": dict(sorted(families.items())),
    "packaged_resource": "datasets/baseline.jsonl",
    "schema_ref": "evaluation_case.v1",
    "required_fields": [
        "case_id",
        "prompt",
        "context",
        "task_type",
        "expected_blocked",
        "case_type",
        "attack_family",
    ],
    "allowed_case_types": ["benign", "adversarial"],
    "allowed_risk_levels": ["low", "medium", "high", "critical"],
}

for out in (OUT_EVALS, OUT_PKG):
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print("wrote", OUT_EVALS, OUT_PKG)