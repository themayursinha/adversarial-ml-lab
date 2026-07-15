"""Generate baseline.manifest.json from baseline.jsonl (dev maintenance)."""
from __future__ import annotations

import json
from pathlib import Path

from src.eval.digest import build_dataset_manifest

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "evals/datasets/baseline.jsonl"
OUT_EVALS = REPO_ROOT / "evals/datasets/baseline.manifest.json"
OUT_PKG = REPO_ROOT / "src/resources/datasets/baseline.manifest.json"

manifest = build_dataset_manifest(
    DATASET,
    suite_name="baseline",
    packaged_resource="datasets/baseline.jsonl",
)

for out in (OUT_EVALS, OUT_PKG):
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print("wrote", OUT_EVALS, OUT_PKG)
