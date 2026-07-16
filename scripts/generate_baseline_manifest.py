"""Generate baseline.manifest.json from baseline.jsonl (dev maintenance)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.eval.digest import build_dataset_manifest  # noqa: E402

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
