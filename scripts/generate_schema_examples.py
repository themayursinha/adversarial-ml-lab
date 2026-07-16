"""Generate packaged schema example documents (dev maintenance)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.eval.contract import build_run_provenance, load_dataset_manifest  # noqa: E402
from src.utils.llm_client import LLMMode  # noqa: E402

EXAMPLES = REPO_ROOT / "src/resources/schemas/examples"
JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"
MANIFEST_PATH = REPO_ROOT / "evals/datasets/baseline.manifest.json"


def main() -> None:
    EXAMPLES.mkdir(parents=True, exist_ok=True)
    manifest = load_dataset_manifest(MANIFEST_PATH)
    (EXAMPLES / "baseline_manifest.example.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    row = json.loads(JSONL.read_text(encoding="utf-8").splitlines()[0])
    (EXAMPLES / "baseline_case.example.json").write_text(
        json.dumps(row, indent=2) + "\n",
        encoding="utf-8",
    )
    provenance = build_run_provenance(
        dataset_path=JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
        manifest=manifest,
    )
    (EXAMPLES / "baseline_run_provenance.example.json").write_text(
        json.dumps(provenance, indent=2) + "\n",
        encoding="utf-8",
    )
    print("wrote", EXAMPLES)


if __name__ == "__main__":
    main()
