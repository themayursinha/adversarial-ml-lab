# Evaluation Schema & Manifest Specification

This directory contains the versioned JSON Schema definitions for the adversarial-ml-lab evaluation framework. The packaged baseline and manifest-backed custom datasets are governed by these contracts; ungoverned custom datasets retain legacy row validation.

## Schema files

| File | Scope | Draft |
|------|-------|-------|
| `evaluation_schema.json` | Canonical umbrella name (`oneOf` over case, manifest, run provenance) | 2020-12 |
| `schema.json` | Identical umbrella alias (backward compatible) | 2020-12 |
| `evaluation_case.v1.json` | A single row in the JSONL dataset | 2020-12 |
| `evaluation_manifest.v1.json` | The dataset manifest document (`.manifest.json`) | 2020-12 |
| `evaluation_run_provenance.v1.json` | The run provenance block inside an evaluation result | 2020-12 |
| `dataset.manifest.template.json` | Fill-in template for a new dataset manifest (digest, ordering, families) | — |
| `run_provenance.template.json` | Fill-in template for run metadata (digest, code, config fingerprint, seed, metrics) | — |
| `examples/*.example.json` | Validated sample documents checked in CI | — |

---

## 1. Evaluation case row (`evaluation_case.v1.json`)

**File:** `evaluation_case.v1.json`

Validates one line of the JSONL dataset. Every row is an object with `additionalProperties: false`.

### Required fields

| Field | Type | Constraint |
|-------|------|------------|
| `case_id` | string | `^[a-z0-9_]+$`, minLength: 1 |
| `prompt` | string | — |
| `context` | string | — |
| `task_type` | string | minLength: 1 |
| `expected_blocked` | boolean | — |

### Optional fields

| Field | Type | Constraint |
|-------|------|------------|
| `case_type` | string | enum: `"benign"`, `"adversarial"` |
| `attack_family` | string | minLength: 1 |
| `expected_review` | boolean | — |
| `expected_risk_level` | string | enum: `"low"`, `"medium"`, `"high"`, `"critical"` |
| `notes` | string | — |

### Fail-closed rule

Any row that violates the schema (missing required field, wrong type, disallowed enum value, unknown property) is rejected at load time. The evaluator never silently skips or defaults a malformed row.

---

## 2. Dataset manifest (`evaluation_manifest.v1.json`)

**File:** `evaluation_manifest.v1.json`

Validates the `.manifest.json` document that accompanies a JSONL dataset file. The manifest freezes the dataset's identity, content integrity, and structural constraints.

### Required fields

| Field | Type | Constraint |
|-------|------|------------|
| `manifest_version` | string | `"1.0.0"` |
| `contract_id` | string | `"adml.evaluation.dataset.v1"` |
| `suite_name` | string | non-empty |
| `dataset_filename` | string | non-empty |
| `content_digest_sha256` | string | `^[a-f0-9]{64}$` |
| `case_count` | integer | >= 1 |
| `case_ids` | array[string] | uniqueItems, each matches `^[a-z0-9_]+$` |
| `family_counts` | object | string keys, non-negative integer values |
| `schema_ref` | string | `"evaluation_case.v1"` |
| `required_fields` | array[string] | minItems: 1 |
| `allowed_case_types` | array[string] | enum subset of `["benign", "adversarial"]` |
| `allowed_risk_levels` | array[string] | enum subset of `["low", "medium", "high", "critical"]` |

### Optional fields

| Field | Type | Constraint |
|-------|------|------------|
| `packaged_resource` | string | non-empty when set |

### Runtime invariants (enforced by Python, not by JSON Schema alone)

The schema enforces type shape and value ranges. Cross-field invariants are enforced by `validate_manifest_document()` in `src/eval/contract.py`:

1. `len(case_ids) == case_count`
2. `sum(family_counts.values()) == case_count`
3. `case_ids` are unique and ordered exactly as they appear in the JSONL
4. `content_digest_sha256` matches `sha256(dataset_bytes)`
5. No unknown fields may appear in the manifest

### Ordering constraint

The `case_ids` array in the manifest defines the **canonical ordering** of the dataset. The JSONL file must list rows in the exact same order. Any deviation triggers a fail-closed `EvaluationContractError`.

---

## 3. Run provenance (`evaluation_run_provenance.v1.json`)

**File:** `evaluation_run_provenance.v1.json`

Validates the `provenance` block inside an `EvaluationRunResult`. Every evaluation run produces a provenance record that captures the full execution context for reproducibility.

### Top-level fields

| Field | Type | Required |
|-------|------|----------|
| `contract_id` | string | yes (`"adml.evaluation.run.v1"`) |
| `dataset` | object | yes |
| `runtime` | object | yes |
| `code` | object | yes |
| `metrics` | object | yes |

### `dataset` block

| Field | Type | Constraint |
|-------|------|------------|
| `dataset_filename` | string | non-empty (filename only, no path) |
| `suite_name` | string | non-empty |
| `content_digest_sha256` | string | `^[a-f0-9]{64}$` |
| `case_count` | integer or null | >= 1 when set; null when no manifest |
| `contract_id` | string or null | `"adml.evaluation.dataset.v1"` when set; null when no manifest |
| `packaged_resource` | string or null | non-empty when set; null when no manifest |

### `runtime` block

| Field | Type | Constraint |
|-------|------|------------|
| `llm_mode` | string | e.g. `"simulation"`, `"openai"`, `"anthropic"`, `"ollama"` |
| `simulation_seed` | null | always null in v1 |
| `deterministic` | boolean | true when `llm_mode` is `"simulation"` |

### `code` block

| Field | Type | Constraint |
|-------|------|------------|
| `package_version` | string | semver from `src.__version__` |
| `commit_sha` | string or null | 40-character lowercase Git SHA when repository metadata is available |
| `config_fingerprint_sha256` | string | `^[a-f0-9]{64}$` — deterministic digest of default config |

### `metrics` block

| Field | Type | Constraint |
|-------|------|------------|
| `definitions` | object | string keys, string values (min 1 entry) |

### Fail-closed rules

- `additionalProperties: false` is set at every level. Any unknown field causes rejection.
- Missing required fields cause rejection.
- Type mismatches (e.g. `case_count` as a string, `deterministic` as null) cause rejection.
- The `simulation_seed` field must be exactly `null` — any truthy value is rejected.

---

## Validation flow

```
dataset.jsonl
    |
    v
evaluation_case.v1.json  --->  validate each row
    |
    +---> dataset.manifest.json
              |
              v
          evaluation_manifest.v1.json  --->  validate manifest document
              |
              v
          runtime invariants: case_count, family_counts, digest, ordering
              |
              v
          (load succeeds or fail-closed)

evaluation run
    |
    v
build_run_provenance()
    |
    v
evaluation_run_provenance.v1.json  --->  validate provenance block
```

---

## Templates and examples

- **`dataset.manifest.template.json`** — start here for a governed dataset: set `suite_name`, `dataset_filename`, replace `content_digest_sha256` with `sha256(file bytes)`, fill `case_ids` in JSONL order, and align `family_counts` with row `attack_family` values. Enumerated labels live in `allowed_case_types` and `allowed_risk_levels`.
- **`run_provenance.template.json`** — documents the run/result metadata block: dataset digest, `code.package_version`, `code.commit_sha`, `code.config_fingerprint_sha256`, `runtime.simulation_seed` (null in v1), and `metrics.definitions`.
- **`examples/`** — committed instances validated in `tests/test_evaluation_schemas.py`. Regenerate with `scripts/generate_schema_examples.py` after baseline changes.

---

## Adding a new dataset

1. Create the JSONL file with rows conforming to `evaluation_case.v1.json`.
2. Run `scripts/generate_baseline_manifest.py` (or equivalent) to produce the `.manifest.json`.
3. The generated manifest will be validated against `evaluation_manifest.v1.json` at load time.
4. Place both files in `evals/datasets/` and (for packaged datasets) `src/resources/datasets/`.

---

## Versioning

- `manifest_version` is `"1.0.0"` for this contract.
- The `contract_id` fields (`adml.evaluation.dataset.v1`, `adml.evaluation.run.v1`) are immutable once set.
- Schema files (`evaluation_case.v1.json`, `evaluation_manifest.v1.json`, `evaluation_run_provenance.v1.json`) are versioned in the filename. A breaking change produces a new `.v2.json` file.