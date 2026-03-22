# Evaluation Methodology

## Dataset Format

JSONL rows with fields:
- `case_id`
- `prompt`
- `context`
- `task_type`
- `expected_blocked`
- `case_type` (optional; defaults to `benign` when `expected_blocked=false`, otherwise `adversarial`)
- `attack_family` (optional; defaults to `clean` for benign rows, otherwise `unknown`)
- `expected_review` (optional)
- `expected_risk_level` (optional)
- `notes` (optional)

## Execution

```bash
adml eval --suite baseline
```

`adml eval` defaults to the packaged baseline dataset. Use `--dataset` to point at a custom JSONL corpus.

Use `--show-cases` to include per-case results in the JSON output.

```bash
adml eval --suite baseline --show-cases
```

## Core Metrics

- `pass_rate`: percent of cases where observed blocked/not-blocked matches expectation.
- `blocked_cases`: total blocked outputs.
- `review_cases`: cases that require human review.
- `review_match_rate`: percent of cases with an `expected_review` label where observed review behavior matches expectation.
- `risk_match_rate`: percent of cases with an `expected_risk_level` label where observed risk level matches expectation.
- `family_metrics`: per-attack-family totals for cases, blocked outputs, review cases, and blocked-expectation pass rate.

When `--show-cases` is enabled, the output also includes `case_results` with expected labels, observed outcomes, detection counts, event types, and expectation-match fields.

## Reproducibility

- Evaluation corpus is committed to repo.
- The baseline corpus is packaged with the distribution for installed CLI smoke tests.
- Simulation mode avoids non-deterministic external model calls.
- Results can be diffed across commits in CI.
