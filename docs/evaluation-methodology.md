# Evaluation Methodology

## Dataset Format

JSONL rows with fields:
- `case_id`
- `prompt`
- `context`
- `task_type`
- `expected_blocked`

## Execution

```bash
adml eval --dataset evals/datasets/baseline.jsonl --suite baseline
```

## Core Metrics

- `pass_rate`: percent of cases where observed blocked/not-blocked matches expectation.
- `blocked_cases`: total blocked outputs.
- `review_cases`: cases that require human review.

## Reproducibility

- Evaluation corpus is committed to repo.
- Simulation mode avoids non-deterministic external model calls.
- Results can be diffed across commits in CI.
