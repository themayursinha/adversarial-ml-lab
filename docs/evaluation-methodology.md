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
adml eval --suite baseline
```

`adml eval` defaults to the packaged baseline dataset. Use `--dataset` to point at a custom JSONL corpus.

## Core Metrics

- `pass_rate`: percent of cases where observed blocked/not-blocked matches expectation.
- `blocked_cases`: total blocked outputs.
- `review_cases`: cases that require human review.

## Reproducibility

- Evaluation corpus is committed to repo.
- The baseline corpus is packaged with the distribution for installed CLI smoke tests.
- Simulation mode avoids non-deterministic external model calls.
- Results can be diffed across commits in CI.
