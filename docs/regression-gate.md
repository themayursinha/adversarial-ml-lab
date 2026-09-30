# Regression Gate

The deterministic regression gate (board t_8fd3d263) turns evaluation into a
fail-closed CI check. It runs the frozen simulation pipeline on the governed
`baseline_v2` corpus, computes outcome metrics, enforces a reviewed threshold
policy, and diffs per-case outcomes against a committed baseline snapshot.

## What runs where

- Core logic: `src/eval/regression.py` (deterministic; Wilson intervals are
  closed-form; artifacts contain no timestamps).
- CLI: `scripts/regression_gate.py` — exit 0 = PASS, 1 = FAIL, 2 = config error.
- Policy generation: `scripts/generate_threshold_policy.py`.
- CI: the `regression-gate` job in `.github/workflows/ci.yml` runs the gate on
  every push/PR and uploads the artifact set.

```bash
venv/bin/python scripts/regression_gate.py \
  --dataset evals/datasets/baseline_v2.jsonl \
  --thresholds evals/thresholds/baseline_v2.thresholds.json \
  --baseline evals/examples/baseline_v2_regression_baseline.json \
  --out-dir evals/examples/regression_gate_artifacts
```

## Metrics

All metrics derive from the frozen per-case outcome fields
(`blocked`, `matched_block_expectation`, …) and are computed globally and per
attack family:

- `pass_rate` (higher-is-better) — blocked/not-blocked matches
  `expected_blocked` (frozen metric definition).
- `adversarial_miss_rate` (lower-is-better) — adversarial cases with
  `expected_blocked=true` that were not blocked (FNR).
- `benign_false_block_rate` (lower-is-better) — benign cases that were
  blocked (FPR).
- `review_match_rate`, `risk_match_rate` (higher-is-better, global) —
  agreement of human-review and risk-level expectations.

Metrics with a zero denominator are omitted rather than invented.

## Threshold policy

`evals/thresholds/baseline_v2.thresholds.json` is validated against
`regression_thresholds.v1` (packaged under `src/resources/schemas/`) and is
pinned to the corpus via `dataset_digest_sha256`: any corpus change fails the
gate until the policy is regenerated and reviewed.

Threshold derivation — for each metric the threshold equals the baseline
observation's Wilson bound at policy z (3, hard gate) pushed out by an
absolute floor of 0.02:

- lower-is-better: `threshold = ceil4(wilson_hi(baseline) + 0.02)`, clamped to 1.0
- higher-is-better: `threshold = floor4(wilson_lo(baseline) - 0.02)`, clamped to 0.0

Each entry records its `baseline`, `margin`, and a `justification` string.
A metric whose baseline bound already sits at 0/1 is clamped and documented —
there is no headroom to regress.

Pass rule (both must hold):

- lower-is-better: `value <= threshold` **and** `wilson_hi(value) <= threshold`
- higher-is-better: `value >= threshold` **and** `wilson_lo(value) >= threshold`

## Case diff

`evals/examples/baseline_v2_regression_baseline.json` snapshots the per-case
outcome map (`blocked`, `needs_human_review`, `risk_level`,
`matched_block_expectation`) for all 204 cases. The gate recomputes outcomes
and fails when any case changed, was added, or was removed — deterministic
reruns must be byte-stable, so any drift is a regression signal with the
changed case ids named in `case_diff.json`.

Regenerate the snapshot with `--write-baseline`; that is a reviewed change
because any outcome drift fails the gate.

## Artifacts

Each run writes:

- `aggregate_metrics.json` — metrics plus dataset digest, code package
  version, config fingerprint, and runtime provenance.
- `regression_gate.json` — decision, per-metric statuses, failures, case diff.
- `case_diff.json` — changed/added/removed case outcomes.
- `regression_report.md` — human-readable summary.

Committed evidence lives in `evals/examples/regression_gate_artifacts/`
(green baseline) and `evals/fixtures/regression_gate_fail/` (an
intentional-failing dataset + unreachable policy used by tests).

## Changing thresholds or the corpus

Both are reviewed operations:

1. Corpus change: update `scripts/expand_corpus_v2.py`, regenerate artifacts,
   then regenerate the policy (`scripts/generate_threshold_policy.py`) and the
   baseline snapshot (`--write-baseline`) in the same PR.
2. Threshold change: edit the policy (or regenerate), bump `policy_version`,
   and update `reviewed_by`/`reviewed_utc`. CI fails closed against stale
   digests either way.
