# Defense Ablations

The ablation harness (board t_145d47d5) measures which controls add detection
value on the governed `baseline_v2` corpus and where they fail. It is
simulation-only evidence over the deterministic heuristic pipeline: these
numbers measure control contribution inside this lab harness and are **not
production-efficacy claims**.

## Method

`src/eval/ablation.py` runs every case through ten configurations:

| Config | Controls enabled |
|---|---|
| `defense_off` | none |
| `canonicalization_only` | canonicalization |
| `filter_only` | context filter (raw text) |
| `anomaly_only` | anomaly scorer |
| `uncertainty_only` | uncertainty scorer |
| `isolation_only` | context isolation |
| `redaction_only` | content redaction |
| `canonicalization_plus_filter` | canonicalization + filter |
| `default_pipeline` | the shipped `DefensePipeline` (canon + filter + anomaly + uncertainty) |
| `all_controls` | everything, including isolation and redaction |

The `default_pipeline` row delegates to the production `DefensePipeline`, so
the harness cannot drift from shipped behavior (pinned by
`tests/test_defense_ablations.py`). Responses come from the simulation LLM,
generated once per case and shared across configurations, so config deltas
are attributable to controls only.

Each row reports blocked-signal and flagged-signal confusion matrices
(TP/FP/FN/TN plus a separate count for adversarial cases labeled
`expected_blocked=false` — canonicalization-neutralizable evasions where
blocking would be an over-block), per-family pass rates, and failure lists
(misses and false blocks) ranked by expected risk.

Regenerate:

```bash
venv/bin/python scripts/ablation_runner.py
```

Committed artifact: `evals/examples/baseline_v2_ablation_report.json`
(byte-stable; recomputation equality is tested).

## Findings on baseline_v2 (204 cases)

1. **The context filter is the only blocking control.** `filter_only`,
   `canonicalization_plus_filter`, `default_pipeline`, and `all_controls`
   produce identical blocked outcomes: miss rate 0.7524, false-block rate
   0.0326. Canonicalization, anomaly, uncertainty, isolation, and redaction
   add zero marginal blocked detections on this corpus. If a defense change
   alters this, the report and the pinned test must be updated together.
2. **Canonicalization adds no marginal detection here** because the filter
   inspects simulated outputs; input-side obfuscation rarely reaches the
   output channel. Its value in this harness is limited to normalization
   signals (e.g. zero-width removal) measured under `flagged`.
3. **Anomaly and uncertainty are alert/review controls, not blocking
   controls** — their blocked confusion matrices are all-zero by design;
   see the `flagged` matrices for alert coverage and benign flag rates.
4. **Isolation yields no single-turn detections.** Context-integrity
   verification requires session state; on single-turn corpus cases the
   control produces no signal. This is a harness-shape limitation, not a
   control endorsement.
5. **Redaction is a hygiene control, not a detector.** It fired on only 5
   cases (placeholder-shaped strings hitting PII-adjacent patterns) and
   blocked nothing; the corpus contains no real PII by policy.

## Failure surface and risk ranking

The `default_pipeline` blocks 26 of 105 expected-block adversarial cases
(79 misses: 9 critical, 59 high, 11 medium) and false-blocks 3 of 92 benign
cases (1 low, 2 medium risk); the 7 canonicalization-neutralizable evasions
are left unblocked as labeled. The miss list in the report is ranked by
expected risk (critical first) with per-risk counts. Highest-risk failures
are pinned by tests: the committed report must reproduce exactly, and the
miss list must remain risk-ordered with critical-risk entries present — any
drift fails `tests/test_defense_ablations.py` and forces a conscious report
refresh.

The `flagged` signal (anomaly alerts + human-review routing) covers 96 of
105 expected-block adversarial cases but also flags 76 benign cases — high
alert coverage comes at a large benign flag cost, which is exactly the
trade-off the uncertainty threshold controls.

Follow-up work (thresholds, defense tuning) must use the dev split only, per
`docs/evaluation-corpus-governance.md`.
