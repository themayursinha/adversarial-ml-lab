# Evaluation Corpus Governance

## Purpose

The expanded baseline corpus (`evals/datasets/baseline_v2.jsonl`, suite
`baseline_v2`) grows the 50-case baseline to 204 cases across nine attack
families while adding the governance layer the P2 gate requires: per-case
provenance, duplicate detection, leakage scanning, family balance, and a
deterministic held-out split.

The frozen row schema (`evaluation_case.v1`) is unchanged. Provenance lives in
a sidecar document (`evals/datasets/baseline_v2.provenance.json`) validated
against `corpus_provenance.v1` (packaged under `src/resources/schemas/`), so
no row shape or manifest field drifted.

## Composition

| Family | Cases | Adversarial | Benign hard negatives |
|---|---:|---:|---:|
| clean | 37 | 0 | — |
| prompt_injection | 30 | 21 | 9 |
| inference_evasion | 28 | 17 | 11 |
| context_tampering | 24 | 17 | 7 |
| data_exfiltration | 24 | 17 | 7 |
| jailbreak | 22 | 15 | 7 |
| rag_poisoning | 19 | 13 | 6 |
| tool_misuse | 12 | 8 | 4 |
| many_shot | 8 | 4 | 4 |
| **total** | **204** | | |

`tool_misuse` and `many_shot` are new families aligned with the roadmap's
agentic-attack expansion. Every family carries hard negatives
(benign-looking inputs that must not be blocked) and edge cases (unicode,
long/empty context, multilingual, malformed encodings, marker-shaped benign
text). The first 50 rows are byte-identical to `baseline.jsonl`; the v1
dataset stays frozen.

## Label semantics

- `expected_blocked=true` — the defense should hard-block this input/output.
- `expected_blocked=false` on an adversarial row — the defense should
  neutralize (canonicalize/filter) rather than hard-block, matching the
  legacy evasion-row convention.
- Benign rows inside adversarial families are hard negatives: they resemble
  attacks (quoted payloads, encoded benign text, marker-shaped phrasing) but
  must pass through.
- `expected_risk_level` is ground-truth severity, not pipeline output; the
  simulation pipeline's match rates against these labels are reported, never
  asserted.

## Provenance sidecar

Every case has an entry in `cases` keyed by `case_id` with: source,
generation method, seed, attack class, secondary tags, target model,
derivation link (`parent_sample_id`), content and normalized-text hashes,
scrub status, review status, reviewer, held-out membership, and a derivation
note. Legacy rows are documented as `dataset_import`/`approved`; new rows are
`human`/`derived` authored content in `in_review` status — promotion to
`approved` happens through the P2 gate review, not silently.

Schema validation and cross-checks fail closed: unknown fields, hash
mismatches, split disagreements, dangling parent links, or family-count
divergence all reject the sidecar (`verify_provenance_sidecar`).

## Held-out split

Membership is a pure function of the case id:

```
sha256(case_id)mod100<25   (25% target; 57 of 204 cases in v2.0)
```

Discipline: defense tuning (thresholds, filters, scorers) may use only the
dev split listed in the governance report (`held_out_split.dev_ids`); the
held-out ids are used for gate evidence and reruns. The split rule is frozen;
changing it requires a new corpus version and a fresh sidecar.

## Sanitization policy

New-case intake rules (enforced by `scan_case_text` and the generator):

- No secrets or credential-shaped strings; placeholders only
  (`EXAMPLE_TOKEN`, `SAMPLE_API_KEY`, `DATA_PLACEHOLDER`).
- No PII; email/ID/phone-shaped patterns are rejected except
  example-namespace hosts.
- No live targets: only `example.com/org/net/edu`, `*.example`, `*.invalid`,
  `*.test` hosts are allowed (no `.local` mDNS names). Hostname candidates are
  IDNA-normalized before allowlist checks, so homoglyph lookalikes of
  registrable domains fail intake; confusable fixtures live only under
  reserved TLDs such as `.invalid`.
- Attacks are instruction-override style; no operational exploit content.

Legacy v1 rows are retained byte-stable and documented in the sidecar
(`sanitization_policy.legacy_notes`) instead of being rewritten; they carry
fictional legacy hostnames and are excluded from v2 intake scanning.

## Regenerating artifacts

```bash
venv/bin/python scripts/expand_corpus_v2.py
```

Reruns are byte-stable. The script re-derives the manifest, sidecar, and
governance report (`evals/examples/baseline_v2_governance_report.json`),
cross-checks provenance against the written dataset, pins the generator
script digest, and runs a full simulation pass
(`evals/examples/baseline_v2_simulation_snapshot.json`).

To add cases: author them in `scripts/expand_corpus_v2.py` with inline
provenance, add benign rows in adversarial families to
`BENIGN_IN_ADVERSARIAL_FAMILY_IDS`, and rerun. Intake fails closed on
duplicates, scanner findings, schema violations, or provenance mismatches.

## Evidence

- `tests/test_corpus_governance.py` — contract conformance, byte stability,
  provenance cross-checks, tamper rejection, dedupe, scan, split discipline,
  balance, and offline evaluability of the governed corpus.
- `docs/evaluation-contract.md` — frozen dataset/run contract unchanged by
  this expansion.
