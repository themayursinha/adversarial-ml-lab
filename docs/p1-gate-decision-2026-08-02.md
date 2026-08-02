# P1 gate decision — 2026-08-02

**Gate:** baseline integrity and repository truth accepted  
**Checkout:** `main` @ `8be093762cd1d742e72938ab7769e101c11a63c4`  
**Operator:** Hermes (verification-only)  
**Date:** 2026-08-02 (Europe/Berlin)

## Decision

### **GO (conditional) for P2 benchmark expansion**

The repository is trustworthy enough to begin carefully scoped P2 work, provided residual risks below remain accepted and no new honesty/integrity regressions are introduced.

## Fresh verification results

| Check | Result | Notes |
|-------|--------|-------|
| `make lint` | **PASS** | ruff clean |
| `make typecheck` | **PASS** | mypy, 59 source files |
| `pytest` full suite | **PASS** | **269** passed, 1 known Starlette TestClient deprecation warning |
| `make security` | **PASS** | bandit: 0 high/medium; pip_audit: no known vulns |
| `make package` | **PASS** | sdist+wheel built; twine check PASSED |
| baseline eval (`adml eval --suite baseline`) | **PASS** | 50 cases; pass_rate **0.92**; simulation; digest `99a6515f…baded9` |
| `docker compose config --quiet` | **PASS** | valid compose |
| Docker image build (`adversarial-ml-lab:p1-gate`) | **PASS** | multi-stage build completed |
| Docker CLI help smoke | **PASS** | `python -m src.cli --help` in image |
| Docker scan smoke (stdin, `--network none`, simulation) | **PASS** | simulation scan path exercised |

## Claim / integrity traceability

| Artifact | Status |
|----------|--------|
| [claim-map.md](claim-map.md) | Present; linked from architecture |
| [security-invariants.md](security-invariants.md) | Present (P1 map + failure paths) |
| [security-coverage-summary.md](security-coverage-summary.md) | Present |
| Honesty PR #123 | Merged (CLI default simulation; Gradio APP_STATE simulation) |
| Invariant PRs #124 / #125 | Merged after Codex tip reviews |

No open integrity defects of the class that previously blocked the gate (docs vs code drift on simulation defaults, Gradio privacy claim, vacuous pipeline/isolation tests) remain on `main` after #123–#125.

## Residual risks (accepted for conditional GO)

Ranked from [security-invariants.md](security-invariants.md) §9 and gate review:

1. **No API/web authentication** — anyone who can reach Gradio/API can submit content. Bind loopback / reverse-proxy auth for any shared deploy.
2. **Heuristic defenses only** — filters/anomaly/RAG are lab-grade, not enterprise DLP. Do not market as a production gateway.
3. **Gradio vs service RAG gap** — demo shortcuts ≠ full service RAG path. Keep architecture honesty.
4. **Pattern redaction gaps** — encoding/novel secrets can bypass. Expected residual.
5. **`--mode auto` opt-in** — explicit but can still leak content if misused. Operator responsibility.
6. **Small 50-case baseline** — pass_rate 0.92 is not broad benchmark credibility; P2 must add provenance-labeled corpus work without overclaim.
7. **API `/scan` uses `LLMClient.from_env()` when process env has keys** — FastAPI path is operator-enabled; CLI/Gradio defaults stay simulation-first. Document and keep API opt-in.

## What would force NO-GO

- Reintroduction of silent live-backend defaults on CLI/Gradio without opt-in  
- Failing lint/typecheck/tests/security/package/baseline/docker smoke on clean checkout  
- Unresolved claim-to-code contradictions in claim-map / security-invariants  
- License/data contamination or high-risk corpus issues (P2 concern)

## Scope of this GO

**In scope after GO:** P2 cards (corpus expansion, thresholds, ablations) under existing simulation-first and honesty rules.  
**Out of scope:** waiving residual risks above; live multi-tenant claims; production SOC marketing.

## Evidence handles

- Commit SHA: `8be093762cd1d742e72938ab7769e101c11a63c4`
- Baseline dataset digest: `99a6515f3488f25e4ebaaf44880b42779b5671bd0045d92f793d37b475baded9`
- Local gate logs (operator machine, not committed): lint/typecheck/pytest/security/package/eval/docker under `/tmp/p1-gate-*.txt`

## Sign-off

Hermes verification-only recommendation: **conditional GO**.  
Independent Codex review requested on the PR carrying this decision record.
