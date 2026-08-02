# Security coverage summary (P1 invariant map)

Generated: 2026-08-02 (local, branch `hermes/p1-security-invariant-map-20260802`)

## Full suite

- **264** tests passed (`pytest -q`)
- lint / typecheck clean

## Focused security modules

Selected tests: `test_security_invariants`, `test_security_pipeline`, `test_modules`,
`test_api`, `test_web_state`, `test_cli`, `test_package_gate`, `test_doc_claims`.

| Metric | Value |
|--------|------:|
| Statements | 1728 |
| Covered | 1057 |
| Line coverage | **61.2%** |

High coverage on: canonicalization, poison defense, defense pipeline, context filter, API schemas/server, web state.  
Lower (expected): Gradio UI controllers, optional tracking, constitutional reviewer, full isolation process_request path.

Regenerate JSON (gitignored optional / local only):

```bash
venv/bin/python -m pytest -q \
  --cov=src/services --cov=src/defenses --cov=src/rag --cov=src/api --cov=src/web \
  --cov-report=json:evidence/security-coverage.json \
  tests/test_security_invariants.py tests/test_security_pipeline.py tests/test_modules.py \
  tests/test_api.py tests/test_web_state.py tests/test_cli.py tests/test_package_gate.py \
  tests/test_doc_claims.py
```
