# Security invariants and failure-path map

**Status:** active (P1)  
**Repo tip baseline:** `main` @ merge of honesty PR `#123` (`813c121` lineage)  
**Purpose:** Before benchmark expansion, map every security-critical control to **named tests**, list **failure paths**, and rank **residual risk**.

Companion matrices: [claim-map.md](claim-map.md), [control-mapping.md](control-mapping.md), [threat-model.md](threat-model.md).  
Executable checks: `tests/test_security_invariants.py` plus the node IDs cited below.

## How to read this document

| Column | Meaning |
|--------|---------|
| **Invariant** | Behavior that must stay true for safe defaults |
| **Code** | Primary implementation |
| **Direct tests** | Full pytest node IDs that assert the behavior |
| **Failure paths covered** | Malformed input, missing deps, unsafe default, fail-closed |
| **Residual** | Honest remaining risk |

## 1. Core defense pipeline

| ID | Invariant | Code | Direct tests | Failure paths covered | Residual |
|----|-----------|------|--------------|----------------------|----------|
| P-01 | Stage order is anomaly (raw) → canonicalize → filter → uncertainty | `src/services/defense_pipeline.py` | `tests/test_security_pipeline.py::test_defense_pipeline_scores_anomaly_on_raw_input_before_canonicalization` | N/A (order) | Optional constitutional reviewer not in default path |
| P-02 | Anomaly sees raw zero-width before strip | same | same test | obfuscation path | Heuristic only |
| P-03 | Detection events emitted on blocked adversarial output | `DefensePipeline.analyze_output` | `tests/test_security_pipeline.py::test_defense_pipeline_emits_detection_events` | high-risk output | Not a full exploit suite |
| P-04 | Canonicalization removes zero-width / control chars | `src/services/canonicalization.py` | `tests/test_security_pipeline.py::test_canonicalize_text_removes_zero_width`, `tests/test_security_invariants.py::test_canonicalize_strips_control_chars_and_preserves_empty` | empty string, controls | Does not decode encodings |
| P-05 | Canonicalization rejects non-text types fail-closed | `canonicalize_text` | `tests/test_security_invariants.py::test_canonicalize_rejects_non_str` | type error | — |

## 2. Isolation and redaction

| ID | Invariant | Code | Direct tests | Failure paths covered | Residual |
|----|-----------|------|--------------|----------------------|----------|
| I-01 | Sessions are isolated per id | `ContextIsolationServer` | `tests/test_security_invariants.py::test_isolation_cross_session_context_not_shared` | cross-session | In-process only |
| I-02 | Basic redaction removes common secrets | `ContentRedactor` | `tests/test_modules.py::TestIsolationServer::test_redaction` | email/API-like patterns | Pattern-based only |
| I-03 | Expired sessions fail closed (return None) | `get_session` | `tests/test_security_invariants.py::test_isolation_expired_session_fails_closed` | expiry | Clock skew |
| I-04 | Unknown session integrity check fails closed | `verify_context_integrity` | `tests/test_security_invariants.py::test_isolation_unknown_session_integrity_fails_closed` | missing session | — |
| I-05 | Context length anomaly fails closed | `verify_context_integrity` | `tests/test_security_invariants.py::test_isolation_context_length_anomaly_fails_closed` | injection via length | Heuristic threshold +2 |
| I-06 | `process_request` fails closed on bloated client context | `process_request` | `tests/test_security_invariants.py::test_isolation_process_request_fails_closed_on_bloated_context` | request-level tamper | — |

## 3. Human review / uncertainty

| ID | Invariant | Code | Direct tests | Failure paths covered | Residual |
|----|-----------|------|--------------|----------------------|----------|
| U-01 | High uncertainty can flag human review | `EnsembleUncertaintyScorer` | `tests/test_security_invariants.py::test_human_review_flag_is_asserted_not_vacuous` | review path | Calibration not production-grade |
| U-02 | Pipeline surfaces `needs_human_review` | `PipelineResult` | `tests/test_security_invariants.py::test_pipeline_surfaces_needs_human_review_field` | blocked or review on adversarial | Threshold config |

## 4. RAG

| ID | Invariant | Code | Direct tests | Failure paths covered | Residual |
|----|-----------|------|--------------|----------------------|----------|
| R-01 | Poisoned chunks flagged via defense | `RagPoisoningDefense` | `tests/test_security_pipeline.py::test_defense_pipeline_analyze_rag_context_flags_poisoned_chunk` | poisoned content | Heuristic |
| R-02 | Empty retrieval is safe no-op | `RagPoisoningDefense.analyze` | `tests/test_security_invariants.py::test_rag_defense_empty_chunks_safe` | empty list | — |
| R-03 | Missing RAG extra fails with actionable error | CLI rag path | `tests/test_cli.py::test_rag_without_rag_extra_returns_actionable_error` | missing dependency | — |
| R-04 | Default store is filesystem-backed under `./data/chroma` (or env) | `RagVectorStore` | `tests/test_security_invariants.py::test_rag_vector_store_defaults_to_filesystem_persist` | default path | Not pure in-memory |
| R-05 | Gradio demo may use lighter shortcuts than service RAG | docs + web controllers | documented in architecture; not full service path | demo vs service gap | **Do not treat Gradio as production RAG gateway** |

## 5. Simulation-first / live backends

| ID | Invariant | Code | Direct tests | Failure paths covered | Residual |
|----|-----------|------|--------------|----------------------|----------|
| S-01 | `LLMClient()` defaults to simulation | `llm_client.py` | `tests/test_doc_claims.py::test_llm_client_defaults_to_simulation_mode` | default | — |
| S-02 | CLI no-`--mode` stays simulation (no ambient-key leak) | `_resolve_mode` | `tests/test_cli.py::test_resolve_mode_defaults_to_simulation`, `tests/test_cli.py::test_run_scan_command_emits_json` | unsafe default | — |
| S-03 | Explicit `--mode auto` enables env auto-detect | `_resolve_mode("auto")` | `tests/test_cli.py::test_resolve_mode_auto_means_env_detect` | opt-in live | Operator responsibility |
| S-04 | OpenAI mode without key fails closed | backends | `tests/test_modules.py::TestLLMClient::test_openai_mode_requires_api_key` | missing credential | — |
| S-05 | Gradio `APP_STATE` always simulation | `src/web/state.py` | `tests/test_web_state.py::test_app_state_singleton_is_simulation` | privacy default | No runtime toggle in stock UI |
| S-06 | FastAPI health reports simulation by default | `create_app` | `tests/test_api.py::test_health_endpoint` | default API | Optional live via env on API process |

## 6. API surface

| ID | Invariant | Code | Direct tests | Failure paths covered | Residual |
|----|-----------|------|--------------|----------------------|----------|
| A-01 | `/health` ok + simulation | routes | `tests/test_api.py::test_health_endpoint` | — | No authn |
| A-02 | `/scan` clean vs adversarial | routes | `tests/test_api.py::test_scan_endpoint_clean_input`, `tests/test_api.py::test_scan_endpoint_adversarial_input` | policy path | No authn/rate limit |
| A-03 | Missing body / invalid task → 422 | pydantic | `tests/test_api.py::test_scan_endpoint_validation`, `tests/test_api.py::test_scan_endpoint_invalid_task` | malformed | — |
| A-04 | Unknown eval suite → 404 | routes | `tests/test_api.py::test_eval_endpoint_unknown_suite` | missing suite | — |
| A-05 | Null content rejected; empty string handled | schemas/routes | `tests/test_security_invariants.py::test_api_scan_rejects_null_content`, `tests/test_security_invariants.py::test_api_scan_accepts_empty_string_content` | null + empty | Whitespace-only still accepted |

## 7. Packaging / supply chain defaults

| ID | Invariant | Code | Direct tests | Failure paths covered | Residual |
|----|-----------|------|--------------|----------------------|----------|
| K-01 | Package gate fails closed on missing import | package gate | `tests/test_package_gate.py::test_package_gate_fails_closed_on_missing_import` | missing dep | — |
| K-02 | Heavy ML not in default install | packaging | `tests/test_packaging.py::test_heavy_ml_dependencies_are_not_installed_by_default` | unsafe default bloat | — |
| K-03 | Optional extras declared | pyproject | `tests/test_packaging.py::test_optional_extras_define_rag_vision_and_tracking_dependencies` | — | — |
| K-04 | Baseline eval packaged (50 cases) | resources | CLI/API eval tests | missing resource paths covered in eval validators | Small baseline only |
| K-05 | Dockerfile default is Gradio | Dockerfile | `tests/test_doc_claims.py::test_dockerfile_default_entrypoint_runs_gradio_app` | entrypoint | App binds `0.0.0.0:7860` in `app.py` — operator network exposure |

## 8. Evaluation contract fail-closed (selected)

Many validators already cover malformed JSONL, missing fields, parity, digest tamper. Representative:

- `tests/test_evaluation_contract.py::test_load_evaluation_cases_fails_closed_on_malformed_json`
- `tests/test_eval_validator.py` missing field / malformed cases
- `tests/test_eval_integration.py::test_validate_then_metadata_fails_when_dataset_tampered_after_validation`

## 9. Residual risk ranking (pre-P2)

| Rank | Risk | Why it still matters | Gate impact |
|------|------|----------------------|-------------|
| 1 | **No API/web authentication** | Anyone who can reach Gradio/API can scan content | Document; bind loopback in prod notes |
| 2 | **Heuristic defenses only** | Filters/anomaly/RAG are demo-grade, not production DLP | Do not market as enterprise gate |
| 3 | **Gradio vs service RAG gap** | Demo shortcuts ≠ full `RagPoisoningDefense` path | Keep architecture honesty |
| 4 | **Pattern redaction gaps** | Encoding / novel secret formats bypass | Same as threat model |
| 5 | **Ambient `--mode auto`** | Explicit but still easy to leak content if misused | Operator education |
| 6 | **Small 50-case baseline** | Not broad benchmark coverage | Blocks vanity claims; unlocks careful P2 |

## 10. Coverage artifact

Measured on this branch (local):
- Focused security modules line coverage (selected tests): see generated `evidence/security-coverage.json` (not always committed).
- Full suite after this change: **264** tests.

Generate locally (not committed if gitignored):

```bash
venv/bin/python -m pytest -q \
  --cov=src/services --cov=src/defenses --cov=src/rag --cov=src/api --cov=src/web \
  --cov-report=term-missing --cov-report=json:evidence/security-coverage.json \
  tests/test_security_invariants.py tests/test_security_pipeline.py tests/test_modules.py \
  tests/test_api.py tests/test_web_state.py tests/test_cli.py tests/test_package_gate.py \
  tests/test_doc_claims.py
```

Commit gate for this P1 card: **all listed direct tests pass** + `make lint` + `make typecheck` + full `pytest`.

## 11. Go / no-go for P2 benchmark expansion

**Conditional go** only if:

1. This map remains linked from claim-map / architecture  
2. `tests/test_security_invariants.py` green  
3. No new doc/code honesty regressions  
4. Residual risks #1–#3 accepted explicitly in P2 design (local-only defaults, no overclaim)

P1 gate card should re-run clean checkout verification after this lands.

## 12. P1 gate decision

See [p1-gate-decision-2026-08-02.md](p1-gate-decision-2026-08-02.md) for the conditional GO record and fresh verification evidence.
