# Claim-to-Code Map

This document ties public architecture, threat-model, and control-mapping statements to **live modules** and **named tests**. The hard-coded contract matrix in `tests/test_doc_claims.py::CONTROL_SYMBOL_CLAIMS` checks that each listed symbol imports and that each cited pytest node id exists; it does **not** parse this markdown file or prove that a test exercises every claim. Use **gap** / **partial** labels below when no direct test exists.

## Simulation-first boundaries

| Claim | Code truth | Tests |
|-------|------------|-------|
| `LLMClient()` defaults to simulation | `LLMClient(mode=LLMMode.SIMULATION)`; `SimulatedLLM` in `src/utils/llm_client.py` | `tests/test_doc_claims.py::test_llm_client_defaults_to_simulation_mode` |
| CLI defaults to simulation without `--mode` (privacy-safe) | `_resolve_mode(None)` → `LLMMode.SIMULATION`; scan/fuzz help text | `tests/test_cli.py::test_resolve_mode_defaults_to_simulation` |
| CLI `--mode auto` enables env auto-detect via `from_env` | `_resolve_mode("auto")` is `None`; `from_env` prefers Anthropic → OpenAI → Ollama | `tests/test_cli.py::test_resolve_mode_auto_means_env_detect`, `tests/test_modules.py::TestLLMClient::test_from_env_auto_detects_openai` |
| Explicit `--mode` backend name forces that backend | `LLMClient.from_env(mode=...)` and CLI `--mode` | `tests/test_modules.py::TestLLMClient::test_from_env_explicit_mode_overrides` |
| `adml scan` reports simulation when env is empty / default mode | `run_scan_command` uses resolved mode | `tests/test_cli.py::test_run_scan_command_emits_json` (clears backend env via `monkeypatch`) |
| Gradio web always uses simulation `APP_STATE` (privacy note) | module-level `APP_STATE = create_app_state()` → `LLMMode.SIMULATION`; controllers import `APP_STATE` | `tests/test_web_state.py::test_create_app_state_defaults_to_simulation_even_if_openai_key_set`, `tests/test_web_state.py::test_app_state_singleton_is_simulation` |
| Gradio demo is the default container entrypoint | `Dockerfile` `ENTRYPOINT ["python", "app.py"]` | `tests/test_doc_claims.py::test_dockerfile_default_entrypoint_runs_gradio_app` |
| FastAPI is opt-in (`adml api` / compose `api` service) | `src/api/server.py`; compose overrides image entrypoint | `tests/test_api.py::test_health_endpoint`, `tests/test_doc_claims.py::test_compose_api_overrides_entrypoint_and_simulation_first_env` |
| Not production multi-tenant isolation | In-process session store only; no authn/z on API | — (documented limitation) |

## Trust boundaries and data flow

| Claim | Code truth | Tests |
|-------|------------|-------|
| Untrusted input via web or CLI | `src/web/controllers.py`, `src/cli.py` `scan`/`fuzz` | `tests/test_cli.py` |
| Output path: anomaly on **raw** input, then canonicalization, then filter and uncertainty | `DefensePipeline.analyze_output` order in `src/services/defense_pipeline.py` | `tests/test_security_pipeline.py::test_defense_pipeline_scores_anomaly_on_raw_input_before_canonicalization` (asserts full stage order) |
| Canonicalization utility | `canonicalize_text` in `src/services/canonicalization.py` | `tests/test_security_pipeline.py::test_canonicalize_text_removes_zero_width` |
| Structured security events | `src/domain/security_events.py`, `PipelineResult.events` | `tests/test_security_pipeline.py::test_defense_pipeline_emits_detection_events` |
| RAG retrieved-chunk defense | `DefensePipeline.analyze_rag_context` → `RagPoisoningDefense` | `tests/test_security_pipeline.py::test_defense_pipeline_analyze_rag_context_flags_poisoned_chunk` |
| Baseline `rag_poisoning` **eval family** (poisoned context in JSONL, not chunk API) | `run_evaluation_suite` on packaged baseline | `tests/test_security_pipeline.py::test_run_evaluation_suite_baseline_reports_new_metrics` (family label only) |

## OWASP LLM Top 10 (2025) — subset mapped to this lab

Official names per [OWASP GenAI LLM Top 10 (2025)](https://genai.owasp.org/llm-top-10/). Unsupported IDs are listed under gaps rather than forced mappings.

| Control | Module(s) | Primary tests |
|---------|-----------|---------------|
| LLM01 Prompt injection (demos) | `PromptInjectionAttack` | `tests/test_modules.py::TestPromptInjection::test_payload_listing` |
| LLM01 Mitigation | `DefensePipeline`, `ContextAwareFilter` | `tests/test_security_pipeline.py::test_defense_pipeline_emits_detection_events`, `tests/test_modules.py::TestContextFilter::test_detects_injection_indicators` |
| LLM02 Sensitive information disclosure | `ContentRedactor` | `tests/test_modules.py::TestIsolationServer::test_redaction` |
| LLM03 Supply chain | CI `bandit`, `pip_audit`, CycloneDX SBOM | **gap:** no dedicated pytest; `make security`, `.github/workflows/ci.yml` |
| LLM04 Data and model poisoning | `RagPoisoningDefense`, `RagPoisoningAttack` | `tests/test_security_pipeline.py::test_defense_pipeline_analyze_rag_context_flags_poisoned_chunk` |
| LLM05 Improper output handling | `ContextAwareFilter` on canonical model output | `tests/test_security_pipeline.py::test_defense_pipeline_emits_detection_events` |
| LLM06 Excessive agency | — | **gap:** no tool/agent execution boundary controls |
| LLM07 System prompt leakage (demo heuristics) | Output filter signatures (e.g. “reveal system prompt”) | **partial:** `test_defense_pipeline_emits_detection_events` (adversarial output, not a dedicated leakage suite) |
| LLM08 Vector and embedding weaknesses | `RagPoisoningDefense` | `tests/test_security_pipeline.py::test_defense_pipeline_analyze_rag_context_flags_poisoned_chunk` |
| LLM09 Misinformation | — | **gap:** no misinformation/factuality control |
| LLM10 Unbounded consumption | — | **gap:** no rate/cost enforcement |

## Additional lab controls (not OWASP IDs)

| Topic | Implementation | Tests |
|-------|----------------|-------|
| Context tampering demos | `ContextTamperingAttack` | `tests/test_modules.py` (attack family tests) |
| Inference evasion demos | `InferenceEvasionAttack` | `tests/test_modules.py` |
| Session isolation | `ContextIsolationServer` | `tests/test_modules.py::TestIsolationServer::test_session_isolation` |
| Uncertainty / human-review signal | `EnsembleUncertaintyScorer` | `tests/test_modules.py::TestUncertaintyScorer::test_human_review_flag` |
| Optional NeMo Guardrails bridge | `NemoguardrailsAction` | **gap:** no unit test |
| Optional constitutional reviewer | `ConstitutionalReviewer` | **gap:** not in default pipeline |

## Public CLI surface (0.2.x)

| Command | Purpose | Tests |
|---------|---------|-------|
| `scan` | Run defense pipeline + LLM via `from_env` | `tests/test_cli.py::test_run_scan_command_emits_json` |
| `eval` | Baseline JSONL harness (50 cases packaged) | `tests/test_cli.py::test_run_eval_command_uses_packaged_dataset_by_default` |
| `serve` | Gradio web demo | manual / release-check smoke |
| `api` | FastAPI HTTP surface | `tests/test_api.py` |
| `fuzz` | Automated attack families | `tests/test_doc_claims.py::test_documented_cli_commands_exist` |
| `rag` | Vector store + poison defense (needs `[rag]` extra) | `tests/test_cli.py::test_rag_without_rag_extra_returns_actionable_error` |

## Evaluation methodology claims

| Claim | Code | Tests |
|-------|------|-------|
| Packaged baseline dataset | `src/resources/datasets/*.jsonl` via `default_evaluation_dataset()` | `tests/test_cli.py::test_run_eval_command_uses_packaged_dataset_by_default` |
| Deterministic heuristic eval default | `run_evaluation_suite` + simulation LLM | `tests/test_security_pipeline.py::test_run_evaluation_suite_baseline_reports_new_metrics` |
| Frozen dataset/run contract | `src/eval/contract.py`, baseline manifest + schema | `tests/test_evaluation_contract.py` |
| Optional LLM-as-judge | `run_evaluation_with_judge`, `src/eval/judge.py` | CLI `--judge`; **gap:** no dedicated pytest for judge path |

## Unsupported guarantees (explicit)

- No hosted policy engine or tenant-scoped data plane.
- No guarantee that optional API/FastAPI deployments are safe on the public internet without your own auth, rate limits, and network controls.
- `ConstitutionalReviewer` and `NemoguardrailsAction` are library integrations, not default enforcement.
- RAG workflows use the optional `[rag]` extra and in-process vector store; there is no `make up-rag` compose stack.

## Residual gaps

- OWASP LLM03 supply chain: document CI/Makefile only until a pytest contract exists.
- OWASP LLM06, LLM09, LLM10: not implemented in this lab scope.
- Add unit tests for `ConstitutionalReviewer`, `NemoguardrailsAction`, and `run_fuzz_command` happy path.
- Baseline `rag_poisoning` eval rows exercise the output pipeline on poisoned **context** strings; they do not call `analyze_rag_context` (separate test added for chunk defense).