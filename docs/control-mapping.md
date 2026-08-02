# Control Mapping (Security-First)

Each row links to code and tests. Full matrix: [claim-map.md](claim-map.md). `tests/test_doc_claims.py` enforces the hard-coded `CONTROL_SYMBOL_CLAIMS` matrix (symbol import + pytest node existence), not automatic parsing of these docs.

## OWASP LLM Top 10 (2025)

Names follow the [2025 OWASP GenAI LLM Top 10](https://genai.owasp.org/llm-top-10/). Where the lab has no meaningful control, the row is omitted or called out as a **gap** in [claim-map.md](claim-map.md).

- **LLM01 Prompt Injection**
  - Demos: `PromptInjectionAttack` (`src/attacks/prompt_injection.py`) — `tests/test_modules.py::TestPromptInjection::test_payload_listing`
  - Mitigation path: `DefensePipeline` + `ContextAwareFilter` — `tests/test_security_pipeline.py::test_defense_pipeline_emits_detection_events`, `tests/test_modules.py::TestContextFilter::test_detects_injection_indicators`; stage order — `test_defense_pipeline_scores_anomaly_on_raw_input_before_canonicalization`
- **LLM02 Sensitive Information Disclosure**
  - `ContentRedactor` in `src/defenses/isolation_server.py` — `tests/test_modules.py::TestIsolationServer::test_redaction`
- **LLM03 Supply Chain Vulnerabilities**
  - Local/CI: `make security` (`bandit`, `pip_audit`); CI SBOM via CycloneDX — `.github/workflows/ci.yml`, `release.yml`
  - **Gap:** no single pytest asserts the full supply-chain gate; rely on CI/Makefile.
- **LLM04 Data and Model Poisoning**
  - `RagPoisoningDefense`, `RagPoisoningAttack` — `tests/test_security_pipeline.py::test_defense_pipeline_analyze_rag_context_flags_poisoned_chunk`
- **LLM05 Improper Output Handling**
  - `ContextAwareFilter` on canonicalized model output — `tests/test_security_pipeline.py::test_defense_pipeline_emits_detection_events`
- **LLM06 Excessive Agency** — **gap** (no agentic tool-use boundary in scope)
- **LLM07 System Prompt Leakage** — partial demo heuristics in output filter (not a dedicated leakage test suite)
- **LLM08 Vector and Embedding Weaknesses**
  - `RagPoisoningDefense` — `test_defense_pipeline_analyze_rag_context_flags_poisoned_chunk`
- **LLM09 Misinformation** — **gap**
- **LLM10 Unbounded Consumption** — **gap**

## Additional lab controls (not OWASP IDs)

| Topic | Implementation | Tests |
|-------|----------------|-------|
| Pipeline stage order | Anomaly (raw input) → canonicalize → filter → uncertainty | `tests/test_security_pipeline.py::test_defense_pipeline_scores_anomaly_on_raw_input_before_canonicalization` (full four-stage order) |
| Canonicalization | `canonicalize_text` | `tests/test_security_pipeline.py::test_canonicalize_text_removes_zero_width` |
| Context tampering demos | `ContextTamperingAttack` | `tests/test_modules.py` |
| Inference evasion demos | `InferenceEvasionAttack` | `tests/test_modules.py` |
| Session isolation | `ContextIsolationServer` | `TestIsolationServer::test_session_isolation` |
| Uncertainty / review gate | `EnsembleUncertaintyScorer` | `TestUncertaintyScorer::test_human_review_flag` |
| Optional HTTP surface | `src/api/` FastAPI | `tests/test_api.py` |
| Optional NeMo bridge | `NemoguardrailsAction` | gap |
| Optional constitutional review | `ConstitutionalReviewer` | gap (not default pipeline) |

## NIST AI RMF + GenAI Profile Alignment

- **Govern:** `SECURITY.md`, contribution controls, disclosure process.
- **Map:** `docs/threat-model.md`, `docs/architecture.md`, this file, `docs/claim-map.md`.
- **Measure:** baseline eval (`adml eval`), pass/review/risk metrics — `docs/evaluation-methodology.md`.
- **Manage:** CI security checks, container hardening notes — `docs/deployment-hardening.md`, release workflow.