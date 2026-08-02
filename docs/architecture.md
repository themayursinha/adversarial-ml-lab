# Architecture

## High-Level Components

- `src/attacks/`: adversarial attack generators and sample corpora (prompt injection, context tampering, inference evasion, RAG poisoning, fuzzer, optional `vision/`).
- `src/defenses/`: mitigation components (context filter, isolation/redaction, uncertainty and anomaly scorers, optional constitutional reviewer module).
- `src/services/`: orchestration — canonicalization, `DefensePipeline`, evaluation harness, optional tracing/tracking.
- `src/domain/`: typed security events and result models.
- `src/rag/`: local filesystem-backed vector store helpers (default under `./data/chroma` or `ADML_CHROMA_PERSIST_DIR`) and RAG poisoning defense (optional `[rag]` extra for embeddings). Not a pure in-memory-only store.
- `src/web/`: Gradio UI state, controllers, and view composition.
- `src/api/`: optional FastAPI HTTP surface (`adml api`); not the default Docker entrypoint.
- `src/cli.py`: engineer-facing CLI (`scan`, `eval`, `serve`, `api`, `fuzz`, `rag`, …).
- `src/plugins/` and `src/integrations/`: optional extension and NeMo Guardrails bridge code.

See [Claim-to-Code Map](claim-map.md) for module-to-test traceability and
[Security invariants and failure-path map](security-invariants.md) for P1 security coverage.

## Data Flow (default output path)

1. Untrusted input arrives through web, CLI `scan`, or API `/scan`.
2. `TextAnomalyScorer` flags obfuscated or high-entropy payloads (heuristic, not a hosted model).
3. `canonicalize_text` normalizes Unicode and strips invisible/control characters.
4. `ContextAwareFilter` evaluates policy and attack signatures on canonical output.
5. `EnsembleUncertaintyScorer` estimates trustworthiness and may signal human review.
6. `SecurityEvent` records are attached to pipeline results for audit/reporting.

RAG CLI/service workflows can run retrieval → `RagPoisoningDefense.analyze` before context is trusted.
The Gradio lab UI may use lighter demo shortcuts (`detect_injection` plus chunk ground-truth flags) rather than the full service RAG path — treat the web demo as a teaching surface, not a production RAG gateway.

## Simulation vs optional live backends

- **Constructor default:** `LLMClient()` uses `LLMMode.SIMULATION` (`SimulatedLLM`) — no external inference required.
- **CLI default path:** without `--mode`, CLI forces **simulation** so ambient API keys cannot accidentally send file/stdin content to a live backend. Help text matches this contract.
- **CLI live opt-in:** pass `--mode auto` to run `LLMClient.from_env()` auto-detect (Anthropic → OpenAI → Ollama → simulation), or pass an explicit backend name.
- **Gradio web:** always uses module-level `APP_STATE` from `create_app_state()` with **simulation**. There is no runtime operator toggle in the launched app; changing that requires code/env wiring beyond the default entrypoint.
- **API path:** uses `LLMClient.from_env()` according to API configuration (operator-enabled service).
- **Not provided:** a managed multi-tenant runtime, authenticated API gateway, or production SOC telemetry pipeline.

## Design Principles

- Defense in depth: independent controls; default pipeline chains anomaly → canonicalization → filter → uncertainty.
- Reproducibility: deterministic baseline eval corpus and stable metrics in simulation mode.
- Interface stability: service-layer abstractions isolate UI/API from core logic.