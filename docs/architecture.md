# Architecture

## High-Level Components

- `src/attacks/`: adversarial attack generators and sample corpora (prompt injection, context tampering, inference evasion, RAG poisoning, fuzzer, optional `vision/`).
- `src/defenses/`: mitigation components (context filter, isolation/redaction, uncertainty and anomaly scorers, optional constitutional reviewer module).
- `src/services/`: orchestration — canonicalization, `DefensePipeline`, evaluation harness, optional tracing/tracking.
- `src/domain/`: typed security events and result models.
- `src/rag/`: in-memory vector store helpers and RAG poisoning defense (optional `[rag]` extra for embeddings).
- `src/web/`: Gradio UI state, controllers, and view composition.
- `src/api/`: optional FastAPI HTTP surface (`adml api`); not the default Docker entrypoint.
- `src/cli.py`: engineer-facing CLI (`scan`, `eval`, `serve`, `api`, `fuzz`, `rag`, …).
- `src/plugins/` and `src/integrations/`: optional extension and NeMo Guardrails bridge code.

See [Claim-to-Code Map](claim-map.md) for module-to-test traceability.

## Data Flow (default output path)

1. Untrusted input arrives through web, CLI `scan`, or API `/scan`.
2. `TextAnomalyScorer` flags obfuscated or high-entropy payloads (heuristic, not a hosted model).
3. `canonicalize_text` normalizes Unicode and strips invisible/control characters.
4. `ContextAwareFilter` evaluates policy and attack signatures on canonical output.
5. `EnsembleUncertaintyScorer` estimates trustworthiness and may signal human review.
6. `SecurityEvent` records are attached to pipeline results for audit/reporting.

RAG workflows add retrieval → `RagPoisoningDefense.analyze` before context is trusted.

## Simulation vs optional live backends

- **Constructor default:** `LLMClient()` uses `LLMMode.SIMULATION` (`SimulatedLLM`) — no external inference required.
- **CLI/API default path:** `LLMClient.from_env()` (and CLI without explicit `--mode`) auto-selects Anthropic, OpenAI, or Ollama when the matching env vars are set; otherwise falls back to simulation.
- **Explicit override:** pass `mode=` to `from_env` or `--mode` on the CLI to force simulation or a specific backend.
- **Not provided:** a managed multi-tenant runtime, authenticated API gateway, or production SOC telemetry pipeline.

## Design Principles

- Defense in depth: independent controls; default pipeline chains anomaly → canonicalization → filter → uncertainty.
- Reproducibility: deterministic baseline eval corpus and stable metrics in simulation mode.
- Interface stability: service-layer abstractions isolate UI/API from core logic.