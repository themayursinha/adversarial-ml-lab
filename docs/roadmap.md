# Project Status

## Current Release Line: 0.2.x

The current release line is intended to be publicly shareable and reproducible for security engineers.

Completed in this line:

- Modular web stack in `src/web`
- Service-layer defense pipeline (anomaly → canonicalization → filter → uncertainty) and RAG defense hook
- CLI workflows: `scan`, `eval`, `serve`, `api`, `fuzz`, `rag`, `plugin`, `config`, optional `image-attack`
- Packaged baseline evaluation dataset (50 cases) for installed CLI and API smoke tests
- RAG poisoning simulation and defense laboratory (in-memory vector store; `[rag]` extra for embeddings)
- Optional FastAPI surface and compose `api` service (operator-enabled, not default Gradio container)
- Automated red-team `fuzz` command over attack families
- Heuristic `TextAnomalyScorer` and optional `ConstitutionalReviewer` module (reviewer not wired into default pipeline)
- Optional LLM backends (simulation default; OpenAI/Anthropic/Ollama when configured)
- Optional `adml eval --judge` LLM-as-judge path (`src/eval/judge.py`)
- Governance, release, and supply-chain documentation with [claim-to-code map](claim-map.md)

## Stable Public Surface for This Release

- Web demo launched through `app.py`
- CLI entrypoints exposed through `adml` / `src.cli`
- Baseline evaluation workflow and dataset schema
- RAG poisoning demonstration tab in Web UI
- Structured security event outputs from the service layer

## Future Work

Possible extensions — **not** release commitments:

### Core Lab & Telemetry

- Expand the eval corpus with labeled false-positive and false-negative cases
- Add policy packs for more agentic workflow scenarios
- Add structured telemetry export sinks beyond optional W&B (`[tracking]` extra)
- Wire `ConstitutionalReviewer` into an opt-in pipeline stage with tests
- Add release provenance attestations beyond the current SBOM + sigstore bundle on release

### Advanced Attack Vectors

- **Multi-Turn Jailbreaks**: deeper multi-message conditioning scenarios in the eval corpus
- **Data Exfiltration Architectures**: Markdown/image exfiltration demos
- **"Many-Shot" Evasion**: large fake benign Q&A context stuffing scenarios

### Enhanced Defense Mechanisms

- Stronger model-based perplexity filters (current `TextAnomalyScorer` is heuristic trigram/entropy analysis)
- Broader LLM-as-judge coverage in CI (today optional and network-dependent)

### Real-World Integration & Infrastructure

- **GitHub Action / CI Scanner:** repo-local composite action `.github/actions/adml-scan` is used by `adml-pr-scan.yml`; **gap:** versioned marketplace packaging and external consumer hardening remain future work.
- RAG: use `adml rag` with the `[rag]` extra locally (no dedicated compose RAG stack; removed misleading `make up-rag`).
- Deeper NeMo Guardrails integration tests for `NemoguardrailsAction`