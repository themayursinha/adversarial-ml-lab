# Threat Model

Scope: **local lab / demo** for adversarial LLM patterns. This is not a production SaaS threat model.

## Assets

- Prompt and context data submitted by users.
- Model outputs consumed by downstream users or systems.
- Session context in context-isolation workflows (in-process store).
- Logs and evaluation artifacts.

## Trust Boundaries

| Boundary | What crosses it | Limitation in this repo |
|----------|-----------------|-------------------------|
| User input → application | Web, CLI, optional API | No built-in end-user authentication |
| Session store → handler | `ContextIsolationServer` | Process memory only; not a distributed session service |
| Simulated vs live LLM | `LLMClient` mode switch | Live modes require operator-supplied keys/network |
| Container → host | Docker / compose profiles | Default image runs Gradio only; API is operator-enabled |
| CI → release artifact | GitHub Actions, SBOM | GitHub Releases distribution; not PyPI |

## Primary Adversary Goals

- Prompt injection to override task intent.
- Context tampering to smuggle fake conversation history.
- Inference evasion using obfuscation and canonicalization bypass attempts.
- RAG corpus poisoning to steer retrieval.
- Sensitive data leakage via logs or output reflection.

## Defensive Controls (implemented)

- Heuristic anomaly scoring on **raw** input (`TextAnomalyScorer`) before normalization.
- Input/output canonicalization (`canonicalize_text` in `src/services/canonicalization.py`) before signature filtering and uncertainty scoring.
- Context-aware output filtering (`ContextAwareFilter`).
- Context isolation, tamper checks, and redaction (`ContextIsolationServer`, `ContentRedactor`).
- Ensemble uncertainty scoring and human-review signal (`EnsembleUncertaintyScorer`).
- RAG poisoning analysis (`RagPoisoningDefense`).
- Structured `SecurityEvent` emission from `DefensePipeline`.

## Out of scope / unsupported guarantees

- Production-grade sandboxing, hardware isolation, or tenant-scoped data planes.
- Guaranteed resistance to adaptive human red teams or nation-state adversaries.
- Safe public exposure of `adml api` without operator-imposed network and auth controls.

Traceability: [Claim-to-Code Map](claim-map.md).