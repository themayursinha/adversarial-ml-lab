# Architecture

## High-Level Components

- `src/attacks/`: adversarial attack generators and sample corpora.
- `src/defenses/`: mitigation components (filtering, isolation, uncertainty scoring).
- `src/services/`: orchestration layer for canonicalization, defense pipeline, and eval harness.
- `src/domain/`: typed event and result models.
- `src/web/`: Gradio UI state, controllers, and view composition.
- `src/cli.py`: engineer-facing command line interface.

## Data Flow

1. Untrusted input arrives through web or CLI.
2. Canonicalization normalizes Unicode and strips invisible/control characters.
3. Context-aware filter evaluates policy and attack signatures.
4. Ensemble uncertainty scoring estimates trustworthiness.
5. Structured security events are emitted for audit/reporting.

## Design Principles

- Defense in depth: independent controls, no single-point trust.
- Reproducibility: deterministic eval corpus and stable metrics.
- Interface stability: service-layer abstractions isolate UI from core logic.
