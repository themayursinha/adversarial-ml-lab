# Threat Model

## Assets

- Prompt and context data submitted by users.
- Model outputs consumed by downstream users or systems.
- Session context in context-isolation workflows.
- Logs and evaluation artifacts.

## Trust Boundaries

- User input -> application boundary.
- Session context store -> request handler boundary.
- Containerized runtime -> host/runtime environment boundary.
- CI pipeline -> release artifact boundary.

## Primary Adversary Goals

- Prompt injection to override task intent.
- Context tampering to smuggle fake conversation history.
- Inference evasion using obfuscated text.
- Sensitive data leakage via logs or output reflection.

## Defensive Controls

- Input canonicalization before detection.
- Context-aware output filtering.
- Context isolation + tamper checks.
- Ensemble uncertainty scoring and review gate.
- Redaction controls for common secret/PII indicators.
