# Contributing

## Development Setup

```bash
python3 -m venv venv
venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements.txt
```

## Common Commands

```bash
make lint
make typecheck
make test
make security
```

## Pull Request Requirements

- Keep changes scoped and documented.
- Add or update tests for behavioral changes.
- Run lint, type checks, and tests locally before pushing.
- Update docs for any user-facing behavior changes.

## Commit Guidance

Use clear, imperative commit messages. Example:
- `Add canonicalization stage to defense pipeline`
- `Split Gradio app into web controllers and UI modules`

## Security-Sensitive Contributions

For changes touching detection logic, policy rules, or redaction:
- Include adversarial test cases.
- Include at least one false-positive/false-negative discussion in PR notes.
- Confirm no secrets are logged in new code paths.
