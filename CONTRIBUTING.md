# Contributing

## Development Setup

```bash
python3 -m venv venv
venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements-dev.txt
```

## Common Commands

```bash
make lint
make typecheck
make test
make security
make package
make release-check
```

## Pull Request Requirements

- Keep changes scoped and documented.
- Add or update tests for behavioral changes.
- Run lint, type checks, and tests locally before pushing.
- Update docs for any user-facing behavior changes.
- If a change affects packaging, CLI behavior, or release docs, run `make release-check`.

## Commit Guidance

Use clear, imperative commit messages. Example:
- `Add canonicalization stage to defense pipeline`
- `Split Gradio app into web controllers and UI modules`

## Security-Sensitive Contributions

For changes touching detection logic, policy rules, or redaction:
- Include adversarial test cases.
- Include at least one false-positive/false-negative discussion in PR notes.
- Confirm no secrets are logged in new code paths.

## Maintainer Release Notes

- Package version is sourced from `src/__init__.py`.
- The packaged baseline evaluation dataset is part of the wheel/sdist and should remain usable via `adml eval --suite baseline`.
- Follow [`docs/release-checklist.md`](docs/release-checklist.md) before tagging a public release.
