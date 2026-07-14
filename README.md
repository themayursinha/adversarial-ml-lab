# Adversarial ML Security Lab

Security-focused adversarial LLM lab for engineers who want to demonstrate, test, and explain common attack and defense patterns without relying on external model APIs.

## Status

This project is a polished public `0.2.x` release line intended for sharing, demos, and reproducible security experiments.

- Simulation-first: no live model API integration is required or enabled by default.
- Public surface: web demo, CLI workflows, baseline evaluation suite, and supporting security docs.
- Not a production gateway: this repo demonstrates controls and failure modes; it is not a hosted policy engine or a hardened multi-tenant service.

## Who This Is For

- Security engineers evaluating prompt injection, context tampering, and evasion defenses.
- Researchers or educators who want a compact, reproducible adversarial ML demo lab.
- Reviewers who want a repo with working CI, packaging, and security release hygiene.

## What It Demonstrates

- Indirect prompt injection and output filtering
- Conversation context tampering and session isolation
- Inference evasion via obfuscation and canonicalization
- RAG poisoning and knowledge base security
- Local content scanning for prompt-risk and sensitive-data indicators
- Reproducible evaluation with a packaged baseline dataset

## Quick Start

Clone and install runtime dependencies:

```bash
git clone https://github.com/themayursinha/adversarial-ml-lab.git
cd adversarial-ml-lab
python3 -m venv venv
venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements.txt
```

Run the web demo:

```bash
venv/bin/python app.py
```

Run CLI workflows from the repo checkout:

```bash
venv/bin/python -m src.cli scan --file README.md --task summarize
venv/bin/python -m src.cli eval --suite baseline
venv/bin/python -m src.cli serve --host 0.0.0.0 --port 7860
```

The default installation is CPU-light. Install optional ML features only when needed:

```bash
# Local embedding model for the RAG CLI workflow
venv/bin/python -m pip install ".[rag]"

# Torch and torchvision for image adversarial attacks
venv/bin/python -m pip install ".[vision]"

# Weights & Biases experiment tracking
venv/bin/python -m pip install ".[tracking]"
```

## What It Does Not Do

- It does not ship a real OpenAI-backed runtime. The codebase is intentionally simulation-first.
- It does not claim production-grade sandboxing, tenant isolation, or SOC-ready telemetry pipelines.
- It does not attempt broad benchmark coverage; the included dataset is a small, deterministic baseline suite.

## Documentation

- [Architecture](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [Control Mapping](docs/control-mapping.md)
- [Evaluation Methodology](docs/evaluation-methodology.md)
- [Deployment Hardening](docs/deployment-hardening.md)
- [Project Status](docs/roadmap.md)
- [Release Checklist](docs/release-checklist.md)
- [Security Policy](SECURITY.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## Development and Release Checks

Install development, security, and packaging tools:

```bash
venv/bin/python -m pip install -r requirements-dev.txt
```

Common commands:

```bash
make lint
make typecheck
make test
make security
make eval
make package
make release-check
```

`make release-check` runs the local release verification path: quality gates, security checks, wheel/sdist build, `twine check`, installed CLI smoke test, and packaged baseline evaluation smoke test.

## Docker

The default container uses Chainguard Python images with a non-root runtime profile and installs only the CPU-light core dependencies. RAG embeddings, image attacks, and W&B tracking remain opt-in package extras and are not included in this image.

```bash
docker build -t adversarial-ml-lab .
docker run -p 7860:7860 adversarial-ml-lab
```

## Release

Before tagging a release:

- run `make release-check`
- bump `src/__init__.py`
- review [`docs/release-checklist.md`](docs/release-checklist.md)

Release flow:

```bash
git add src/__init__.py
git commit -m "release: vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main --follow-tags
```

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which:

- reruns quality and security checks
- builds wheel and sdist artifacts
- smoke-tests the packaged CLI and container image
- generates an SBOM
- creates a GitHub Release with the build artifacts attached

The project is intentionally distributed through GitHub Releases only. PyPI/TestPyPI publishing is not part of the release path.

## License

MIT
