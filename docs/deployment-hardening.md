# Deployment Hardening

## Container Runtime

- Non-root runtime user (uid/gid 65532) in the default `Dockerfile` (Chainguard Python).
- Base image digests pinned in `Dockerfile` (`@sha256:…` on builder and runtime stages).
- `docker-compose.yml` `api` service: read-only root, `cap_drop: ALL`, `no-new-privileges`, tmpfs for `/tmp` and cache.
- Default image **entrypoint** is `python app.py` (Gradio). The compose `api` service sets `entrypoint: ["python", "-m", "src.cli"]` and `command: ["api", ...]` so FastAPI starts instead of Gradio.

Recommendations when you deploy beyond local demos:

- Enable read-only root filesystem (compose `api` already sets `read_only: true`).
- Drop unnecessary Linux capabilities (already dropped in compose profile).
- Do not expose `adml api` to the public internet without authentication, TLS termination, and rate limiting.

## Network and Secrets

- **Simulation-first:** no live model API calls unless the operator sets `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `OLLAMA_HOST` (compose `api` leaves `OLLAMA_HOST` empty by default; `make up` keeps that default). `make up-llm` and `make up-full` export `OLLAMA_HOST=http://ollama:11434` for the API container when Ollama is started.
- Inject secrets via environment variables only (`src/utils/llm_client.py` loads keys from env).
- Avoid logging raw prompts that may contain credentials; use structured logging levels in production.

## Operational Controls

- Health checks: Docker `HEALTHCHECK` on Gradio port; compose `api` hits `/health`.
- CI runs lint, tests, `bandit`, `pip_audit`, and SBOM generation (see `.github/workflows/ci.yml`).
- Release workflow rebuilds artifacts, smoke-tests wheel/container, attaches SBOM (and sigstore bundle on release).

See [architecture.md](architecture.md) and [claim-map.md](claim-map.md) for what is **not** hardened by default.