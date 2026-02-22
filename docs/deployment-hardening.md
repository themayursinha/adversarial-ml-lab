# Deployment Hardening

## Container Runtime

- Use non-root runtime user (already configured in Dockerfile).
- Pin base image digests for reproducibility.
- Enable read-only root filesystem when deploying.
- Drop unnecessary Linux capabilities.

## Network and Secrets

- Keep API mode disabled by default (simulation-first).
- Inject secrets via environment variables only.
- Do not log prompts containing credentials or tokens.

## Operational Controls

- Health checks enabled.
- CI runs static checks, tests, and security scans.
- Generate SBOM for each release candidate.
