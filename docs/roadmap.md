# Project Status

## Current Release Line: 0.2.x

The current release line is intended to be publicly shareable and reproducible for security engineers.

Completed in this line:

- Modular web stack in `src/web`
- Service-layer defense pipeline and canonicalization flow
- CLI workflows for `scan`, `eval`, and `serve`
- Packaged baseline evaluation dataset for installed CLI use
- Governance, release, and supply-chain documentation

## Stable Public Surface for This Release

- Web demo launched through `app.py`
- CLI entrypoints exposed through `src.cli`
- Baseline evaluation workflow and dataset schema
- Structured security event outputs from the service layer

## Future Work

These are possible future extensions, not release commitments:

- Expand the eval corpus with labeled false-positive and false-negative cases
- Add policy packs for more agentic workflow scenarios
- Add structured telemetry export sinks
- Add release provenance and signature attestations beyond the current SBOM flow
