# Release Checklist

Use this checklist before tagging a public release.

## 1. Update Version and Review Public Metadata

- Bump `src/__init__.py`
- Confirm repository URLs in `pyproject.toml` still point to `themayursinha/adversarial-ml-lab`
- Confirm README examples and release notes match the current CLI and docs

## 2. Run Local Verification

```bash
make release-check
docker build -t adversarial-ml-lab .
```

Optional container smoke test:

```bash
docker run --rm --entrypoint python adversarial-ml-lab -m src.cli --help
```

## 3. Review Release Surface

- `venv/bin/python -m src.cli eval --suite baseline` succeeds from the repo checkout
- installed wheel smoke test succeeds through `make release-check`
- security docs still reflect actual project behavior and limitations
- [security-invariants.md](security-invariants.md) residual risks reviewed before marketing claims
- no broken links or stale repo coordinates remain in docs or metadata

## 4. Tag and Publish

```bash
git add src/__init__.py README.md pyproject.toml docs/
git commit -m "release: vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main --follow-tags
```

GitHub Actions flow:

- `.github/workflows/release.yml` builds artifacts, runs release smoke tests, and attaches release assets

## 5. Post-Release Checks

- Verify the GitHub release includes wheel, sdist, and SBOM artifacts
- Optionally verify a downloaded release wheel exposes `adml`
- Verify `adml eval --suite baseline` works from the published package
