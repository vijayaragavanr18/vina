# VINA Release Guide

## Versioning

VINA follows [Semantic Versioning](https://semver.org/):

- **MAJOR** — incompatible API changes
- **MINOR** — backward-compatible feature additions
- **PATCH** — backward-compatible bug fixes

## Release Process

### 1. Prepare the Release

```bash
# Ensure working tree is clean
git status

# Run full test suite
python -m pytest tests/ --cov=vina

# Run quality checks
ruff check vina/ tests/
black --check vina/ tests/
mypy vina/ tests/
bandit -r vina/
```

### 2. Create Release Artifacts

```bash
# Run the release script (dry run first)
./scripts/release.sh 0.2.0 --dry-run

# Then without dry run
./scripts/release.sh 0.2.0
```

The script will:

1. Update version in `vina/_version.py` and `pyproject.toml`
2. Run the full test suite
3. Build wheel and sdist
4. Generate SBOM (cyclonedx)
5. Generate SHA256/SHA512 checksums
6. Create a release manifest
7. Create a git tag

### 3. Publish

```bash
# Push the tag
git push --tags origin main

# Publish to PyPI
twine upload dist/*.whl dist/*.tar.gz
```

### 4. GitHub Release

1. Go to https://github.com/anomalyco/vina/releases
2. The release workflow will create a draft release
3. Add release notes describing changes
4. Publish the release

## Release Artifacts

Each release includes:

- **Wheel** (`vina-{version}-py3-none-any.whl`)
- **Source distribution** (`vina-{version}.tar.gz`)
- **SBOM** (`vina.sbom.json`) — CycloneDX format
- **Checksums** (`SHA256SUMS`, `SHA512SUMS`)
- **Release manifest** (`RELEASE_MANIFEST.txt`)
- **Docker image** — published to GitHub Container Registry

## Installation

```bash
# From PyPI
pip install vina

# With extras
pip install vina[full]

# From source
pip install git+https://github.com/anomalyco/vina.git

# From a release wheel
pip install vina-0.2.0-py3-none-any.whl

# Docker
docker pull ghcr.io/anomalyco/vina:latest
```

## CI/CD Pipeline

The release workflow in `.github/workflows/release.yml`:

1. Builds wheel and sdist
2. Generates SBOM and checksums
3. Creates a GitHub release with all artifacts
4. Publishes to PyPI
5. Builds and pushes Docker image to GHCR

## Quality Gates

The CI pipeline enforces:

| Gate | Tool | Threshold |
|------|------|-----------|
| Linting | Ruff | No errors |
| Formatting | Black | No diffs |
| Type checking | mypy | No errors |
| Security | Bandit | No high-severity issues |
| Dependency audit | pip-audit | No vulnerabilities |
| Tests | pytest | All passing |
| Coverage | pytest-cov | >= 80% |
