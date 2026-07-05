#!/usr/bin/env bash
# VINA Release Script
# Usage: ./scripts/release.sh <version> [--dry-run]
set -euo pipefail

VERSION="${1:-}"
DRY_RUN="${2:-}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version> [--dry-run]"
  echo "Example: $0 0.2.0"
  exit 1
fi

# Validate version format
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "Error: Version must be in semver format (X.Y.Z)"
  exit 1
fi

cd "$REPO_ROOT"

# Ensure working tree is clean
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Error: Working tree is not clean. Commit or stash changes first."
  exit 1
fi

echo "=== VINA Release v$VERSION ==="
echo "Repository: $REPO_ROOT"

# Update version in _version.py
cat > vina/_version.py << PYEOF
"""Version information for VINA."""

__version__ = "$VERSION"

VERSION_INFO = {
    "major": ${VERSION%%.*},
    "minor": ${VERSION#*.};
    minor="${minor%%.*}",
    patch="${VERSION##*.}",
    pre_release: None,
    build: None,
}


def version_str() -> str:
    return __version__


def version_tuple() -> tuple[int, int, int]:
    parts = __version__.split(".")
    return tuple(int(p) for p in parts[:3])


__all__ = [
    "__version__",
    "VERSION_INFO",
    "version_str",
    "version_tuple",
]
PYEOF

# Update version in pyproject.toml
sed -i "s/^version = .*/version = \"$VERSION\"/" pyproject.toml

# Update version in __init__.py
echo "Updating vina/__init__.py ..."

# Run tests
echo "=== Running tests ==="
python -m pytest tests/ --tb=short -q || {
  echo "Tests failed. Aborting release."
  exit 1
}

# Build packages
echo "=== Building packages ==="
python -m build --wheel --sdist

# Generate SBOM
echo "=== Generating SBOM ==="
pip install cyclonedx-bom 2>/dev/null || true
cyclonedx-py requirements --format json --output dist/vina.sbom.json 2>/dev/null || {
  echo "SBOM generation skipped (cyclonedx-bom not available)"
}

# Generate checksums
echo "=== Generating checksums ==="
cd dist
sha256sum * > SHA256SUMS 2>/dev/null || true
sha512sum * > SHA512SUMS 2>/dev/null || true
cd "$REPO_ROOT"

# Create release manifest
cat > dist/RELEASE_MANIFEST.txt << MANIFEST
VINA Release v$VERSION
Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Git Commit: $(git rev-parse HEAD)
Artifacts:
$(ls -la dist/)
MANIFEST

echo ""
echo "=== Release artifacts ==="
ls -la dist/

if [[ "$DRY_RUN" == "--dry-run" ]]; then
  echo ""
  echo "[DRY RUN] Skipping git tag and push."
  echo "Run without --dry-run to complete the release."
  exit 0
fi

# Create git tag
echo ""
echo "=== Creating git tag v$VERSION ==="
git add vina/_version.py pyproject.toml vina/__init__.py dist/
git commit -m "Release v$VERSION"
git tag -a "v$VERSION" -m "VINA v$VERSION"

echo ""
echo "=== Release v$VERSION ready ==="
echo "Run 'git push --tags origin main' to publish."
echo "Run 'twine upload dist/*.whl dist/*.tar.gz' to publish to PyPI."
