# Contributing to VINA

## Code of Conduct

This project is committed to providing a welcoming, inclusive, and harassment-free
experience for everyone.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/vina.git`
3. Set up the development environment (see [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md))
4. Create a feature branch: `git checkout -b feat/your-feature`

## Development Workflow

### Before Committing

Run all quality checks:

```bash
# Lint
ruff check vina/ tests/

# Format
black vina/ tests/

# Type check
mypy vina/ tests/

# Security
bandit -r vina/

# Tests
pytest --cov=vina --cov-report=term
```

### Commit Messages

Use conventional commits:

```
feat: add new scanner module
fix: correct CVE version matching for Debian packages
docs: update plugin author guide
refactor: simplify pipeline scheduler
test: add integration tests for feed manager
chore: update dependencies
```

### Pull Request Process

1. Ensure all quality checks pass
2. Add tests for new functionality
3. Update documentation if needed
4. Create a pull request against the `main` branch
5. Request review from at least one maintainer

## Code Standards

### Python

- Target Python 3.12+
- Use type annotations for all function signatures
- Use dataclasses for data containers
- Follow existing patterns for scanner modules

### Testing

- All new code must have tests
- Maintain or improve code coverage
- Use pytest for new tests
- Mock external services for deterministic tests

### Documentation

- Document all public APIs
- Include docstrings for classes and methods
- Update relevant guides when adding features

## Project Structure

See [ARCHITECTURE_GUIDE.md](ARCHITECTURE_GUIDE.md) for the full project structure.

## Plugin Development

See [PLUGIN_AUTHOR_GUIDE.md](PLUGIN_AUTHOR_GUIDE.md) for plugin development documentation.

## Questions?

Open an issue at https://github.com/anomalyco/vina/issues
