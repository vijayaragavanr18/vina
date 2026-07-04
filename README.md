# VINA

VINA stands for Vulnerability Intelligence & Network Analyzer.

It is a modular, async Python framework for running security reconnaissance and analysis workflows. The current implementation focuses on safe command execution, structured results, and a first working web recon pipeline powered by Subfinder.

## What It Does

- Runs external security tools through a shared async runner.
- Loads tool paths and runtime settings from configuration.
- Persists JSON artifacts under `output/`.
- Produces concise, structured console output.

See `PROJECT_SPEC.md` for the full architecture and design constraints.

## Quick Start

1. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the test suite:

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

4. Run a web recon scan:

```bash
./.venv/bin/python -m vina scan example.com
```

## Web Recon Output

The web recon scanner uses Subfinder and writes deduplicated subdomains to:

```text
output/web/subdomains.json
```

## Notes

- The CLI entry point is `vina`.
- Configuration and logger defaults use the VINA project name.
- Generated artifacts such as `.venv/`, `output/`, and `*.egg-info` are intentionally not tracked in source control.
# vina
