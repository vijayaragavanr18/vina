# VINA

**Vulnerability Intelligence & Network Analyzer**

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000)](https://docs.astral.sh/ruff/)
[![Mypy](https://img.shields.io/badge/types-mypy-blue)](https://mypy-lang.org/)
[![Tests](https://img.shields.io/badge/tests-669%20passing-brightgreen)]()

VINA is a modular, async Python framework for Linux security enumeration, vulnerability intelligence, attack-path correlation, and exploitability analysis. It combines 18-stage OS-level reconnaissance with a knowledge engine, CVE matching (104 local entries + 5 live feeds), correlation engine, exploitability scoring, and a plugin SDK.

## Features

- **OS enumeration** – 18-stage pipeline: host_recon, system_info, kernel, users, groups, services, filesystem, mount points, capabilities, network, environment, processes, packages, logs, SSH, sudo, cron, systemd, Docker, secrets, privilege escalation
- **Web reconnaissance** – subdomain discovery (Subfinder), HTTP probing (httpx), port scanning (naabu, nmap), tech detection (whatweb), URL crawling (katana, gau, waybackurls, url_aggregator), vulnerability scanning (nuclei)
- **Vulnerability Intelligence** – CVE matching against software inventory with version-aware comparison (Debian/semver/ranges/wildcards), CVSS scoring, CISA KEV, EPSS probability, confidence scoring
- **Knowledge & Remediation Engine** – 40+ enrichment rules, GTFOBins mapping, MITRE ATT&CK (30+ techniques), CIS benchmarks (50+ references), CWE mapping, automated remediation suggestions
- **Correlation & Attack Paths** – dependency-aware chain detection (privilege escalation, persistence, container escape, lateral movement, credential exposure), risk scoring (0–100), evidence collection
- **Exploitability Analysis** – non-intrusive scoring of attack feasibility with complexity, maturity, prerequisites, mitigations, and attack-vector context
- **Feed Management** – SQLite-backed cache with automatic NVD/CISA KEV/EPSS/OSV/GitHub Advisory updates, TTL expiry, retry/backoff, conditional requests (ETag/Last-Modified)
- **Plugin SDK** – 14 hook points (before/after pipeline, stage, finding, report), 5 discovery mechanisms (built-in, local packages, entry points, module paths, manual registration), error-isolated execution with fallback
- **Testing & Benchmarking** – mock fixtures, deterministic benchmark profiles, metrics (precision/recall/F1/FP/FN/runtime/memory/CPU), HTML+Markdown reports, integration test suite
- **Reports** – Markdown, HTML (with JS search/filter, severity cards, attack path visualization), and JSON formats with vulnerability stats, enrichment details, exploitability assessments
- **CLI** – `scan`, `scan-os`, `scan-web`, `report`, `update-db`, `version`, `doctor`, `plugin` (list/info/enable/disable/doctor), `benchmark` (list/run/compare/report)
- **Code Quality** – Zero Ruff violations, zero mypy errors, 669 passing tests, modern Python 3.12+ idioms throughout

## Quick Start

```bash
# Create and activate a virtual environment
python3 -m venv .venv && source .venv/bin/activate

# Install with development extras
pip install -e ".[dev]"

# Run the full test suite
python -m pytest tests/

# Run an OS enumeration scan
vina scan-os

# Run a web reconnaissance scan
vina scan-web example.com

# Update vulnerability intelligence feeds
vina update-db

# Check installation health
vina doctor
```

## Installation

```bash
# From PyPI (once published)
pip install vina

# With all extras
pip install vina[full]
```

## Quality Gates

Before every release, VINA is validated against:

| Gate | Status |
|------|--------|
| [`ruff check`](https://docs.astral.sh/ruff/) | 0 violations |
| [`ruff format`](https://docs.astral.sh/ruff/) | 116 files formatted |
| [`mypy`](https://mypy-lang.org/) | 0 errors (96 source files) |
| [`pytest`](https://docs.pytest.org/) | 669 passed, 101 subtests |
| `bandit` (security linter) | No high-severity issues |
| `pip-audit` (dependency audit) | No known vulnerabilities |

## Documentation

| Guide | Description |
|-------|-------------|
| [Architecture Guide](docs/ARCHITECTURE_GUIDE.md) | High-level design, data flow, component interaction |
| [Developer Guide](docs/DEVELOPER_GUIDE.md) | Project structure, adding scanners/rules, development workflow |
| [Plugin Author Guide](docs/PLUGIN_AUTHOR_GUIDE.md) | Plugin development, hooks, registration, lifecycle |
| [Release Guide](docs/RELEASE_GUIDE.md) | Versioning, publishing, CI/CD pipeline |
| [Contributing](docs/CONTRIBUTING.md) | Code of conduct, PR process, code standards |

## Project Structure

```
vina/
├── cli.py                  # Typer CLI (scan, update-db, plugin, benchmark, ...)
├── ai/                     # AI analysis & report generation
├── core/                   # Engines: knowledge, correlation, vuln_intel, exploitability, feed_manager, config, runner, aggregator, checkpoint
├── models/                 # Finding, Aggregator, stage models, TargetInput
├── modules/                # Pipeline modules (host_discovery, port_scan, vulnerability_scan, aggregate)
├── pipeline/               # Web pipeline orchestrator, stage result aggregation
├── plugins/                # Plugin SDK (registry, loader, hooks, context, scheduler)
├── reports/                # Report renderers (markdown, HTML, JSON)
├── scanners/               # OS scanners (ssh, cron, systemd, docker, ...) + web scanners
├── testing/                # Testing & benchmarking framework
└── data/                   # CVE database (104 local entries)
```

## Requirements

- Python 3.12+
- Runtime dependencies: aiohttp, typer, rich, pyyaml, psutil, pydantic, json5, requests
- Optional tools for full web scanning: Subfinder, httpx, naabu, nmap, whatweb, katana, gau, waybackurls, nuclei

## License

MIT
