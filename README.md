# VINA

**Vulnerability Intelligence & Network Analyzer**

VINA is a modular, async Python framework for Linux security enumeration, vulnerability analysis, and attack-path correlation. It combines OS-level reconnaissance with a knowledge engine, CVE matching, exploitability analysis, and plugin-based extensibility.

## Features

- **OS enumeration** – 10 scanner modules: SSH, cron, systemd, Docker, kernel, environment, processes, packages, logs, secrets
- **Web reconnaissance** – subdomain discovery via Subfinder, structured JSON output
- **Vulnerability Intelligence** – CVE matching against software inventory with version-aware comparison (Debian/semver/ranges/wildcards), CVSS scoring, KEV & EPSS integration
- **Knowledge & Remediation Engine** – 40+ enrichment rules, GTFOBins mapping, MITRE ATT&CK (30+ techniques), CIS benchmarks (50+ references), CWE mapping
- **Correlation & Attack Paths** – dependency-aware chain detection (privilege escalation, persistence, container escape, lateral movement, credential exposure), risk scoring (0–100)
- **Exploitability Analysis** – non-intrusive scoring of attack feasibility with complexity, maturity, prerequisites, mitigations, and attack-vector context
- **Feed Management** – SQLite-backed cache with automatic NVD/CISA KEV/EPSS/OSV/GitHub Advisory updates, TTL expiry, retry/backoff, conditional requests
- **Plugin SDK** – 14 hook points, 5 discovery mechanisms (built-in, local packages, entry points, module paths, manual registration), error-isolated execution
- **Testing & Benchmarking** – mock fixtures, deterministic benchmark profiles, metrics (precision/recall/F1/FP/FN/runtime/memory/CPU), HTML+Markdown reports
- **Reports** – Markdown, HTML (with JS search/filter), and JSON formats with vulnerability stats, attack path chains, enrichment details, and exploitability analysis
- **CLI** – `scan`, `scan-os`, `scan-web`, `report`, `update-db`, `version`, `doctor`, `plugin` (list/info/enable/disable/doctor), `benchmark` (list/run/compare/report)

## Quick Start

```bash
# Create and activate a virtual environment
python3 -m venv .venv && source .venv/bin/activate

# Install with development extras
pip install -e ".[dev]"

# Run the test suite
python -m pytest tests/

# Run an OS scan
vina scan-os

# Run a web recon scan
vina scan-web example.com

# Update vulnerability feeds
vina update-db
```

## Installation

```bash
# From PyPI
pip install vina

# With extras
pip install vina[full]
```

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
├── core/                   # Engines: knowledge, correlation, vuln_intel, exploitability, feed_manager
├── models/                 # Finding, Aggregator, stage models
├── plugins/                # Plugin SDK (registry, loader, hooks, context)
├── reports/                # Report renderers (markdown, HTML, JSON)
├── scanners/               # OS modules (ssh, cron, systemd, docker, ...) + web pipeline
├── testing/                # Testing & benchmarking framework
└── data/                   # CVE database (104 entries)
```

## Requirements

- Python 3.12+
- Dependencies: aiohttp, typer, rich, pyyaml, psutil, typer

## License

MIT
