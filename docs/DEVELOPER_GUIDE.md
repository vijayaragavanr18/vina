# VINA Developer Guide

## Getting Started

### Prerequisites

- Python 3.12+
- Git
- Linux (recommended) or macOS

### Setup

```bash
# Clone the repository
git clone https://github.com/anomalyco/vina.git
cd vina

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in development mode with all extras
pip install -e ".[dev,testing,docs]"

# Verify installation
vina version
vina doctor
```

## Project Structure

```
vina/
  __init__.py          # Package entry point
  _version.py          # Version information
  cli.py               # Typer CLI (commands: scan, scan_web, scan_os, report, update_db, plugin, benchmark, version, doctor)
  ai/                  # AI analyzer module
  core/                # Core engines:
    config.py          #   Configuration (AppConfig, YAML loader)
    dependency.py      #   DependencyChecker
    runner.py          #   AsyncCommandRunner
    scheduler.py       #   PipelineScheduler
    aggregator.py      #   FindingAggregator
    knowledge.py       #   EnrichmentEngine (40+ rules)
    correlation.py     #   CorrelationEngine (18 rules)
    vuln_intel.py      #   VulnerabilityEngine (CVE matching)
    exploitability.py  #   ExploitabilityEngine (safe analysis)
    feed_manager.py    #   FeedManager (NVD, CISA KEV, EPSS, OSV, GitHub)
    storage.py         #   JsonStore
    logging.py         #   Logging configuration
  data/                # Static data (cves.json)
  models/              # Dataclasses (Finding, StageResult, etc.)
  modules/             # Web pipeline modules
  parsers/             # Output parsers
  pipeline/            # WebPipeline
  plugins/             # Plugin SDK
    sdk.py             #   Convenience exports
    plugin.py          #   Plugin base class
    registry.py        #   PluginRegistry
    loader.py          #   PluginLoader
    hooks.py           #   Hook system
    context.py         #   PluginContext
    exceptions.py      #   Custom exceptions
  reports/             # Report generators (markdown, html, json)
  scanners/            # Scanner modules (os/, web/)
  testing/             # Testing & Benchmarking framework
    fixtures.py        #   Mock objects
    datasets.py        #   Mock data
    metrics.py         #   Metrics computation
    runner.py          #   TestPipelineRunner
    sandbox.py         #   TestSandbox
    benchmark.py       #   Benchmark profiles
    integration.py     #   Integration test suite
plugins/               # Example plugins
  example_scanner/
  example_report/
  example_enrichment/
tests/                 # Test suite (600+ tests)
```

## Development Workflow

### Code Style

We use Ruff for linting and Black for formatting:

```bash
# Lint
ruff check vina/ tests/

# Format
black vina/ tests/

# Type check
mypy vina/ tests/
```

### Running Tests

```bash
# Run all tests
pytest

# With coverage
pytest --cov=vina --cov-report=term --cov-report=html

# Run specific test file
pytest tests/test_plugins.py -v

# Run integration tests
pytest tests/test_testing.py -v -k "integration or sandbox or runner"
```

### Adding a New Scanner

1. Create `vina/scanners/os/<name>.py`
2. Define a result dataclass with `findings: list[Finding]`
3. Create a module class with `__init__(config, context)` and `async run(target)`
4. Register the stage dependency in `os_pipeline.py` `_STAGE_DEPS`
5. Add a stage coroutine to `OSPipeline.run()`
6. Add a `StageDef` to the stages list
7. Include the result key in `result_keys` for finding collection

### Adding an Enrichment Rule

Add a `KnowledgeRule` to the appropriate list in `vina/core/knowledge.py`:

```python
KnowledgeRule(
    rule_id="CUSTOM-001",
    title_patterns=["Finding title pattern"],
    explanation="What this finding means",
    security_impact="Impact description",
    remediation="How to fix it",
    mitre_attack=[MitreTechnique.T1078],
    cwe="CWE-287: Improper Authentication",
)
```

### Adding a Correlation Rule

Add a `CorrelationRule` to `_CORRELATION_RULES` in `vina/core/correlation.py`.

## Architecture Overview

VINA uses a pipeline architecture:

1. **Scanner Stage** — Executes tools and collects raw findings
2. **Vulnerability Intelligence** — Matches software inventory against CVE database
3. **Enrichment** — Adds context (explanations, mitigations, references)
4. **Correlation** — Chains findings into attack paths
5. **Exploitability** — Assesses exploit feasibility (safe analysis only)
6. **Reporting** — Generates JSON, Markdown, and HTML reports

Each stage runs via the `PipelineScheduler` which respects a dependency graph
and executes independent stages concurrently.

## Configuration

VINA uses a YAML configuration file (`config.yaml` by default):

```yaml
output_dir: output
log_dir: logs
timeout_seconds: 60
tool_bins:
  subfinder: subfinder
  nmap: nmap
  nuclei: nuclei
```

Configuration can also be provided as JSON or programmatically via `AppConfig`.

## Release Process

See [RELEASE_GUIDE.md](RELEASE_GUIDE.md) for the full release workflow.
