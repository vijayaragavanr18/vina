# VINA Plugin Author Guide

## Overview

VINA plugins allow extending the framework without modifying core source code.
Plugins can register scanners, enrichment rules, correlation rules, report
sections, CLI commands, parsers, and exporters.

## Quick Start

### Creating a Plugin

Create a directory with a `plugin.py` file:

```
my_plugin/
  plugin.py
```

```python
from vina.plugins.sdk import Plugin, PluginMetadata, PluginContext

class MyPlugin(Plugin):
    metadata = PluginMetadata(
        id="my_plugin",
        name="My Plugin",
        version="1.0.0",
        author="Your Name",
        description="Does something useful",
    )

    def on_load(self, context: PluginContext) -> None:
        context.logger.info("MyPlugin loaded")
```

### Installing a Plugin

Plugins are discovered automatically from:

1. **Local directory**: `./plugins/` or `~/.vina/plugins/`
2. **Entry points**: Packages installed via pip that register the `vina.plugins` entry point
3. **Built-in**: Bundled in `vina/plugins/builtin/`

### Manual Registration

```python
from vina.plugins.registry import get_registry
from my_plugin import MyPlugin

registry = get_registry()
registry.register(MyPlugin())
```

## Plugin Metadata

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier (e.g., `my_plugin`) |
| `name` | Yes | Human-readable name |
| `version` | Yes | Semver version string |
| `author` | No | Plugin author |
| `description` | No | Brief description |
| `license` | No | SPDX license identifier |
| `homepage` | No | Project URL |
| `minimum_vina_version` | No | Minimum VINA version required |
| `categories` | No | List of category strings |
| `dependencies` | No | List of plugin IDs this depends on |

## Lifecycle Hooks

| Method | Called When |
|--------|-------------|
| `on_load(ctx)` | Plugin is loaded and registered |
| `on_unload()` | Plugin is unregistered |
| `on_enable()` | Plugin is enabled |
| `on_disable()` | Plugin is disabled |

## Registration Methods

Override these to provide capabilities:

```python
def register_scanners(self):
    """Return a list of scanner module classes."""
    return [MyScanner]

def register_enrichment_rules(self):
    """Return a list of KnowledgeRule objects."""
    from vina.core.knowledge import KnowledgeRule
    return [KnowledgeRule(...)]

def register_correlation_rules(self):
    """Return a list of CorrelationRule objects."""
    from vina.core.correlation import CorrelationRule, FindingMatcher
    return [CorrelationRule(...)]

def register_report_sections(self):
    """Return a list of report section descriptors."""
    return [MyReportSection()]

def register_cli_commands(self):
    """Return a list of Typer command callbacks."""
    return [my_command]

def register_parsers(self):
    """Return a list of parser functions."""
    return [my_parser]

def register_exporters(self):
    """Return a list of exporter functions."""
    return [my_exporter]

def register_hooks(self):
    """Return a dict mapping HookPoint to handler list.

    Each handler receives a HookEvent and can modify event.data in place.
    """
    from vina.plugins.hooks import HookPoint
    return {
        HookPoint.BEFORE_PIPELINE: [self.on_before_pipeline],
        HookPoint.AFTER_FINDING: [self.on_after_finding],
    }
```

## Hook Points

| Hook Point | Triggered | Event Data |
|------------|-----------|------------|
| `before_pipeline` | Before pipeline starts | `target` |
| `after_pipeline` | After pipeline completes | `target`, `findings` |
| `before_stage` | Before each stage | `stage_name` |
| `after_stage` | After each stage | `stage_name`, `result` |
| `before_finding` | Before finding collection | `findings` |
| `after_finding` | After findings collected | `findings`, `enriched` |
| `before_report` | Before report generation | `findings`, `attack_paths`, `vuln_matches` |
| `after_report` | After report generation | `generated`, `findings` |
| `before_correlation` | Before correlation engine | `findings` |
| `after_correlation` | After correlation engine | `findings`, `attack_paths` |
| `before_exploitability` | Before exploitability engine | `findings`, `attack_paths`, `vuln_matches` |
| `after_exploitability` | After exploitability engine | (assessments) |
| `before_vulnerability_lookup` | Before CVE matching | `findings` |
| `after_vulnerability_lookup` | After CVE matching | `findings`, `vuln_matches`, `vuln_stats` |

## Plugin Context

The `PluginContext` provides access to VINA services:

```python
class PluginContext:
    logger: logging.Logger
    config: AppConfig
    output_dir: Path
    dependency_checker: DependencyChecker
    knowledge_base: EnrichmentEngine
    vulnerability_database: VulnerabilityEngine
    feed_manager: FeedManager
    data_dir: Path
    plugin_dir: Path
    extra: dict
```

## Error Handling

Plugin exceptions are caught by the framework. A plugin failure never stops
a scan. Errors are logged and recorded in the hook event's `errors` list.

## Testing Plugins

```python
from my_plugin import MyPlugin

def test_my_plugin():
    p = MyPlugin()
    assert p.metadata.id == "my_plugin"
    assert p.enabled is True

    rules = p.register_enrichment_rules()
    assert rules is not None
    assert len(rules) == 1
```

## Entry Point Registration

To distribute a plugin via pip, add to your `pyproject.toml`:

```toml
[project.entry-points."vina.plugins"]
my_plugin = "my_package.plugin:MyPlugin"
```

## Example Plugin

See `plugins/example_scanner/`, `plugins/example_report/`, and
`plugins/example_enrichment/` for complete examples.
