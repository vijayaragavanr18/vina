# VINA Architecture Guide

## High-Level Architecture

```
┌─────────────────────────────────────────────────────┐
│                    CLI (Typer)                        │
│  scan │ scan-web │ scan-os │ report │ update-db      │
│  plugin │ benchmark │ version │ doctor                │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│                   Pipeline                            │
│  ┌──────────┐   ┌──────────┐   ┌──────────────────┐ │
│  │ Scanners │──▶│  Vuln.   │──▶│   Enrichment      │ │
│  │ (18 OS)  │   │  Intel.  │   │   (40+ rules)     │ │
│  └──────────┘   └──────────┘   └────────┬─────────┘ │
│                                         │           │
│  ┌──────────┐   ┌──────────┐   ┌────────▼─────────┐ │
│  │ Reports  │◀──│Exploit.  │◀──│  Correlation      │ │
│  │JSON/MD/  │   │Analysis  │   │  (18 rules)       │ │
│  │HTML      │   │(safe)    │   └──────────────────┘ │
│  └──────────┘   └──────────┘                        │
└─────────────────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│                   Plugin System                       │
│  ┌──────────┐   ┌──────────┐   ┌──────────────────┐ │
│  │ Registry │   │  Loader  │   │     Hooks         │ │
│  └──────────┘   └──────────┘   └──────────────────┘ │
└─────────────────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│               Feed Manager (Offline-first)            │
│  NVD │ CISA KEV │ EPSS │ OSV │ GitHub Advisories   │
└─────────────────────────────────────────────────────┘
```

## Core Components

### 1. Pipeline Scheduler

The `PipelineScheduler` manages stage execution with dependency resolution:

- Stages declare dependencies (e.g., `system_info` depends on `host_recon`)
- Independent stages run concurrently (`max_parallel=6`)
- Each stage wraps a scanner module with retry logic
- Results collected into `StageResult` objects

### 2. Finding System

All scanners emit `Finding` dataclass instances with:
- `title`, `description`, `severity`, `category`
- `source_stage`, `target`, `evidence`
- `recommendation`, `references`, `tags`
- `host`, `port`, `protocol`, `url`, `confidence`

Findings are deduplicated by `(title, target, source_stage)`.

### 3. Engine Pipeline

After scanner stages complete, the engine pipeline runs sequentially:

1. **VulnerabilityEngine** — Extracts software inventory from findings, matches against CVE database (104 local CVEs + feed data), computes risk scores
2. **EnrichmentEngine** — Matches finding titles against 40+ KnowledgeRules, adds explanations, security impact, remediation, MITRE/CWE/CIS references, GTFOBins mapping
3. **CorrelationEngine** — Combines findings into attack paths (18 rules covering privilege escalation, container escape, lateral movement, persistence, credential exposure)
4. **ExploitabilityEngine** — Assesses exploit feasibility for CVEs, attack paths, and high-value findings (SUID, GTFOBins, writable PATH, passwordless sudo, Docker socket). Safe analysis only — no exploitation.

### 4. Plugin SDK

The plugin system provides:
- **Plugin base class** with lifecycle and registration methods
- **PluginRegistry** (singleton) for managing plugins and hooks
- **PluginLoader** for discovery (built-in, local, entry points, manual)
- **Hook system** with 14 well-defined hook points
- **Context** providing access to all VINA services
- **Exception boundaries** — plugin failures never stop scans

### 5. Feed Manager

The feed manager provides offline-first vulnerability intelligence:
- 5 providers: NVD JSON 2.0, CISA KEV, EPSS, OSV, GitHub Security Advisories
- SQLite-backed cache with checksum validation
- Incremental updates with ETag/Last-Modified
- Rate limiting and exponential backoff retry
- Offline mode with local database fallback

### 6. Testing & Benchmarking Framework

The testing framework provides:
- **MockCommandRunner** — deterministic command execution
- **MockFindingFactory** — scenario-based finding generation
- **TestPipelineRunner** — controlled pipeline execution with metrics
- **Benchmark profiles** — expected vs actual comparison
- **Metrics** — precision, recall, F1, FP, FN, coverage, timing
- **Sandbox** — isolated temp environment with mock HTTP server

## Data Flow

```
Target Input
    │
    ▼
Scanner Stages ───────────────────► Raw Findings
    │                                      │
    │                                      ▼
    │                           VulnerabilityEngine
    │                              (CVE matching)
    │                                      │
    │                                      ▼
    │                              EnrichmentEngine
    │                            (knowledge base)
    │                                      │
    │                                      ▼
    │                              CorrelationEngine
    │                            (attack paths)
    │                                      │
    │                                      ▼
    │                              ExploitabilityEngine
    │                            (feasibility scoring)
    │                                      │
    │                                      ▼
    └──────────────────────────► Report Generator
                                   (JSON/MD/HTML)
```

## Configuration

Configuration uses Pydantic `BaseModel` hierarchy loaded from YAML:

```yaml
output_dir: output
log_dir: logs
timeout_seconds: 60
runner:
  concurrency: 4
  stdout_limit_bytes: 10485760
tool_bins:
  nuclei: nuclei
  nmap: nmap
```

## Plugin Integration

```
┌────────────┐    ┌──────────────┐    ┌──────────────┐
│  Pipeline   │───▶│  Hook Points  │───▶│   Plugins     │
│             │    │before_pipeline│    │               │
│             │    │after_finding  │    │ register_*()  │
│             │    │before_report  │    │               │
└────────────┘    └──────────────┘    └──────────────┘
```

See [PLUGIN_AUTHOR_GUIDE.md](PLUGIN_AUTHOR_GUIDE.md) for details.
