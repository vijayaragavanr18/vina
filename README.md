# VINA

**Vulnerability Intelligence & Network Analyzer**

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000)](https://docs.astral.sh/ruff/)
[![Mypy](https://img.shields.io/badge/types-mypy-blue)](https://mypy-lang.org/)
[![Tests](https://img.shields.io/badge/tests-751%20passing-brightgreen)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange)]()

VINA is a modular, async Python framework for comprehensive Linux security assessment, vulnerability intelligence, attack-path correlation, and exploitability analysis. It combines a **29-stage parallel OS assessment pipeline** with a web reconnaissance engine, a 158-rule knowledge base, 51-rule correlation engine, vulnerability intelligence with 5 live feeds, exploitability scoring, and a full plugin SDK — all orchestrated through a clean CLI.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [CLI Reference](#cli-reference)
- [Architecture](#architecture)
- [OS Security Assessment Pipeline](#os-security-assessment-pipeline)
- [Web Reconnaissance Pipeline](#web-reconnaissance-pipeline)
- [Core Engines](#core-engines)
- [Plugin System](#plugin-system)
- [Testing & Benchmarking](#testing--benchmarking)
- [Reports](#reports)
- [Project Structure](#project-structure)
- [Quality Gates](#quality-gates)
- [Configuration](#configuration)
- [Docker](#docker)
- [Documentation](#documentation)
- [Requirements](#requirements)
- [License](#license)

---

## Features

### OS Security Assessment (29-Stage Pipeline)
- **Host & System Reconnaissance** — OS identification, kernel version, loaded modules, boot parameters
- **User & Access Control** — Account enumeration, group membership, password aging, locked/unlocked accounts
- **Authentication & Privilege Management (PS-02)** — PAM configuration, password policies, credential exposure, session security, Polkit rules, privilege escalation vectors
- **Package & Supply Chain Security (PS-03)** — Package manager auditing (apt, dpkg, rpm, dnf, yum, zypper, snap, flatpak, pip, npm, cargo, gem, go), repository key validation, package integrity verification, SBOM generation
- **Network Stack & Firewall (PS-04)** — Listening ports, exposed services, firewall rules (nftables, iptables, ufw, firewalld), routing hardening, DNS resolver security
- **Boot Process & Secure Boot (PS-05)** — GRUB password protection, Secure Boot status, EFI variables, kernel boot parameters, initramfs integrity, bootloader file permissions
- **Desktop & GUI Security (PS-06)** — Desktop environment auditing (GNOME, KDE, XFCE, Cinnamon, MATE), display manager settings, session lock policies, remote desktop (VNC, RDP, xrdp), browser security
- **Filesystem, Permissions & Storage (PS-07)** — SUID/SGID files, world-writable paths, mount options (noexec, nodev, nosuid), LUKS/dm-crypt encryption, filesystem integrity, immutable files, ACLs
- **Logging, Auditing & Monitoring (PS-08)** — auditd rules, journald/syslog configuration, log rotation/retention, NTP/Chrony time synchronisation, IDS agent detection (fail2ban, AIDE, OSSEC, Wazuh)
- **Cryptographic Configuration (PS-09)** — SSL/TLS certificate validation, OpenSSL/GnuTLS configuration, SSH cipher/MAC auditing, kernel FIPS mode, system entropy assessment
- **Container & Virtualisation Security (PS-10)** — Docker/Podman/containerd/CRI-O configuration, Kubernetes kubelet authentication, namespace isolation, AppArmor/SELinux enforcement, seccomp support, hypervisor detection (KVM, VirtualBox, VMware)
- **Kernel Hardening** — 23+ sysctl parameters (ASLR, ptrace scope, dmesg restriction, SYN cookies, ICMP redirects, rp_filter, etc.)
- **Privilege Escalation Detection** — SUID/SGID abuse, sudo misconfigurations, capability abuse, GTFOBins mapping, writable PATH exploitation
- **Secret & Credential Detection** — Sensitive environment variables, exposed keys, credential files, configuration leaks

### Web Reconnaissance
- **Subdomain Discovery** — Subfinder integration
- **HTTP Probing** — httpx live host detection
- **Port Scanning** — naabu and nmap integration
- **Technology Detection** — whatweb fingerprinting
- **URL Crawling** — katana, gau, waybackurls, URL aggregation
- **Vulnerability Scanning** — Nuclei template scanning

### Intelligence & Analysis Engines
- **Vulnerability Intelligence** — CVE matching against software inventory with semantic version comparison (Debian/semver/ranges/wildcards), CVSS scoring, local database (104 CVEs) + 5 live feeds (NVD, CISA KEV, EPSS, OSV, GitHub Advisory)
- **Knowledge Engine** — 158 enrichment rules across 22 categories with GTFOBins mapping, MITRE ATT&CK techniques (30+), CIS benchmarks (50+ references), CWE mapping, automated remediation
- **Correlation Engine** — 51 attack-path rules mapping multi-finding chains (privilege escalation, persistence, container escape, lateral movement, credential exposure), risk scoring (0–100), evidence collection
- **Exploitability Engine** — Non-intrusive scoring of attack feasibility with complexity, maturity, prerequisites, mitigations, and attack-vector context

### Platform Features
- **Plugin SDK** — 14 hook points, 5 discovery mechanisms, error-isolated execution
- **Feed Manager** — SQLite-backed cache with ETag/Last-Modified, TTL expiry, retry/backoff, offline mode
- **Testing Framework** — Mock fixtures, deterministic benchmark profiles, metrics (precision/recall/F1), integration suites
- **Reports** — Markdown, HTML (with JS search/filter, severity cards, attack path visualisation), and JSON
- **CLI** — 16 commands covering scanning, reporting, feed management, diagnostics, plugins, and benchmarking

---

## Quick Start

```bash
# Create and activate a virtual environment
python3 -m venv .venv && source .venv/bin/activate

# Install with development extras
pip install -e ".[dev]"

# Check installation health
vina doctor

# Run an OS security assessment on localhost
vina scan-os

# Run a web reconnaissance scan
vina scan-web example.com

# Update vulnerability intelligence feeds
vina update-db

# Generate reports from scan output
vina report

# Run the full test suite
python -m pytest tests/
```

---

## Installation

```bash
# From source (recommended during alpha)
git clone https://github.com/vijayaragavanr18/vina.git
cd vina
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# With all extras (docs, plugins, release tooling)
pip install -e ".[full]"
```

### Dependency Groups

| Group | Contents |
|:------|:---------|
| **core** | typer, rich, pyyaml, pydantic |
| **dev** | pytest, ruff, black, mypy, bandit, pip-audit, pre-commit |
| **plugins** | importlib-metadata |
| **testing** | pytest, pytest-cov, psutil |
| **docs** | sphinx, sphinx-rtd-theme, sphinx-autodoc-typehints |
| **release** | build, twine, cyclonedx-bom |
| **full** | All of the above |

---

## CLI Reference

VINA provides 16 commands through its Typer CLI:

### Scanning

| Command | Description |
|:--------|:------------|
| `vina scan <target>` | Run the legacy VINA pipeline (recon → ports → tech → crawl → findings → analysis) |
| `vina scan-os` | Run the 29-stage OS security assessment pipeline on localhost |
| `vina scan-web <target>` | Web reconnaissance pipeline (supports `--resume` and `--force`) |

### Intelligence & Reporting

| Command | Description |
|:--------|:------------|
| `vina update-db` | Update vulnerability feeds (NVD, CISA KEV, EPSS, OSV, GitHub Advisory). Supports `--force`, `--offline`, `--status`, `--feed <name>` |
| `vina report` | Generate reports from pipeline output. Supports `--html`, `--markdown`, `--json` |

### Plugins

| Command | Description |
|:--------|:------------|
| `vina plugin-list` | List all registered plugins and their status |
| `vina plugin-info <id>` | Show detailed plugin information |
| `vina plugin-enable <id>` | Enable a plugin |
| `vina plugin-disable <id>` | Disable a plugin |
| `vina plugin-doctor` | Check plugin system health |

### Benchmarking

| Command | Description |
|:--------|:------------|
| `vina benchmark-list` | List available benchmark profiles |
| `vina benchmark-run <profile>` | Run a benchmark with precision/recall/F1 metrics |
| `vina benchmark-compare <a> <b>` | Compare two benchmark result JSON files |
| `vina benchmark-report <dir>` | Generate aggregate benchmark report |

### Diagnostics

| Command | Description |
|:--------|:------------|
| `vina doctor` | Run diagnostic checks (Python version, config, directories, vuln DB, feeds, plugins, tools, cache) |
| `vina version` | Show VINA version, Python version, and platform info |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              VINA CLI (Typer)                              │
│   scan  ·  scan-os  ·  scan-web  ·  report  ·  update-db  ·  doctor  ·…   │
└────────────┬───────────────┬───────────────┬────────────────────────────────┘
             │               │               │
    ┌────────▼───────┐ ┌─────▼──────┐ ┌──────▼──────┐
    │  OS Pipeline   │ │    Web     │ │   Legacy    │
    │  (29 stages)   │ │  Pipeline  │ │  Pipeline   │
    └───┬────┬───┬───┘ └────────────┘ └─────────────┘
        │    │   │
  ┌─────▼┐ ┌▼───▼──────────────────────────────────────┐
  │Stages│ │            Core Engines                    │
  │(//6) │ │ Knowledge · Correlation · Vuln Intel       │
  │      │ │ Exploitability · Feed Manager · Scheduler  │
  └──────┘ └────────┬───────────────────────────────────┘
                    │
        ┌───────────▼──────────────┐
        │    Cross-Cutting         │
        │ Plugins · Reports · CLI  │
        │ Config · Runner · Store  │
        └──────────────────────────┘
```

### Data Flow

1. **CLI** parses user input and dispatches to the appropriate pipeline
2. **Pipeline Scheduler** resolves stage dependencies and executes stages concurrently (up to 6 parallel)
3. **Scanner Modules** collect findings via `AsyncCommandRunner` subprocess execution
4. **Knowledge Engine** enriches each finding with GTFOBins, MITRE ATT&CK, CIS, and CWE context
5. **Vulnerability Intelligence** matches software inventory against CVE databases
6. **Correlation Engine** detects multi-finding attack paths and chains
7. **Exploitability Engine** scores real-world attack feasibility
8. **Plugin Hooks** fire at 14 lifecycle points throughout the pipeline
9. **Report Generators** produce JSON, Markdown, and HTML output

---

## OS Security Assessment Pipeline

The OS pipeline runs **29 concurrent stages** with dependency-aware scheduling. All stages depend on `host_recon` and execute in parallel up to 6 at a time.

### Pipeline Stages

| # | Stage | Module | Description |
|:--|:------|:-------|:------------|
| 1 | `host_recon` | Standalone | Host discovery and initial reconnaissance |
| 2 | `system_info` | Standalone | OS identification and system details |
| 3 | `ssh` | Standalone | SSH server configuration security audit |
| 4 | `kernel` | Standalone | Kernel version, loaded modules, parameters |
| 5 | `kernel_hardening` | Standalone | 23+ sysctl hardening checks (ASLR, ptrace, dmesg, etc.) |
| 6 | `environment` | Standalone | Environment variable security analysis |
| 7 | `packages` | Standalone | Installed package enumeration |
| 8 | `services` | Standalone | Running service enumeration and analysis |
| 9 | `users` | Standalone | User account, group, and password policy analysis |
| 10 | `filesystem` | Standalone | Filesystem permissions, SUID/SGID, world-writable |
| 11 | `network` | Standalone | Network configuration and active connections |
| 12 | `processes` | Standalone | Running process analysis |
| 13 | `cron` | Standalone | Cron job security analysis |
| 14 | `systemd` | Standalone | Systemd unit file analysis |
| 15 | `docker` | Standalone | Docker/container daemon configuration |
| 16 | `logs` | Standalone | Log file presence and configuration |
| 17 | `secrets` | Standalone | Secret and credential detection |
| 18 | `capabilities` | Standalone | Linux capabilities analysis |
| 19 | `sudo` | Standalone | Sudo/sudoers configuration analysis |
| 20 | `privilege_escalation` | Standalone | Privilege escalation vector detection |
| 21 | `auth_security` | Multi-module | PAM, password policies, credentials, sessions, Polkit |
| 22 | `packages_security` | Multi-module | Package managers, repos, integrity, supply chain, SBOM |
| 23 | `network_security` | Multi-module | Firewalls, routing, DNS, listening services |
| 24 | `boot_security` | Multi-module | GRUB, Secure Boot, kernel params, boot files |
| 25 | `gui_security` | Multi-module | Desktop environments, remote desktop, browsers |
| 26 | `storage_security` | Multi-module | Permissions, mounts, encryption, integrity |
| 27 | `monitoring_security` | Multi-module | Audit rules, syslog, NTP/Chrony, IDS agents |
| 28 | `crypto_security` | Multi-module | TLS certs, SSH ciphers, FIPS, entropy |
| 29 | `container_security` | Multi-module | Docker/K8s config, namespaces, LSM, virtualization |

### Pipeline Performance

The scheduler estimates sequential execution time and reports parallelism gains:

```
Pipeline duration: 9.24s
Sequential estimate: 30.65s
Time saved by parallelism: 21.41s (70% faster)
```

---

## Web Reconnaissance Pipeline

The web pipeline orchestrates external security tools in a sequential workflow:

```
subfinder → httpx → naabu → nmap → whatweb → katana → gau+waybackurls → url_aggregator → nuclei
```

| Stage | Tool | Purpose |
|:------|:-----|:--------|
| Subdomain Discovery | Subfinder | Passive subdomain enumeration |
| HTTP Probing | httpx | Live host detection and response analysis |
| Port Scanning | naabu | Fast port discovery |
| Service Detection | nmap | Service version fingerprinting |
| Tech Detection | whatweb | Web technology identification |
| URL Crawling | katana | Active web crawling |
| Historical URLs | gau, waybackurls | Wayback Machine and archive URL collection |
| URL Aggregation | url_aggregator | Deduplication and normalisation of discovered URLs |
| Vulnerability Scan | Nuclei | Template-based vulnerability detection |

Supports `--resume` for interrupted scans and `--force` to override cached results.

---

## Core Engines

### Knowledge Engine

The knowledge engine enriches raw findings with security context using **158 rules** across **22 categories**:

| Category | Rule Prefix | Example Checks |
|:---------|:------------|:---------------|
| Privilege Escalation | PE- | SUID abuse, writable PATH, cron hijacking |
| Capabilities | CAP- | Dangerous capabilities (CAP_SYS_ADMIN, CAP_NET_RAW) |
| SSH | SSH- | Weak ciphers, root login, password authentication |
| Docker | DOCKER- | Exposed socket, privileged containers |
| Kernel | KERN- | Outdated kernel, dangerous modules |
| Kernel Hardening | KH- | ASLR, ptrace, dmesg, SYN cookies |
| Writable Paths | WR- | World-writable directories in PATH |
| Secrets | SEC- | Exposed credentials, API keys |
| Authentication | AUTH- | Weak passwords, no lockout, PAM misconfiguration |
| Auth Security | AS- | Session timeouts, Polkit rules |
| Processes | PROC- | Suspicious processes, root daemons |
| Packages | PKG- | Outdated packages, unsigned repos |
| Services | SVC- | Insecure services, unnecessary daemons |
| Cron | CRON- | Writable cron scripts, insecure paths |
| Suspicious Binaries | SB- | Unknown SUID binaries |
| Filesystem | FS- | Insecure mount options, missing noexec |
| Network Security | NET- | Exposed ports, firewall gaps |
| Boot Security | BOOT- | GRUB without password, Secure Boot disabled |
| GUI Security | GUI- | Auto-login, weak screen lock, remote desktop |
| Monitoring | MON- | Missing audit rules, no log forwarding |
| Cryptography | CRYPT- | Weak ciphers, expired certificates, low entropy |
| Containers | CONT- | Docker namespace remapping, kubelet auth, LSM status |

Each rule provides: **explanation**, **security impact**, **remediation steps**, **MITRE ATT&CK mapping**, **CIS benchmark reference**, **CWE classification**, and **confidence score**.

### Correlation Engine

The correlation engine detects **51 multi-finding attack paths** that combine weaknesses across stages:

| Attack Type | Example Chains |
|:------------|:---------------|
| **Privilege Escalation** | Writable cron + root cron job → root compromise |
| **Container Escape** | Docker socket + sudo access → host escape |
| **Credential Exposure** | Env variables + writable PATH → credential capture |
| **Persistence** | Writable systemd + service reload → persistent backdoor |
| **Lateral Movement** | SSH keys + network exposure → lateral movement |
| **Sandbox Escape** | LSM disabled + SUID binaries → namespace escape |

Each attack path includes: **severity** (critical/high/medium/low), **risk score** (0–100), **step-by-step attack chain**, **MITRE ATT&CK techniques**, **CWE mapping**, **remediation**, and **exploitability bonus**.

### Vulnerability Intelligence Engine

Matches installed software against known vulnerabilities:

- **Local database**: 104 curated CVE entries
- **Live feeds**: NVD, CISA KEV, EPSS, OSV, GitHub Advisory
- **Version matching**: Semantic versioning, Debian version strings, ranges, wildcards
- **Scoring**: CVSS base scores, EPSS probability, CISA KEV status
- **Feed management**: SQLite cache, ETag/Last-Modified, TTL expiry, retry/backoff, offline mode

### Exploitability Engine

Non-intrusive assessment of real-world attack feasibility:

- **Complexity modelling**: Low/Medium/High/Critical based on prerequisites
- **Attack surface analysis**: Network exposure, local access requirements
- **Exploit maturity**: Proof-of-concept, weaponised, in-the-wild
- **Mitigation awareness**: Existing countermeasures that reduce exploitability
- **Time estimation**: Hours/days/weeks to successful exploitation

---

## Plugin System

VINA includes a comprehensive plugin SDK with 14 lifecycle hook points:

### Hook Points

| Hook | Fires When |
|:-----|:-----------|
| `BEFORE_PIPELINE` / `AFTER_PIPELINE` | Pipeline starts/completes |
| `BEFORE_STAGE` / `AFTER_STAGE` | Each stage starts/completes |
| `BEFORE_FINDING` / `AFTER_FINDING` | Each finding is created/enriched |
| `BEFORE_REPORT` / `AFTER_REPORT` | Report generation starts/completes |
| `BEFORE_CORRELATION` / `AFTER_CORRELATION` | Correlation analysis starts/completes |
| `BEFORE_EXPLOITABILITY` / `AFTER_EXPLOITABILITY` | Exploitability scoring starts/completes |
| `BEFORE_VULNERABILITY_LOOKUP` / `AFTER_VULNERABILITY_LOOKUP` | CVE matching starts/completes |

### Plugin Discovery (5 mechanisms)

1. **Built-in plugins** — bundled with VINA
2. **Local directory** — `~/.vina/plugins/` and `./plugins/`
3. **Entry points** — `[project.entry-points."vina.plugins"]` in `pyproject.toml`
4. **Module paths** — explicit Python module paths in configuration
5. **Manual registration** — programmatic `registry.register(plugin)` calls

### Writing a Plugin

```python
from vina.plugins.sdk import Plugin, PluginMetadata

class MyPlugin(Plugin):
    metadata = PluginMetadata(
        id="my-plugin",
        name="My Plugin",
        version="1.0.0",
        author="Your Name",
        description="Example VINA plugin",
    )

    async def on_after_finding(self, finding, context):
        # Enrich or filter findings
        if "ssh" in finding.title.lower():
            finding.tags.append("custom-ssh-tag")
```

---

## Testing & Benchmarking

### Test Suite

VINA includes **27 test files** with **751 passing tests** covering every module:

```bash
# Run the full suite
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=vina --cov-report=html

# Run a specific test module
python -m pytest tests/test_os_container_security.py -v
```

### Testing Framework (`vina/testing/`)

| Component | Purpose |
|:----------|:--------|
| `fixtures.py` | MockCommandRunner, MockFindingFactory, MockPipelineContext |
| `benchmark.py` | BenchmarkProfile, BenchmarkResult, BenchmarkRunner |
| `metrics.py` | Precision, recall, F1, false-positive/negative rates, runtime, memory, CPU |
| `integration.py` | IntegrationTestSuite for end-to-end validation |
| `datasets.py` | Deterministic test dataset generation |
| `sandbox.py` | Isolated test environments |
| `runner.py` | TestPipelineRunner for controlled pipeline execution |

### Benchmarking

```bash
# List available profiles
vina benchmark-list

# Run a benchmark
vina benchmark-run default

# Compare results
vina benchmark-compare result_a.json result_b.json

# Generate report
vina benchmark-report results/
```

---

## Reports

VINA generates reports in three formats:

### JSON
Machine-readable output with complete finding data, enrichment details, vulnerability matches, correlation results, and exploitability assessments.

### Markdown
Human-readable security report with severity summaries, finding tables, attack path descriptions, and remediation guidance.

### HTML
Interactive report with:
- **JavaScript search and filter** across all findings
- **Severity cards** with colour-coded stats
- **Attack path visualisation** with step-by-step chain rendering
- **Exploitability assessment** tables with risk scoring
- **Vulnerability intelligence** summaries with CVE details

```bash
# Generate all formats
vina report

# Generate specific format
vina report --html
vina report --markdown
vina report --json
```

Reports are saved to `output/reports/` with filenames based on the scan target.

---

## Project Structure

```
vina/
├── cli.py                         # Typer CLI (16 commands)
├── _version.py                    # Auto-generated version info
├── ai/                            # AI analysis & report generation
├── core/                          # Core engines (15 files)
│   ├── knowledge.py               #   158 enrichment rules, GTFOBins, MITRE ATT&CK
│   ├── correlation.py             #   51 attack-path correlation rules
│   ├── exploitability.py          #   Exploitability scoring engine
│   ├── vuln_intel.py              #   Vulnerability intelligence (CVE matching)
│   ├── feed_manager.py            #   Live feed updates (NVD, KEV, EPSS, OSV, GitHub)
│   ├── scheduler.py               #   Dependency-aware parallel stage scheduler
│   ├── runner.py                  #   AsyncCommandRunner (subprocess execution)
│   ├── aggregator.py              #   Finding aggregation & statistics
│   ├── checkpoint.py              #   Pipeline checkpoint/resume support
│   ├── config.py                  #   YAML config loading + Pydantic validation
│   ├── dependency.py              #   External tool availability checking
│   ├── logging.py                 #   Logging configuration
│   ├── pipeline.py                #   Legacy scan pipeline orchestrator
│   └── storage.py                 #   JsonStore for scan result persistence
├── models/                        # Data models
│   ├── findings.py                #   Finding model, Severity, FindingCategory
│   ├── stages.py                  #   StageResult, StageDef, RetryConfig
│   └── common.py                  #   TargetInput, shared models
├── modules/                       # Pipeline module utilities
│   └── common.py                  #   ModuleContext, base module classes
├── pipeline/                      # Web pipeline
│   ├── web_pipeline.py            #   Web recon orchestrator (9 stages)
│   └── aggregator.py              #   URL/finding aggregation
├── plugins/                       # Plugin SDK (7 files)
│   ├── plugin.py                  #   Base Plugin class, PluginMetadata
│   ├── sdk.py                     #   Convenience re-exports
│   ├── registry.py                #   Plugin registry & dependency resolution
│   ├── loader.py                  #   Plugin discovery (5 mechanisms)
│   ├── hooks.py                   #   14 lifecycle hook points
│   ├── context.py                 #   PluginContext runtime context
│   └── exceptions.py              #   Plugin exception hierarchy
├── reports/                       # Report generators
│   ├── report.py                  #   Report orchestrator
│   ├── html.py                    #   Interactive HTML renderer
│   └── markdown.py                #   Markdown renderer
├── scanners/                      # Scanner modules
│   ├── os/                        #   OS assessment scanners
│   │   ├── os_pipeline.py         #     Pipeline orchestrator (29 stages)
│   │   ├── system_info.py         #     OS identification
│   │   ├── ssh.py                 #     SSH configuration audit
│   │   ├── kernel.py              #     Kernel analysis
│   │   ├── kernel_hardening.py    #     Sysctl hardening checks
│   │   ├── environment.py         #     Environment variable analysis
│   │   ├── packages.py            #     Package enumeration
│   │   ├── services.py            #     Service analysis
│   │   ├── users.py               #     User/group analysis
│   │   ├── filesystem.py          #     Filesystem permissions
│   │   ├── network.py             #     Network configuration
│   │   ├── processes.py           #     Process analysis
│   │   ├── cron.py                #     Cron job analysis
│   │   ├── systemd.py             #     Systemd unit analysis
│   │   ├── docker.py              #     Docker configuration
│   │   ├── logs.py                #     Log file analysis
│   │   ├── secrets.py             #     Secret/credential detection
│   │   ├── capabilities.py        #     Linux capabilities
│   │   ├── sudo.py                #     Sudo configuration
│   │   ├── privilege_escalation.py#     Privesc vector detection
│   │   ├── auth_security/         #     [PS-02] Auth & access control
│   │   ├── packages_security/     #     [PS-03] Package & supply chain
│   │   ├── network_security/      #     [PS-04] Network stack & firewall
│   │   ├── boot_security/         #     [PS-05] Boot & Secure Boot
│   │   ├── gui_security/          #     [PS-06] Desktop & GUI
│   │   ├── storage_security/      #     [PS-07] Filesystem & storage
│   │   ├── monitoring_security/   #     [PS-08] Logging & monitoring
│   │   ├── crypto_security/       #     [PS-09] Cryptography
│   │   └── container_security/    #     [PS-10] Containers & virtualisation
│   └── web/                       #   Web reconnaissance scanners
├── testing/                       # Testing & benchmarking framework
│   ├── benchmark.py               #   Benchmark profiles & runner
│   ├── fixtures.py                #   Mock objects & factories
│   ├── metrics.py                 #   Precision/recall/F1 metrics
│   ├── integration.py             #   Integration test suite
│   ├── datasets.py                #   Test dataset generation
│   ├── sandbox.py                 #   Isolated test environments
│   └── runner.py                  #   Test pipeline runner
├── parsers/                       # External tool output parsers
├── output/                        # Output handling
└── data/                          # Local vulnerability data
    └── cves.json                  #   104 curated CVE entries

tests/                             # Test suite (27 files, 751 tests)
docs/                              # Documentation (5 guides)
config/                            # Configuration files
templates/                         # Report templates
scripts/                           # Utility scripts
```

---

## Quality Gates

Before every release, VINA is validated against strict quality gates:

| Gate | Tool | Status |
|:-----|:-----|:-------|
| Linting | [`ruff check`](https://docs.astral.sh/ruff/) | 0 violations |
| Formatting | [`ruff format`](https://docs.astral.sh/ruff/) | All files formatted |
| Type Safety | [`mypy`](https://mypy-lang.org/) | 0 errors (144 source files) |
| Test Suite | [`pytest`](https://docs.pytest.org/) | 751 tests passing |
| Security | `bandit` | No high-severity issues |
| Dependencies | `pip-audit` | No known vulnerabilities |

---

## Configuration

VINA uses a YAML configuration file (`config.yaml`) with Pydantic validation:

```yaml
# config.yaml
scan:
  timeout: 300
  max_parallel: 6
  checkpoint: true

feeds:
  nvd: true
  cisa_kev: true
  epss: true
  osv: true
  github: true
  offline: false
  cache_ttl: 86400

reports:
  formats: [json, markdown, html]
  output_dir: output/reports

plugins:
  enabled: true
  directories:
    - ~/.vina/plugins/
    - ./plugins/
```

---

## Docker

VINA includes Docker support for containerised scanning:

```bash
# Build the image
docker build -t vina .

# Run an OS scan
docker run --privileged vina scan-os

# Development container
docker compose up -d
```

Available files:
- `Dockerfile` — Production image
- `Dockerfile.dev` — Development image with dev dependencies
- `docker-compose.yml` — Multi-service development environment

---

## Documentation

| Guide | Description |
|:------|:------------|
| [Architecture Guide](docs/ARCHITECTURE_GUIDE.md) | High-level design, data flow, component interaction |
| [Developer Guide](docs/DEVELOPER_GUIDE.md) | Project structure, adding scanners/rules, development workflow |
| [Plugin Author Guide](docs/PLUGIN_AUTHOR_GUIDE.md) | Plugin development, hooks, registration, lifecycle |
| [Release Guide](docs/RELEASE_GUIDE.md) | Versioning, publishing, CI/CD pipeline |
| [Contributing](docs/CONTRIBUTING.md) | Code of conduct, PR process, code standards |

---

## Requirements

### Python
- **Python 3.12+** (tested on 3.12, 3.13, 3.14)

### Core Dependencies
- `typer` ≥0.12 — CLI framework
- `rich` ≥13.7 — Terminal formatting
- `pyyaml` ≥6.0 — Configuration loading
- `pydantic` ≥2.0 — Data validation

### Optional Tools (Web Scanning)
For full web reconnaissance capability, install these external tools:

| Tool | Purpose |
|:-----|:--------|
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain discovery |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing |
| [naabu](https://github.com/projectdiscovery/naabu) | Port scanning |
| [nmap](https://nmap.org/) | Service detection |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | Technology fingerprinting |
| [katana](https://github.com/projectdiscovery/katana) | Web crawling |
| [gau](https://github.com/lc/gau) | Historical URL fetching |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Wayback Machine URLs |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanning |

Check tool availability with:
```bash
vina doctor
```

---

## License

[MIT](LICENSE)
