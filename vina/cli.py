"""Command-line interface for VINA."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pathlib import Path

from .core.aggregator import FindingAggregator
from .core.config import AppConfig, ConfigurationError
from .core.logging import configure_logging
from .core.pipeline import ScanPipeline
from .models.stages import StageResult
from .pipeline.web_pipeline import WebPipeline
from .reports import generate_reports
from .scanners.os.os_pipeline import OSPipeline

app = typer.Typer(add_completion=False, help="VINA security automation framework")
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain or URL to scan"),
    output_dir: Path | None = typer.Option(None, "--output-dir", help="Directory for generated artifacts"),
    config_path: Path | None = typer.Option(None, "--config", help="Optional JSON config override"),
) -> None:
    """Run the legacy VINA pipeline for a target."""
    _run_legacy(target, output_dir, config_path)


@app.command()
def scan_web(
    target: str = typer.Argument(..., help="Target domain or URL to scan"),
    output_dir: Path | None = typer.Option(None, "--output-dir", help="Directory for generated artifacts"),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML/JSON config override"),
    resume: bool = typer.Option(False, "--resume", help="Resume from last checkpoint"),
    force: bool = typer.Option(False, "--force", help="Re-run all stages, ignoring cache and checkpoints"),
) -> None:
    """Run the web reconnaissance pipeline.

    Stages: subfinder, httpx, naabu, nmap, whatweb, katana, gau + waybackurls, url_aggregator, nuclei.
    """
    _run_web(target, output_dir, config_path, resume=resume, force=force)


@app.command()
def scan_os(
    output_dir: Path | None = typer.Option(None, "--output-dir", help="Directory for generated artifacts"),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML/JSON config override"),
) -> None:
    """Run the OS-level enumeration pipeline on the local host.

    Stages: host_recon, system_info, services, users, filesystem, capabilities, network, sudo, privilege_escalation.
    """
    _run_os(output_dir, config_path)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _fatal(message: str, code: int = 1) -> None:
    console.print(f"[red]Error:[/red] {message}")
    raise typer.Exit(code=code)


def _show_stage_table(
    title: str,
    stages: list[StageResult],
    total_duration: float,
) -> None:
    table = Table(title=title)
    table.add_column("Stage")
    table.add_column("Status", justify="right")
    table.add_column("Records", justify="right")
    table.add_column("Duration", justify="right")

    style_map = {
        "success": "green",
        "failed": "red",
        "skipped": "yellow",
        "empty": "dim",
        "timeout": "magenta",
        "missing_dependency": "red",
    }
    for sr in stages:
        style = style_map.get(sr.status.value, "")
        label = f"[{style}]{sr.status.value}[/{style}]" if style else sr.status.value
        table.add_row(sr.name, label, str(sr.record_count), f"{sr.duration:.1f}s")

    sequential_dur = sum(sr.duration for sr in stages)
    saved = sequential_dur - total_duration

    console.print(Panel.fit(table, border_style="cyan"))
    console.print(f"Pipeline duration: [bold]{total_duration:.2f}s[/bold]")
    console.print(f"Sequential estimate: [bold]{sequential_dur:.2f}s[/bold]")
    pct = (saved / sequential_dur * 100) if sequential_dur > 0 else 0.0
    if saved > 0:
        console.print(f"Time saved by parallelism: [bold green]{saved:.2f}s[/bold green] ({pct:.0f}% faster)")
    else:
        console.print(f"Time saved by parallelism: [bold]{saved:.2f}s[/bold]")


def _load_cfg(config_path: Path | None) -> AppConfig:
    try:
        return AppConfig.load(config_path)
    except ConfigurationError as exc:
        _fatal(str(exc))


def _await(coro) -> object:
    try:
        return asyncio.run(coro)
    except KeyboardInterrupt:
        _fatal("Interrupted by user", code=130)
    except Exception as exc:
        _fatal(str(exc))


# ------------------------------------------------------------------
# Runners
# ------------------------------------------------------------------


def _run_legacy(target: str, output_dir: Path | None, config_path: Path | None) -> None:
    config = _load_cfg(config_path)
    configure_logging(config.log_dir)
    result = _await(ScanPipeline(config=config, output_dir=output_dir).run(target))

    table = Table(title="VINA Summary")
    table.add_column("Stage")
    table.add_column("Count", justify="right")
    table.add_row("Assets", str(len(result.recon.assets)))
    table.add_row("Alive hosts", str(len(result.hosts.hosts)))
    table.add_row("Ports", str(len(result.ports.ports)))
    table.add_row("Tech fingerprints", str(len(result.technologies.technologies)))
    table.add_row("Crawled URLs", str(len(result.crawl.entries)))
    table.add_row("Historical URLs", str(len(result.history.urls)))
    table.add_row("Parameters", str(len(result.parameters.parameters)))
    table.add_row("Findings", str(len(result.findings.findings)))
    table.add_row("Analysis items", str(len(result.analysis.items)))

    console.print(Panel.fit(table, title="Scan Complete", border_style="cyan"))
    console.print(f"Markdown report: [bold]{result.report.markdown_path}[/bold]")
    console.print(f"HTML report: [bold]{result.report.html_path}[/bold]")


def _run_web(
    target: str,
    output_dir: Path | None,
    config_path: Path | None,
    *,
    resume: bool = False,
    force: bool = False,
) -> None:
    config = _load_cfg(config_path)
    configure_logging(config.log_dir)
    result = _await(WebPipeline(config=config, output_dir=output_dir).run(target, resume=resume, force=force))

    _show_stage_table("Web Pipeline Results", result.stage_results, result.total_duration)


def _run_os(output_dir: Path | None, config_path: Path | None) -> None:
    config = _load_cfg(config_path)
    configure_logging(config.log_dir)
    result = _await(OSPipeline(config=config, output_dir=output_dir).run("localhost"))

    _show_stage_table("OS Pipeline Results", result.stage_results, result.total_duration)

    # -- Vulnerability Intelligence Summary --
    vuln_matches = getattr(result, "vuln_matches", None) or []
    vuln_stats = getattr(result, "vuln_stats", None)

    if vuln_matches:
        console.print()
        vs = vuln_stats
        vuln_parts = [
            f"[bold]Software Components[/bold]: {vs.total_components if vs else 0}",
            f"[bold]Known Vulnerabilities[/bold]: {vs.total_vulnerabilities if vs else len(vuln_matches)}",
        ]
        if vs:
            vuln_parts.append(f"[bold]Critical CVEs[/bold]: {vs.critical_cves}")
            vuln_parts.append(f"[bold]KEV[/bold]: {vs.kev_count}")
            vuln_parts.append(f"[bold]Public Exploits[/bold]: {vs.public_exploits}")
            vuln_parts.append(f"[bold]Overall Vulnerability Score[/bold]: {vs.overall_score}/100")
            status_str = "[green]Online[/green]" if not vs.is_offline else "[yellow]Offline[/yellow]"
            vuln_parts.append(f"[bold]Database[/bold]: v{vs.db_version} {status_str}")
            if vs.last_updated:
                vuln_parts.append(f"[bold]Last Updated[/bold]: {vs.last_updated[:19]}")
            if vs.feed_age_hours >= 0:
                age_str = f"{vs.feed_age_hours:.1f}h" if vs.feed_age_hours < 24 else f"{vs.feed_age_hours / 24:.1f}d"
                vuln_parts.append(f"[bold]Feed Age[/bold]: {age_str}")
        console.print(Panel.fit(
            "\n".join(vuln_parts),
            title="Vulnerability Intelligence",
            border_style="red",
        ))

    # Show top CVEs
    if vuln_matches:
        from rich.table import Table as RichTable
        cve_table = RichTable(title="Top CVEs", box=None)
        cve_table.add_column("CVE")
        cve_table.add_column("Severity")
        cve_table.add_column("CVSS", justify="right")
        cve_table.add_column("Component")
        cve_table.add_column("Installed")
        cve_table.add_column("Fixed")
        for m in sorted(vuln_matches, key=lambda x: x.risk_score, reverse=True)[:8]:
            color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue", "info": "dim"}.get(m.vulnerability.severity.lower(), "")
            sev_label = f"[{color}]{m.vulnerability.severity.upper()}[/]" if color else m.vulnerability.severity.upper()
            cvss = f"{m.vulnerability.cvss_v3:.1f}" if m.vulnerability.cvss_v3 else ""
            cve_table.add_row(m.vulnerability.cve, sev_label, cvss, m.component.name, m.component.version, m.fixed_version or "N/A")
        console.print(cve_table)

    if findings := getattr(result, "findings", None):
        if vuln_matches:
            console.print()

        agg = FindingAggregator()
        agg.add_findings(findings)
        stats = agg.statistics()

        from .core.correlation import CorrelationEngine, compute_correlation_stats
        from .core.knowledge import EnrichmentEngine

        ee = EnrichmentEngine()
        enriched = ee.enrich_all(findings)
        ce = CorrelationEngine()
        paths = ce.run(enriched)
        ac_stats = compute_correlation_stats(paths)

        console.print()
        console.print(Panel.fit(
            f"[bold]Total Findings[/bold]: {stats.total}\n"
            f"[bold]Attack Paths[/bold]: {ac_stats.total_paths}\n"
            f"[bold]Critical Chains[/bold]: {ac_stats.critical_chains}\n"
            f"[bold]High Risk Chains[/bold]: {ac_stats.high_chains}\n"
            f"[bold]Overall Risk Score[/bold]: {ac_stats.overall_risk_score}/100\n"
            f"[bold]Highest Severity[/bold]: {ac_stats.highest_severity.title() if ac_stats.highest_severity else 'N/A'}\n"
            f"[bold]Average Confidence[/bold]: {ac_stats.average_confidence:.0%}",
            title="Attack Path Analysis",
            border_style="purple",
        ))

        # Show top attack paths
        if paths:
            from rich.table import Table as RichTable
            path_table = RichTable(title="Top Attack Paths", box=None)
            path_table.add_column("Title")
            path_table.add_column("Type")
            path_table.add_column("Severity")
            path_table.add_column("Score", justify="right")
            path_table.add_column("Confidence", justify="right")
            for p in sorted(paths, key=lambda x: x.score, reverse=True)[:5]:
                color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue", "info": "dim"}.get(p.severity.lower(), "")
                sev_label = f"[{color}]{p.severity.upper()}[/]" if color else p.severity.upper()
                path_table.add_row(p.title, p.attack_type.replace("_", " ").title(), sev_label, str(p.score), f"{p.confidence:.0%}")
            console.print(path_table)

    # -- Exploitability Assessment Summary --
    exp_assessments = getattr(result, "exploitability_assessments", None) or []
    if exp_assessments:
        console.print()
        exp_summary = getattr(result, "exploitability_summary", None)
        if exp_summary:
            exp_parts = [
                f"[bold]Total Assessments[/bold]: {exp_summary.total_assessments}",
                f"[bold]Critical (score ≥75)[/bold]: {exp_summary.critical_exploitable}",
                f"[bold]High (55-74)[/bold]: {exp_summary.high_exploitable}",
                f"[bold]Medium (35-54)[/bold]: {exp_summary.medium_exploitable}",
                f"[bold]Low (<35)[/bold]: {exp_summary.low_exploitable}",
                f"[bold]Average Score[/bold]: {exp_summary.average_score}/100",
                f"[bold]Highest Score[/bold]: {exp_summary.highest_score}/100",
            ]
            console.print(Panel.fit(
                "\n".join(exp_parts),
                title="Exploitability Assessment",
                border_style="orange1",
            ))
        # Show top exploits
        from rich.table import Table as RichTable
        exp_table = RichTable(title="Top Exploitability Assessments", box=None)
        exp_table.add_column("Title")
        exp_table.add_column("Score", justify="right")
        exp_table.add_column("Confidence", justify="right")
        exp_table.add_column("Complexity")
        exp_table.add_column("Est. Time")
        for a in sorted(exp_assessments, key=lambda x: x.overall_score, reverse=True)[:5]:
            color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue"}.get(
                _exploitability_tier(a.overall_score), ""
            )
            score_label = f"[{color}]{a.overall_score}[/]" if color else str(a.overall_score)
            cpx_color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue"}.get(
                a.complexity.split("_")[0] if "_" in a.complexity else a.complexity, ""
            )
            cpx_label = f"[{cpx_color}]{a.complexity.replace('_', ' ').title()}[/]" if cpx_color else a.complexity.replace('_', ' ').title()
            exp_table.add_row(
                a.title[:60],
                score_label,
                f"{a.confidence:.0%}",
                cpx_label,
                a.estimated_time_to_exploit,
            )
        console.print(exp_table)


def _exploitability_tier(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


# ------------------------------------------------------------------
# Report command
# ------------------------------------------------------------------


@app.command()
def report(
    output_dir: Path = typer.Option("output", "--output-dir", help="Pipeline output directory"),
    html_format: bool = typer.Option(False, "--html", help="Generate HTML report"),
    markdown_format: bool = typer.Option(False, "--markdown", help="Generate Markdown report"),
    json_format: bool = typer.Option(False, "--json", help="Generate JSON report"),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML/JSON config override"),
) -> None:
    """Generate reports from pipeline output.

    By default all report formats are generated.  Use ``--html``,
    ``--markdown`` or ``--json`` to select specific formats.
    """
    from .core.storage import JsonStore
    from .models.findings import Finding

    config = _load_cfg(config_path)

    store = JsonStore(output_dir)
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    target = "unknown"
    findings: list[Finding] = []
    stage_results: list[StageResult] = []

    # Try to read pipeline checkpoint
    checkpoint_dir = output_dir / "checkpoints"
    if checkpoint_dir.exists():
        cp_files = list(checkpoint_dir.glob("web_*.json"))
        if cp_files:
            cp = checkpoint_dir / cp_files[0]
            import json
            data = json.loads(cp.read_text())
            target = data.get("target", target)
            for stage_name, stage_data in data.get("stages", {}).items():
                sr = StageResult(
                    name=stage_name,
                    status=stage_data.get("status", "unknown"),
                    command=stage_data.get("command", ""),
                    exit_code=stage_data.get("exit_code"),
                    duration=stage_data.get("duration", 0.0),
                    record_count=stage_data.get("record_count", 0),
                    warnings=stage_data.get("warnings", []),
                )
                stage_results.append(sr)
            # Reconstruction of findings from checkpoint outputs
            outputs = data.get("stages", {})
            # If nuclei findings exist, reconstruct them
            for sname, sdata in outputs.items():
                host = target
                soutputs = sdata.get("outputs", {})
                rc = sdata.get("record_count", 0)
                if rc > 0:
                    cat_map = {
                        "subfinder": "subdomain",
                        "httpx": "alive_host",
                        "naabu": "open_port",
                        "nmap": "service",
                        "whatweb": "technology",
                        "katana": "endpoint",
                        "gau": "historical_url",
                        "waybackurls": "historical_url",
                        "nuclei": "vulnerability",
                    }
                    sev_map = {
                        "subfinder": "info",
                        "httpx": "info",
                        "naabu": "medium",
                        "nmap": "medium",
                        "whatweb": "info",
                        "katana": "info",
                        "gau": "info",
                        "waybackurls": "info",
                    }
                    if sname == "nuclei":
                        findings.append(Finding(
                            title=f"Nuclei findings",
                            description=f"{rc} vulnerabilities detected",
                            severity="high" if rc > 0 else "info",
                            category="vulnerability",
                            source_stage=sname,
                            target=target,
                            evidence=f"",
                            timestamp="",
                        ))
                    else:
                        cat = cat_map.get(sname, "other")
                        sev = sev_map.get(sname, "info")
                        findings.append(Finding(
                            title=f"{sname.title()} results: {rc} items",
                            description=f"{rc} items discovered by {sname}",
                            severity=sev,
                            category=cat,
                            source_stage=sname,
                            target=target,
                            evidence="",
                            timestamp="",
                        ))

    # Also try to read nuclei findings JSON directly
    nuclei_file = output_dir / "web" / "nuclei_findings.json"
    if nuclei_file.exists():
        import json as _json
        try:
            ndata = _json.loads(nuclei_file.read_text())
            for nf in ndata.get("findings", []):
                findings.append(Finding(
                    title=nf.get("template_name", nf.get("template_id", "Nuclei finding")),
                    description=f"Nuclei template: {nf.get('template_id', '')}",
                    severity=nf.get("severity", "info"),
                    category="vulnerability",
                    source_stage="nuclei",
                    target=nf.get("host", target),
                    evidence=nf.get("matched_url", "") or nf.get("extracted_results", [""])[0] if nf.get("extracted_results") else "",
                    host=nf.get("host", ""),
                    url=nf.get("matched_url", ""),
                    tags=nf.get("tags", []),
                    timestamp=nf.get("timestamp", ""),
                ))
        except Exception:
            pass

    # Aggregate
    agg = FindingAggregator()
    agg.add_findings(findings)
    stats = agg.statistics()

    # Determine formats
    explicit = {html_format, markdown_format, json_format}
    if not any(explicit):
        formats = {"json", "markdown", "html"}
    else:
        formats = set()
        if html_format:
            formats.add("html")
        if markdown_format:
            formats.add("markdown")
        if json_format:
            formats.add("json")

    generated = generate_reports(
        target=target,
        findings=findings,
        stage_results=stage_results,
        stats=stats,
        aggregator=agg,
        output_dir=reports_dir,
        formats=formats,
    )

    console.print("[green]Reports generated:[/green]")
    for fmt, path in generated.items():
        console.print(f"  [bold]{fmt}[/bold]: {path}")


# ------------------------------------------------------------------
# Version & Doctor commands
# ------------------------------------------------------------------


@app.command()
def version() -> None:
    """Show VINA version information."""
    from ._version import __version__, VERSION_INFO
    console.print(f"[bold]VINA[/bold] version [green]{__version__}[/green]")
    console.print(f"  Python: {__import__('sys').version}")
    info = VERSION_INFO
    console.print(f"  Major.Minor.Patch: {info['major']}.{info['minor']}.{info['patch']}")
    if info.get("pre_release"):
        console.print(f"  Pre-release: {info['pre_release']}")
    if info.get("build"):
        console.print(f"  Build: {info['build']}")
    try:
        import platform
        console.print(f"  Platform: {platform.system()} {platform.release()} ({platform.machine()})")
    except Exception:
        pass


@app.command()
def doctor() -> None:
    """Run diagnostic checks on the VINA installation."""
    from ._version import __version__
    issues: list[str] = []
    ok: list[str] = []

    # Python version
    import sys
    py_ver = sys.version
    ok.append(f"Python {py_ver}")
    major, minor = sys.version_info[:2]
    if (major, minor) >= (3, 12):
        ok.append("Python version OK (>= 3.12)")
    else:
        issues.append(f"Python {major}.{minor} < 3.12")

    # VINA version
    ok.append(f"VINA {__version__}")

    # Config check
    try:
        from .core.config import AppConfig, ConfigurationError
        try:
            config = AppConfig()
            ok.append("Configuration loaded")
        except ConfigurationError as e:
            issues.append(f"Configuration error: {e}")
    except Exception as e:
        issues.append(f"Config module error: {e}")

    # Writable directories
    dirs_to_check = {
        "Output": Path.cwd() / "output",
        "Cache": Path.home() / ".vina" / "cache",
        "Feeds": Path.home() / ".vina" / "feeds",
        "Plugins": Path.home() / ".vina" / "plugins",
    }
    for label, d in dirs_to_check.items():
        try:
            d.mkdir(parents=True, exist_ok=True)
            test_file = d / ".vina_write_test"
            test_file.write_text("ok")
            test_file.unlink()
            ok.append(f"{label} dir: {d} (writable)")
        except Exception as e:
            issues.append(f"{label} dir: {d} ({e})")

    # Vulnerability database
    try:
        from .core.vuln_intel import get_default_db
        db = get_default_db()
        count = len(db._entries) if hasattr(db, "_entries") else 0
        ok.append(f"Vulnerability database: {count} entries")
    except Exception as e:
        issues.append(f"Vulnerability database: {e}")

    # Feed manager
    try:
        from .core.feed_manager import get_default_manager
        fm = get_default_manager()
        meta = fm.get_metadata()
        total = meta.total_entries if hasattr(meta, "total_entries") else 0
        status = "offline" if getattr(meta, "is_offline", True) else "online"
        ok.append(f"Feed manager: {total} entries ({status})")
    except Exception as e:
        issues.append(f"Feed manager: {e}")

    # Plugin health
    try:
        from .plugins.registry import get_registry
        registry = get_registry()
        count = registry.count()
        ok.append(f"Plugins: {count} registered")
        for p in registry.list_plugins():
            deps = p.metadata.dependencies
            if deps:
                missing = [d for d in deps if registry.get(d) is None]
                if missing:
                    issues.append(f"Plugin '{p.metadata.id}' missing deps: {missing}")
    except Exception as e:
        issues.append(f"Plugins: {e}")

    # Available tools
    try:
        from .core.dependency import DependencyChecker
        checker = DependencyChecker()
        tools = ["find", "cat", "ls", "ps", "uname", "stat", "env"]
        available = sum(1 for t in tools if checker.available(t))
        ok.append(f"Core tools: {available}/{len(tools)} available")
    except Exception as e:
        issues.append(f"Tools check: {e}")

    # Cache integrity
    try:
        from .core.feed_manager import get_default_manager
        fm = get_default_manager()
        if fm.verify_integrity():
            ok.append("Cache integrity: OK")
        else:
            issues.append("Cache integrity: FAILED")
    except Exception:
        pass

    # Display results
    if ok:
        console.print("[bold green]OK:[/bold green]")
        for item in ok:
            console.print(f"  [green]✓[/green] {item}")
    if issues:
        console.print("\n[bold yellow]Issues:[/bold yellow]")
        for issue in issues:
            console.print(f"  [red]✗[/red] {issue}")
    if not issues:
        console.print("\n[green]All checks passed.[/green]")
    else:
        raise typer.Exit(code=1)


# ------------------------------------------------------------------
# Benchmark commands
# ------------------------------------------------------------------


@app.command()
def benchmark_list() -> None:
    """List available benchmark profiles."""
    from .testing.benchmark import get_benchmark_profiles
    profiles = get_benchmark_profiles()
    if not profiles:
        console.print("[yellow]No benchmark profiles registered.[/yellow]")
        return
    table = Table(title=f"Benchmark Profiles ({len(profiles)})")
    table.add_column("Name")
    table.add_column("Pipeline")
    table.add_column("Target")
    table.add_column("Expected Findings")
    table.add_column("Max Runtime")
    for name, p in sorted(profiles.items()):
        table.add_row(
            name,
            p.pipeline,
            p.target,
            str(len(p.expected_findings)),
            f"{p.max_runtime_seconds:.0f}s",
        )
    console.print(table)


@app.command()
def benchmark_run(
    profile_name: str = typer.Argument("mock-os-localhost", help="Benchmark profile name"),
    output_dir: Path | None = typer.Option(None, "--output-dir", help="Directory for benchmark output"),
) -> None:
    """Run a single benchmark profile and generate reports."""
    from .testing.benchmark import BenchmarkRunner, get_benchmark_profiles
    profiles = get_benchmark_profiles()
    if profile_name not in profiles:
        _fatal(f"Unknown benchmark profile '{profile_name}'. Use 'vina benchmark list' to see available profiles.")
        return

    profile = profiles[profile_name]
    out = output_dir or Path.cwd() / "benchmark_output"
    runner = BenchmarkRunner(output_dir=out)
    console.print(f"[bold]Running benchmark:[/bold] {profile.name}")
    console.print(f"  Target: {profile.target}")
    console.print(f"  Pipeline: {profile.pipeline}")
    console.print()

    result = runner.run_profile(profile)

    console.print()
    if result.passed:
        console.print(f"[green]✓ BENCHMARK PASSED[/green]")
    else:
        console.print(f"[red]✗ BENCHMARK FAILED[/red]")
        for err in result.errors:
            console.print(f"  [red]Error:[/red] {err}")

    if result.metrics:
        m = result.metrics
        console.print(f"\n[bold]Metrics:[/bold]")
        console.print(f"  Precision: {m.precision:.1%}")
        console.print(f"  Recall: {m.recall:.1%}")
        console.print(f"  F1 Score: {m.f1_score:.3f}")
        console.print(f"  Runtime: {m.runtime_seconds:.1f}s / {m.max_runtime_seconds:.0f}s budget")
        console.print(f"  Findings: {m.total_actual} actual, {m.total_expected} expected, {m.total_matched} matched")
        console.print(f"  Peak Memory: {m.peak_memory_mb:.1f} MB")

    # Save reports
    report_paths = result.save_report(out / "reports")
    console.print(f"\n[green]Reports saved:[/green]")
    for fmt, path in report_paths.items():
        console.print(f"  {fmt}: {path}")


@app.command()
def benchmark_compare(
    result_a: str = typer.Argument(..., help="Path to first benchmark JSON result"),
    result_b: str = typer.Argument(..., help="Path to second benchmark JSON result"),
) -> None:
    """Compare two benchmark results."""
    import json
    from pathlib import Path

    def load(path: str) -> dict:
        p = Path(path)
        if not p.exists():
            _fatal(f"File not found: {path}")
        return json.loads(p.read_text())

    data_a = load(result_a)
    data_b = load(result_b)

    table = Table(title="Benchmark Comparison")
    table.add_column("Metric")
    table.add_column(f"Result A")
    table.add_column(f"Result B")
    table.add_column("Delta")

    metrics_a = data_a.get("metrics", {})
    metrics_b = data_b.get("metrics", {})

    for key in ("precision", "recall", "f1_score", "accuracy", "runtime_seconds", "peak_memory_mb", "total_findings", "total_attack_paths"):
        val_a = metrics_a.get(key, data_a.get(key, 0))
        val_b = metrics_b.get(key, data_b.get(key, 0))
        delta = val_b - val_a
        delta_str = f"{delta:+.4f}" if isinstance(delta, float) else f"{delta:+d}"
        table.add_row(key, str(val_a), str(val_b), delta_str)

    console.print(table)


@app.command()
def benchmark_report(
    output_dir: Path = typer.Argument(..., help="Directory containing benchmark results"),
) -> None:
    """Generate an aggregate benchmark report from saved results."""
    from pathlib import Path
    import json
    from datetime import datetime

    results_dir = Path(output_dir) / "reports"
    if not results_dir.is_dir():
        _fatal(f"No benchmark reports found in {output_dir}/reports/")

    md_lines = [
        f"# Aggregate Benchmark Report",
        f"Generated: {datetime.now().isoformat()}",
        f"Source: {results_dir.resolve()}",
        "",
        "## Summary",
        "",
        "| Profile | Precision | Recall | F1 | Runtime | Memory | Passed |",
        "|---------|-----------|--------|----|---------|--------|--------|",
    ]

    json_files = sorted(results_dir.glob("*_benchmark.json"))
    if not json_files:
        console.print("[yellow]No benchmark JSON files found.[/yellow]")
        return

    for jf in json_files:
        try:
            data = json.loads(jf.read_text())
            m = data.get("metrics", {})
            name = data.get("profile", {}).get("name", jf.stem)
            precision = f"{m.get('precision', 0):.1%}"
            recall = f"{m.get('recall', 0):.1%}"
            f1 = f"{m.get('f1_score', 0):.3f}"
            runtime = f"{m.get('runtime_seconds', 0):.1f}s"
            memory = f"{m.get('peak_memory_mb', 0):.1f}MB"
            passed = "✅" if data.get("passed") else "❌"
            md_lines.append(f"| {name} | {precision} | {recall} | {f1} | {runtime} | {memory} | {passed} |")
        except Exception:
            pass

    report_md = "\n".join(md_lines)
    report_path = results_dir / "aggregate_benchmark_report.md"
    report_path.write_text(report_md, encoding="utf-8")
    console.print(f"[green]Aggregate report saved to:[/green] {report_path}")
    console.print()
    console.print(report_md)


# ------------------------------------------------------------------
# Plugin management commands
# ------------------------------------------------------------------


@app.command()
def plugin_list() -> None:
    """List all registered plugins and their status."""
    from .plugins.registry import get_registry
    registry = get_registry()
    plugins = registry.list_plugins()
    if not plugins:
        console.print("[yellow]No plugins registered.[/yellow]")
        return
    table = Table(title=f"Plugins ({len(plugins)})")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Enabled")
    table.add_column("Author")
    table.add_column("Categories")
    for p in plugins:
        enabled = "[green]Yes[/green]" if p.enabled else "[red]No[/red]"
        table.add_row(
            p.metadata.id,
            p.metadata.name,
            p.metadata.version,
            enabled,
            p.metadata.author,
            ", ".join(p.metadata.categories),
        )
    console.print(table)


@app.command()
def plugin_info(
    plugin_id: str = typer.Argument(..., help="Plugin ID"),
) -> None:
    """Show detailed information about a plugin."""
    from .plugins.registry import get_registry
    from .plugins.exceptions import PluginNotFoundError
    registry = get_registry()
    try:
        p = registry.get(plugin_id)
        if p is None:
            raise PluginNotFoundError(plugin_id)
    except PluginNotFoundError:
        _fatal(f"Plugin '{plugin_id}' not found")
        return
    meta = p.metadata
    enabled = "[green]Yes[/green]" if p.enabled else "[red]No[/red]"
    parts = [
        f"[bold]ID[/bold]: {meta.id}",
        f"[bold]Name[/bold]: {meta.name}",
        f"[bold]Version[/bold]: {meta.version}",
        f"[bold]Author[/bold]: {meta.author}",
        f"[bold]Description[/bold]: {meta.description}",
        f"[bold]License[/bold]: {meta.license or 'N/A'}",
        f"[bold]Homepage[/bold]: {meta.homepage or 'N/A'}",
        f"[bold]Min VINA Version[/bold]: {meta.minimum_vina_version}",
        f"[bold]Enabled[/bold]: {enabled}",
        f"[bold]Categories[/bold]: {', '.join(meta.categories)}",
        f"[bold]Dependencies[/bold]: {', '.join(meta.dependencies) or 'None'}",
    ]
    console.print(Panel.fit("\n".join(parts), title=f"Plugin: {meta.id}", border_style="cyan"))


@app.command()
def plugin_enable(
    plugin_id: str = typer.Argument(..., help="Plugin ID to enable"),
) -> None:
    """Enable a plugin."""
    from .plugins.registry import get_registry
    from .plugins.exceptions import PluginNotFoundError
    registry = get_registry()
    try:
        registry.enable(plugin_id)
        console.print(f"[green]Enabled plugin '{plugin_id}'[/green]")
    except PluginNotFoundError:
        _fatal(f"Plugin '{plugin_id}' not found")


@app.command()
def plugin_disable(
    plugin_id: str = typer.Argument(..., help="Plugin ID to disable"),
) -> None:
    """Disable a plugin."""
    from .plugins.registry import get_registry
    from .plugins.exceptions import PluginNotFoundError
    registry = get_registry()
    try:
        registry.disable(plugin_id)
        console.print(f"[yellow]Disabled plugin '{plugin_id}'[/yellow]")
    except PluginNotFoundError:
        _fatal(f"Plugin '{plugin_id}' not found")


@app.command()
def plugin_doctor() -> None:
    """Check plugin system health and diagnose issues."""
    from .plugins.registry import get_registry
    from .plugins.loader import LOCAL_PLUGIN_DIRS, ENTRY_POINT_GROUP
    registry = get_registry()
    issues: list[str] = []
    ok: list[str] = []

    plugin_count = registry.count()
    ok.append(f"Registered plugins: {plugin_count}")

    local_dirs = [d for d in LOCAL_PLUGIN_DIRS if d.is_dir()]
    if local_dirs:
        ok.append(f"Local plugin dirs: {', '.join(str(d) for d in local_dirs)}")
    else:
        issues.append("No local plugin directories found (checked ~/.vina/plugins/ and ./plugins/)")

    try:
        import importlib.metadata as ilm
        eps = ilm.entry_points(group=ENTRY_POINT_GROUP)
        if eps:
            ok.append(f"Entry-point plugins: {len(list(eps))}")
        else:
            ok.append("Entry-point plugins: none registered")
    except Exception as exc:
        issues.append(f"Entry-point discovery error: {exc}")

    for p in registry.list_plugins():
        meta = p.metadata
        if meta.dependencies:
            missing = [d for d in meta.dependencies if registry.get(d) is None]
            if missing:
                issues.append(f"Plugin '{meta.id}' missing dependencies: {', '.join(missing)}")

    if issues:
        console.print("[bold yellow]Issues Found:[/bold yellow]")
        for issue in issues:
            console.print(f"  [red]✗[/red] {issue}")
    if ok:
        console.print("[bold green]OK:[/bold green]")
        for item in ok:
            console.print(f"  [green]✓[/green] {item}")
    if not issues:
        console.print("[green]Plugin system is healthy.[/green]")


# ------------------------------------------------------------------
# Database management commands
# ------------------------------------------------------------------


@app.command()
def update_db(
    force: bool = typer.Option(False, "--force", help="Force re-download all feeds, ignoring cache"),
    offline: bool = typer.Option(False, "--offline", help="Show cached database status without updating"),
    status: bool = typer.Option(False, "--status", help="Show database status only"),
    feed_name: str | None = typer.Option(None, "--feed", help="Update a single feed (nvd, cisa_kev, epss, osv, github_advisory)"),
) -> None:
    """Update the local vulnerability database from external feeds.

    Fetches CVE data from NVD, CISA KEV, EPSS, OSV, and GitHub Security Advisories.
    """
    from .core.feed_manager import FeedManager, get_feed_status, FeedType

    manager = FeedManager()

    if offline or status:
        _show_db_status(manager)
        return

    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    console.print("[bold]Updating vulnerability database...[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Updating feeds...", total=None)

        if feed_name:
            result = manager.update_feed(feed_name, force=force)
            if result:
                from .core.feed_manager import UpdateStatus
                status_str = result.status.value
                color = "green" if result.status == UpdateStatus.SUCCESS else "yellow" if result.status == UpdateStatus.NO_UPDATE else "red"
                console.print(f"  {feed_name}: [{color}]{status_str}[/{color}] ({result.total_entries} entries)")
            else:
                console.print(f"  [red]Unknown feed: {feed_name}[/red]")
        else:
            results = manager.update(force=force)
            for name, result in results.items():
                from .core.feed_manager import UpdateStatus
                status_str = result.status.value
                color = "green" if result.status == UpdateStatus.SUCCESS else "yellow" if result.status == UpdateStatus.NO_UPDATE else "red"
                icon = "[green]✓[/]" if result.status == UpdateStatus.SUCCESS else "[yellow]~[/]" if result.status == UpdateStatus.NO_UPDATE else "[red]✗[/]"
                detail = f" ({result.total_entries} entries)" if result.total_entries > 0 else ""
                err_info = f" - {result.error}" if result.error else ""
                console.print(f"  {icon} {name}: [{color}]{status_str}[/{color}]{detail}{err_info}")

        progress.remove_task(task)

    console.print()
    _show_db_status(manager)


def _show_db_status(manager: FeedManager) -> None:
    """Display the current database status."""
    meta = manager.get_metadata()

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    status_color = "green" if not meta.is_offline else "yellow"
    status_label = "[green]Online[/green]" if not meta.is_offline else "[yellow]Offline[/yellow]"

    parts = [
        f"[bold]Database Status[/bold]: {status_label}",
        f"[bold]Total Entries[/bold]: {meta.total_entries}",
        f"[bold]Cache Size[/bold]: {_format_bytes(manager.cache_size_bytes)}",
    ]

    if meta.last_updated:
        try:
            updated = datetime.fromisoformat(meta.last_updated)
            age_hours = (now - updated).total_seconds() / 3600
            age_str = f"{age_hours:.1f}h" if age_hours < 24 else f"{age_hours / 24:.1f}d"
            parts.append(f"[bold]Last Updated[/bold]: {meta.last_updated[:19]} ({age_str} ago)")
            age_color = "green" if age_hours < 24 else "yellow" if age_hours < 72 else "red"
            parts.append(f"[bold]Feed Age[/bold]: [{age_color}]{age_str}[/{age_color}]")
        except (ValueError, TypeError):
            parts.append(f"[bold]Last Updated[/bold]: {meta.last_updated}")
    else:
        parts.append("[bold]Last Updated[/bold]: [red]Never[/red]")
        parts.append("[bold]Feed Age[/bold]: [red]N/A[/red]")

    parts.append(f"[bold]Checksum[/bold]: {meta.checksum[:16] if meta.checksum else 'N/A'}...")

    # Per-feed breakdown
    feed_lines = ["", "[bold]Feeds:[/bold]"]
    for ft_name, count in sorted(meta.feed_entry_counts.items()):
        ts = meta.feed_last_updated.get(ft_name, "never")
        feed_lines.append(f"  {ft_name}: {count} entries (last: {ts[:16] if ts != 'never' else 'never'})")
    parts.extend(feed_lines)

    console.print(Panel.fit("\n".join(parts), title="Vulnerability Database", border_style="blue"))

    if not manager.verify_integrity():
        console.print("[red]WARNING: Database integrity check failed! Run 'vina update-db --force' to rebuild.[/red]")


def _format_bytes(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


__all__ = ["app"]
