"""Command-line interface for VINA."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .core.config import AppConfig, ConfigurationError
from .core.logging import configure_logging
from .core.pipeline import ScanPipeline
from .pipeline.web_pipeline import WebPipeline, StageStatistics as WebStageStats
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
) -> None:
    """Run the web reconnaissance pipeline.

    Stages: subfinder, httpx, naabu, nmap, whatweb, katana, gau + waybackurls, url_aggregator, nuclei.
    """
    _run_web(target, output_dir, config_path)


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
    stages: list[WebStageStats],
    total_duration: float,
) -> None:
    table = Table(title=title)
    table.add_column("Stage")
    table.add_column("Status", justify="right")
    table.add_column("Records", justify="right")

    for sr in stages:
        style_map = {"success": "green", "failed": "red", "skipped": "yellow", "empty": "dim"}
        style = style_map.get(sr.status, "")
        label = f"[{style}]{sr.status}[/{style}]" if style else sr.status
        table.add_row(sr.name, label, str(sr.record_count))

    console.print(Panel.fit(table, border_style="cyan"))
    console.print(f"Total duration: [bold]{total_duration:.2f}s[/bold]")


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


def _run_web(target: str, output_dir: Path | None, config_path: Path | None) -> None:
    config = _load_cfg(config_path)
    configure_logging(config.log_dir)
    result = _await(WebPipeline(config=config, output_dir=output_dir).run(target))

    _show_stage_table("Web Pipeline Results", result.stage_results, result.total_duration)


def _run_os(output_dir: Path | None, config_path: Path | None) -> None:
    config = _load_cfg(config_path)
    configure_logging(config.log_dir)
    result = _await(OSPipeline(config=config, output_dir=output_dir).run("localhost"))

    _show_stage_table("OS Pipeline Results", result.stage_results, result.total_duration)


__all__ = ["app"]
