"""Web pipeline orchestration for VINA.

Coordinates all web scanner modules using a dependency-aware scheduler
that executes independent stages concurrently, with retry logic,
checkpointing, and resume support.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any, cast

from ..core.aggregator import FindingAggregator
from ..core.checkpoint import CheckpointManager
from ..core.config import AppConfig
from ..core.dependency import DependencyChecker
from ..core.runner import AsyncCommandRunner, CommandResult
from ..core.scheduler import PipelineScheduler, RetryConfig, StageDef
from ..core.storage import JsonStore
from ..models.common import TargetInput
from ..models.findings import Finding
from ..models.stages import (
    StageResult,
    StageState,
    build_missing_dependency_stage,
    build_skipped_stage,
    build_stage_result,
    log_stage_result,
    summary_for_stages,
)
from ..modules.common import ModuleContext
from ..reports import generate_reports
from ..scanners.web.gau import GauModule, GauResult
from ..scanners.web.httpx import HttpxModule
from ..scanners.web.katana import KatanaModule
from ..scanners.web.naabu import NaabuModule
from ..scanners.web.nmap import NmapModule
from ..scanners.web.nuclei import NucleiModule
from ..scanners.web.recon import ReconModule
from ..scanners.web.url_aggregator import UrlAggregatorModule
from ..scanners.web.waybackurls import WaybackurlsModule, WaybackurlsResult
from ..scanners.web.whatweb import WhatWebModule

logger = logging.getLogger(__name__)

# Tools required by the web pipeline, keyed by the stage name used in
# the skip-check.  Stages that are pure Python (e.g. url_aggregator)
# are omitted.
_REQUIRED_WEB_TOOLS: dict[str, str] = {
    "subfinder": "subfinder",
    "httpx": "httpx",
    "naabu": "naabu",
    "nmap": "nmap",
    "whatweb": "whatweb",
    "katana": "katana",
    "gau": "gau",
    "waybackurls": "waybackurls",
    "nuclei": "nuclei",
}

# Dependency graph.
# Each stage lists the stages it depends on.  Stages with no deps are
# eligible to run immediately.
_STAGE_DEPS: dict[str, list[str]] = {
    "subfinder": [],
    "httpx": ["subfinder"],
    "gau": ["subfinder"],
    "waybackurls": ["subfinder"],
    "naabu": ["httpx"],
    "whatweb": ["httpx"],
    "katana": ["httpx"],
    "nmap": ["naabu"],
    "url_aggregator": ["katana", "gau", "waybackurls"],
    "nuclei": ["url_aggregator"],
}

# Per-stage timeout overrides (seconds).  Stages not listed inherit the
# global timeout from the configuration.
_STAGE_TIMEOUTS: dict[str, int] = {"subfinder": 180, "httpx": 120, "naabu": 300, "nuclei": 900}


@dataclass(slots=True)
class PipelineResult:
    """Aggregate result returned by the web pipeline."""

    target: TargetInput
    started_at: datetime
    finished_at: datetime
    total_duration: float
    stage_results: list[StageResult] = field(default_factory=list)
    summary: str = ""


class WebPipeline:
    """Coordinate the fixed web recon chain for a target.

    Stages run according to the dependency graph defined in
    ``_STAGE_DEPS``, with independent stages executed concurrently
    up to ``_MAX_PARALLEL``.

    Supports checkpointing, resume (``--resume``), forced re-run
    (``--force``), automatic retry of transient failures, and
    per-stage timeout overrides.
    """

    _MAX_PARALLEL = 4

    def __init__(self, config: AppConfig, output_dir: Path | None = None) -> None:
        self.config = config
        self.output_root = output_dir or config.output_dir
        self.store = JsonStore(self.output_root)
        self.runner = AsyncCommandRunner()
        self.context = ModuleContext(self.runner, self.store, self.config.timeout_seconds)
        self._dep_checker = DependencyChecker(config)

    async def run(self, target: str, *, resume: bool = False, force: bool = False) -> PipelineResult:
        """Run the full web pipeline and return a PipelineResult.

        Parameters
        ----------
        target:
            The target domain or URL to scan.
        resume:
            When True, skip stages that completed successfully in a
            previous run (requires a checkpoint file).
        force:
            When True, ignore any existing checkpoint and re-run every
            stage.
        """
        # Pre-flight dependency check --------------------------------------
        self._run_dep_check()

        target_input = TargetInput.from_raw(target)
        started_at = datetime.now(UTC)
        started_perf = perf_counter()

        # Shared mutable state for passing data between stages.
        _results: dict[str, Any] = {}
        _rc: dict[str, int] = {}

        # Checkpoint setup ------------------------------------------------
        cp = CheckpointManager(self.output_root, "web", target)
        if force:
            cp.clear()

        _completed: set[str] = set()
        if resume and cp.exists():
            _completed = {name for name in cp.completed_stage_names() if cp.is_successfully_completed(name)}
            # Reconstruct shared outputs from checkpoint.
            restored = cp.restore_outputs()
            _results.update(restored)
            if _completed:
                print("Resuming from checkpoint...")

        def _tool(name: str) -> bool:
            tool = _REQUIRED_WEB_TOOLS.get(name)
            return self._dep_checker.available(tool) if tool else True

        def _ctx(timeout: int | None = None) -> ModuleContext:
            if timeout is None:
                return self.context
            return ModuleContext(self.runner, self.store, timeout)

        # Stage coroutines ------------------------------------------------

        async def _stage_subfinder() -> StageResult:
            if "subfinder" in _completed:
                print("  Skipping completed stage: subfinder")
                return cp.restore_stage("subfinder")
            if not _tool("subfinder"):
                return self._finish(
                    "subfinder", cp, build_missing_dependency_stage("subfinder", "subfinder"), _results, _rc
                )
            mod = ReconModule(self.config, _ctx(_STAGE_TIMEOUTS.get("subfinder")))
            res = await mod.run(target_input)
            _results["subdomains"] = res.subdomains
            _results["subfinder_result"] = res
            _rc["subfinder"] = len(res.subdomains)
            return self._finish("subfinder", cp, self._record("subfinder", res, _rc["subfinder"]), _results, _rc)

        async def _stage_httpx() -> StageResult:
            if "httpx" in _completed:
                print("  Skipping completed stage: httpx")
                return cp.restore_stage("httpx")
            subdomains = _results.get("subdomains", [])
            if not subdomains:
                return self._finish("httpx", cp, build_skipped_stage("httpx"), _results, _rc)
            if not _tool("httpx"):
                return self._finish("httpx", cp, build_missing_dependency_stage("httpx", "httpx"), _results, _rc)
            mod = HttpxModule(self.config, _ctx(_STAGE_TIMEOUTS.get("httpx")))
            res = await mod.run(subdomains, target_input)
            _results["alive_hosts"] = res.alive_hosts
            _results["httpx_result"] = res
            _rc["httpx"] = len(res.alive_hosts)
            return self._finish("httpx", cp, self._record("httpx", res, _rc["httpx"]), _results, _rc)

        async def _stage_gau() -> StageResult:
            if "gau" in _completed:
                print("  Skipping completed stage: gau")
                return cp.restore_stage("gau")
            subdomains = _results.get("subdomains", [])
            if not subdomains:
                return self._finish("gau", cp, build_skipped_stage("gau"), _results, _rc)
            if not _tool("gau"):
                return self._finish("gau", cp, build_missing_dependency_stage("gau", "gau"), _results, _rc)
            mod = GauModule(self.config, self.context)
            res = await mod.run(subdomains, target_input)
            _results["gau"] = res
            _rc["gau"] = len(res.urls)
            return self._finish("gau", cp, self._record("gau", res, _rc["gau"]), _results, _rc)

        async def _stage_waybackurls() -> StageResult:
            if "waybackurls" in _completed:
                print("  Skipping completed stage: waybackurls")
                return cp.restore_stage("waybackurls")
            subdomains = _results.get("subdomains", [])
            if not subdomains:
                return self._finish("waybackurls", cp, build_skipped_stage("waybackurls"), _results, _rc)
            if not _tool("waybackurls"):
                return self._finish(
                    "waybackurls", cp, build_missing_dependency_stage("waybackurls", "waybackurls"), _results, _rc
                )
            mod = WaybackurlsModule(self.config, self.context)
            res = await mod.run(subdomains, target_input)
            _results["waybackurls"] = res
            _rc["waybackurls"] = len(res.urls)
            return self._finish("waybackurls", cp, self._record("waybackurls", res, _rc["waybackurls"]), _results, _rc)

        async def _stage_naabu() -> StageResult:
            if "naabu" in _completed:
                print("  Skipping completed stage: naabu")
                return cp.restore_stage("naabu")
            alive = _results.get("alive_hosts", [])
            if not alive:
                return self._finish("naabu", cp, build_skipped_stage("naabu"), _results, _rc)
            if not _tool("naabu"):
                return self._finish("naabu", cp, build_missing_dependency_stage("naabu", "naabu"), _results, _rc)
            mod = NaabuModule(self.config, _ctx(_STAGE_TIMEOUTS.get("naabu")))
            res = await mod.run(alive, target_input)
            _results["open_ports"] = res.open_ports
            _results["naabu_result"] = res
            _rc["naabu"] = len(res.open_ports)
            return self._finish("naabu", cp, self._record("naabu", res, _rc["naabu"]), _results, _rc)

        async def _stage_nmap() -> StageResult:
            if "nmap" in _completed:
                print("  Skipping completed stage: nmap")
                return cp.restore_stage("nmap")
            ports = _results.get("open_ports", [])
            if not ports:
                return self._finish("nmap", cp, build_skipped_stage("nmap"), _results, _rc)
            if not _tool("nmap"):
                return self._finish("nmap", cp, build_missing_dependency_stage("nmap", "nmap"), _results, _rc)
            mod = NmapModule(self.config, self.context)
            res = await mod.run(ports, target_input)
            _results["nmap_result"] = res
            _rc["nmap"] = res.host_count
            return self._finish("nmap", cp, self._record("nmap", res, _rc["nmap"]), _results, _rc)

        async def _stage_whatweb() -> StageResult:
            if "whatweb" in _completed:
                print("  Skipping completed stage: whatweb")
                return cp.restore_stage("whatweb")
            alive = _results.get("alive_hosts", [])
            if not alive:
                return self._finish("whatweb", cp, build_skipped_stage("whatweb"), _results, _rc)
            if not _tool("whatweb"):
                return self._finish("whatweb", cp, build_missing_dependency_stage("whatweb", "whatweb"), _results, _rc)
            mod = WhatWebModule(self.config, self.context)
            res = await mod.run(alive, target_input)
            _results["whatweb_result"] = res
            _rc["whatweb"] = res.host_count
            return self._finish("whatweb", cp, self._record("whatweb", res, _rc["whatweb"]), _results, _rc)

        async def _stage_katana() -> StageResult:
            if "katana" in _completed:
                print("  Skipping completed stage: katana")
                return cp.restore_stage("katana")
            alive = _results.get("alive_hosts", [])
            if not alive:
                return self._finish("katana", cp, build_skipped_stage("katana"), _results, _rc)
            if not _tool("katana"):
                return self._finish("katana", cp, build_missing_dependency_stage("katana", "katana"), _results, _rc)
            mod = KatanaModule(self.config, self.context)
            res = await mod.run(alive, target_input)
            _results["katana"] = res
            _rc["katana"] = len(res.endpoints)
            return self._finish("katana", cp, self._record("katana", res, _rc["katana"]), _results, _rc)

        async def _stage_url_aggregator() -> StageResult:
            if "url_aggregator" in _completed:
                print("  Skipping completed stage: url_aggregator")
                return cp.restore_stage("url_aggregator")
            katana_res = _results.get("katana")
            if katana_res is None:
                return self._finish("url_aggregator", cp, build_skipped_stage("url_aggregator"), _results, _rc)
            mod = UrlAggregatorModule(self.config, self.context)
            res = await mod.run(
                katana_res, cast(GauResult, _results.get("gau")), cast(WaybackurlsResult, _results.get("waybackurls"))
            )
            _results["aggregated"] = res
            _rc["url_aggregator"] = res.unique_count
            return self._finish(
                "url_aggregator", cp, self._record("url_aggregator", res, _rc["url_aggregator"]), _results, _rc
            )

        async def _stage_nuclei() -> StageResult:
            if "nuclei" in _completed:
                print("  Skipping completed stage: nuclei")
                return cp.restore_stage("nuclei")
            agg = _results.get("aggregated")
            if agg is None or not agg.urls:
                return self._finish("nuclei", cp, build_skipped_stage("nuclei"), _results, _rc)
            if not _tool("nuclei"):
                return self._finish("nuclei", cp, build_missing_dependency_stage("nuclei", "nuclei"), _results, _rc)
            mod = NucleiModule(self.config, _ctx(_STAGE_TIMEOUTS.get("nuclei")))
            res = await mod.run(agg.urls, target_input)
            _results["nuclei"] = res
            _rc["nuclei"] = len(res.findings)
            return self._finish("nuclei", cp, self._record("nuclei", res, _rc["nuclei"]), _results, _rc)

        # Build stage definitions ------------------------------------------
        stages = [
            StageDef("subfinder", _STAGE_DEPS["subfinder"], _stage_subfinder, RetryConfig()),
            StageDef("httpx", _STAGE_DEPS["httpx"], _stage_httpx, RetryConfig()),
            StageDef("gau", _STAGE_DEPS["gau"], _stage_gau, RetryConfig()),
            StageDef("waybackurls", _STAGE_DEPS["waybackurls"], _stage_waybackurls, RetryConfig()),
            StageDef("naabu", _STAGE_DEPS["naabu"], _stage_naabu, RetryConfig()),
            StageDef("nmap", _STAGE_DEPS["nmap"], _stage_nmap, RetryConfig()),
            StageDef("whatweb", _STAGE_DEPS["whatweb"], _stage_whatweb, RetryConfig()),
            StageDef("katana", _STAGE_DEPS["katana"], _stage_katana, RetryConfig()),
            StageDef("url_aggregator", _STAGE_DEPS["url_aggregator"], _stage_url_aggregator),
            StageDef("nuclei", _STAGE_DEPS["nuclei"], _stage_nuclei, RetryConfig()),
        ]

        scheduler = PipelineScheduler(max_parallel=self._MAX_PARALLEL)
        scheduler_result = await scheduler.run(stages)

        # Collect findings from scanner results ---------------------------
        findings: list[Finding] = []
        result_keys = {
            "subfinder": "subfinder_result",
            "httpx": "httpx_result",
            "naabu": "naabu_result",
            "nmap": "nmap_result",
            "whatweb": "whatweb_result",
            "katana": "katana",
            "gau": "gau",
            "waybackurls": "waybackurls",
        }
        for _stage_name, result_key in result_keys.items():
            stage_res = _results.get(result_key)
            if stage_res is not None:
                sf = getattr(stage_res, "findings", None) or []
                findings.extend(sf)
        # Nuclei has unified_findings separately
        nuc_res = _results.get("nuclei")
        if nuc_res is not None:
            uf = getattr(nuc_res, "unified_findings", None) or []
            findings.extend(uf)
        # Also collect from aggregated result
        agg_res = _results.get("aggregated")
        if agg_res is not None:
            sf = getattr(agg_res, "findings", None) or []
            findings.extend(sf)

        # Aggregate and generate reports ----------------------------------
        agg = FindingAggregator()
        agg.add_findings(findings)
        stats = agg.statistics()
        target_display = target_input.root_domain or target_input.hostname or target_input.normalized
        reports_dir = self.output_root / "reports"
        if findings:
            generated = generate_reports(
                target=target_display,
                findings=findings,
                stage_results=scheduler_result.stage_results,
                stats=stats,
                aggregator=agg,
                output_dir=reports_dir,
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
            for fmt, path in generated.items():
                logger.info("Report generated: %s (%s)", path, fmt)

        # Build result -----------------------------------------------------
        finished_at = datetime.now(UTC)
        total_duration = perf_counter() - started_perf
        summary = summary_for_stages(
            "Web Pipeline", target_display, scheduler_result.stage_results, scheduler_result.total_duration
        )
        print(summary)

        return PipelineResult(
            target=target_input,
            started_at=started_at,
            finished_at=finished_at,
            total_duration=total_duration,
            stage_results=scheduler_result.stage_results,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_dep_check(self) -> None:
        """Check all required web tools and print the pre-flight summary."""
        results = self._dep_checker.check_all(list(_REQUIRED_WEB_TOOLS.values()))
        self._dep_checker.print_summary(results)

    @staticmethod
    def _finish(
        name: str, cp: CheckpointManager, stage: StageResult, results: dict[str, Any], _rc: dict[str, int]
    ) -> StageResult:
        """Record stage to checkpoint and log.  Returns the stage."""
        outputs = {}
        if name == "subfinder":
            outputs["subdomains"] = results.get("subdomains", [])
        elif name == "httpx":
            outputs["alive_hosts"] = results.get("alive_hosts", [])
        elif name == "naabu":
            outputs["open_ports"] = results.get("open_ports", [])
        cp.record_stage(stage, outputs=outputs)
        return stage

    @staticmethod
    def _record(name: str, result: Any, record_count: int) -> StageResult:
        """Build and log a :class:`StageResult` from a module result.

        Every module result is expected to expose ``command_result``
        (a :class:`CommandResult`), ``warnings`` (list[str]) and
        ``execution_time_seconds`` (float).
        """
        cr: CommandResult = result.command_result
        stage = build_stage_result(
            name=name,
            command_result=cr,
            record_count=record_count,
            warnings=result.warnings,
            extra_duration=result.execution_time_seconds,
        )
        log_stage_result(stage)
        return stage


__all__ = ["PipelineResult", "StageResult", "StageState", "WebPipeline"]
