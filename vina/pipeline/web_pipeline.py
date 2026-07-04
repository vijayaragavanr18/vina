"""Web pipeline orchestration for VINA.

Coordinates all web scanner modules in a fixed order,
passing structured dataclasses between stages.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Literal

from ..core.config import AppConfig
from ..core.runner import AsyncCommandRunner
from ..core.storage import JsonStore
from ..models.common import TargetInput
from ..modules.common import ModuleContext
from ..scanners.web.gau import GauModule
from ..scanners.web.httpx import HttpxModule
from ..scanners.web.katana import KatanaModule
from ..scanners.web.naabu import NaabuModule
from ..scanners.web.nmap import NmapModule
from ..scanners.web.nuclei import NucleiModule
from ..scanners.web.recon import ReconModule
from ..scanners.web.url_aggregator import UrlAggregatorModule
from ..scanners.web.waybackurls import WaybackurlsModule
from ..scanners.web.whatweb import WhatWebModule

StageStatus = Literal["success", "empty", "failed", "skipped"]


@dataclass(slots=True)
class StageStatistics:
    """Execution metadata for one pipeline stage."""

    name: str
    status: StageStatus
    execution_time: float
    warnings: list[str]
    record_count: int


@dataclass(slots=True)
class PipelineResult:
    """Aggregate result returned by the web pipeline."""

    target: TargetInput
    started_at: datetime
    finished_at: datetime
    total_duration: float
    stage_results: list[StageStatistics] = field(default_factory=list)
    summary: str = ""


class WebPipeline:
    """Coordinate the fixed web recon chain for a target."""

    def __init__(self, config: AppConfig, output_dir: Path | None = None) -> None:
        self.config = config
        self.output_root = output_dir or config.output_dir
        self.store = JsonStore(self.output_root)
        self.runner = AsyncCommandRunner()
        self.context = ModuleContext(
            self.runner, self.store, self.config.timeout_seconds
        )

    async def run(self, target: str) -> PipelineResult:
        """Run the full web pipeline and return a PipelineResult."""
        target_input = TargetInput.from_raw(target)
        started_at = datetime.now(timezone.utc)
        started_perf = perf_counter()

        stage_results: list[StageStatistics] = []
        subdomains: list[str] = []
        alive_hosts: list[str] = []
        open_ports: list[str] = []

        # Stage 1: Subfinder ---------------------------------------------------
        subfinder = ReconModule(self.config, self.context)
        subfinder_result = await subfinder.run(target_input)
        subdomains = subfinder_result.subdomains
        stage_results.append(
            self._stats(
                "subfinder",
                subfinder_result.execution_time_seconds,
                subfinder_result.warnings,
                len(subdomains),
                self._status(subfinder_result.command_result.succeeded, bool(subdomains)),
            )
        )

        # Stage 2: Httpx -------------------------------------------------------
        httpx_result: HttpxResult | None = None  # noqa: F821
        if not subdomains:
            stage_results.append(StageStatistics("httpx", "skipped", 0.0, [], 0))
        else:
            httpx = HttpxModule(self.config, self.context)
            httpx_result = await httpx.run(subdomains, target_input)
            alive_hosts = httpx_result.alive_hosts
            stage_results.append(
                self._stats(
                    "httpx",
                    httpx_result.execution_time_seconds,
                    httpx_result.warnings,
                    len(alive_hosts),
                    self._status(httpx_result.command_result.succeeded, bool(alive_hosts)),
                )
            )

        # Stage 3: Naabu -------------------------------------------------------
        naabu_result: NaabuResult | None = None  # noqa: F821
        if not alive_hosts:
            stage_results.append(StageStatistics("naabu", "skipped", 0.0, [], 0))
        else:
            naabu = NaabuModule(self.config, self.context)
            naabu_result = await naabu.run(alive_hosts, target_input)
            open_ports = naabu_result.open_ports
            stage_results.append(
                self._stats(
                    "naabu",
                    naabu_result.execution_time_seconds,
                    naabu_result.warnings,
                    len(open_ports),
                    self._status(naabu_result.command_result.succeeded, bool(open_ports)),
                )
            )

        # Stage 4: Nmap --------------------------------------------------------
        nmap_result: NmapResult | None = None  # noqa: F821
        if not open_ports:
            stage_results.append(StageStatistics("nmap", "skipped", 0.0, [], 0))
        else:
            nmap = NmapModule(self.config, self.context)
            nmap_result = await nmap.run(open_ports, target_input)
            stage_results.append(
                self._stats(
                    "nmap",
                    nmap_result.execution_time_seconds,
                    nmap_result.warnings,
                    nmap_result.host_count,
                    self._status(nmap_result.command_result.succeeded, nmap_result.host_count > 0),
                )
            )

        # Stage 5: WhatWeb -----------------------------------------------------
        whatweb_result: WhatWebResult | None = None  # noqa: F821
        if not alive_hosts:
            stage_results.append(StageStatistics("whatweb", "skipped", 0.0, [], 0))
        else:
            whatweb = WhatWebModule(self.config, self.context)
            whatweb_result = await whatweb.run(alive_hosts, target_input)
            stage_results.append(
                self._stats(
                    "whatweb",
                    whatweb_result.execution_time_seconds,
                    whatweb_result.warnings,
                    whatweb_result.host_count,
                    self._status(whatweb_result.command_result.succeeded, whatweb_result.host_count > 0),
                )
            )

        # Stage 6: Katana ------------------------------------------------------
        katana_result: KatanaResult | None = None  # noqa: F821
        if not alive_hosts:
            stage_results.append(StageStatistics("katana", "skipped", 0.0, [], 0))
        else:
            katana = KatanaModule(self.config, self.context)
            katana_result = await katana.run(alive_hosts, target_input)
            stage_results.append(
                self._stats(
                    "katana",
                    katana_result.execution_time_seconds,
                    katana_result.warnings,
                    len(katana_result.endpoints),
                    self._status(katana_result.command_result.succeeded, bool(katana_result.endpoints)),
                )
            )

        # Stage 7: Gau + Waybackurls (concurrent) ----------------------------
        gau_result: GauResult | None = None  # noqa: F821
        wayback_result: WaybackurlsResult | None = None  # noqa: F821
        if not alive_hosts:
            stage_results.append(StageStatistics("gau", "skipped", 0.0, [], 0))
            stage_results.append(StageStatistics("waybackurls", "skipped", 0.0, [], 0))
        else:
            gau = GauModule(self.config, self.context)
            wayback = WaybackurlsModule(self.config, self.context)
            gau_result, wayback_result = await asyncio.gather(
                gau.run(alive_hosts, target_input),
                wayback.run(alive_hosts, target_input),
            )
            stage_results.append(
                self._stats(
                    "gau",
                    gau_result.execution_time_seconds,
                    gau_result.warnings,
                    len(gau_result.urls),
                    self._status(gau_result.command_result.succeeded, bool(gau_result.urls)),
                )
            )
            stage_results.append(
                self._stats(
                    "waybackurls",
                    wayback_result.execution_time_seconds,
                    wayback_result.warnings,
                    len(wayback_result.urls),
                    self._status(wayback_result.command_result.succeeded, bool(wayback_result.urls)),
                )
            )

        # Stage 8: UrlAggregator ----------------------------------------------
        agg_result: UrlAggregatorResult | None = None  # noqa: F821
        if katana_result is None:
            stage_results.append(StageStatistics("url_aggregator", "skipped", 0.0, [], 0))
        else:
            aggregator = UrlAggregatorModule(self.config, self.context)
            agg_result = await aggregator.run(
                katana_result,
                gau_result,
                wayback_result,
            )
            stage_results.append(
                self._stats(
                    "url_aggregator",
                    agg_result.execution_time_seconds,
                    agg_result.warnings,
                    agg_result.unique_count,
                    self._status(agg_result.command_result.succeeded, agg_result.unique_count > 0),
                )
            )

        # Stage 9: Nuclei ------------------------------------------------------
        if agg_result is None or not agg_result.urls:
            stage_results.append(StageStatistics("nuclei", "skipped", 0.0, [], 0))
        else:
            nuclei = NucleiModule(self.config, self.context)
            nuclei_result = await nuclei.run(agg_result.urls, target_input)
            stage_results.append(
                self._stats(
                    "nuclei",
                    nuclei_result.execution_time_seconds,
                    nuclei_result.warnings,
                    len(nuclei_result.findings),
                    self._status(nuclei_result.command_result.succeeded, bool(nuclei_result.findings)),
                )
            )

        # Build result ---------------------------------------------------------
        finished_at = datetime.now(timezone.utc)
        total_duration = perf_counter() - started_perf
        summary = self._build_summary(target_input, stage_results, total_duration)
        print(summary)

        return PipelineResult(
            target=target_input,
            started_at=started_at,
            finished_at=finished_at,
            total_duration=total_duration,
            stage_results=stage_results,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _status(succeeded: bool, has_records: bool) -> StageStatus:
        if not succeeded:
            return "failed"
        if not has_records:
            return "empty"
        return "success"

    @staticmethod
    def _stats(
        name: str,
        execution_time: float,
        warnings: list[str],
        record_count: int,
        status: StageStatus,
    ) -> StageStatistics:
        return StageStatistics(
            name=name,
            status=status,
            execution_time=execution_time,
            warnings=warnings,
            record_count=record_count,
        )

    @staticmethod
    def _build_summary(
        target_input: TargetInput,
        stage_results: list[StageStatistics],
        total_duration: float,
    ) -> str:
        """Build a concise console summary."""
        target_display = (
            target_input.root_domain
            or target_input.hostname
            or target_input.normalized
        )

        lines = [
            "=" * 41,
            "VINA Web Pipeline",
            "=" * 41,
            f"Target:          {target_display}",
        ]
        for sr in stage_results:
            lines.append(f"  {sr.name:<18} {sr.status:<8} {sr.record_count}")
        lines.append(f"Total Duration:  {total_duration:.2f}s")
        lines.append("=" * 41)
        return "\n".join(lines)


__all__ = [
    "PipelineResult",
    "StageStatistics",
    "StageStatus",
    "WebPipeline",
]
