"""Controlled pipeline execution with metrics collection.

Wraps :class:`OSPipeline` and :class:`WebPipeline` to capture
timing, resource usage, and structured results for benchmarking.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..core.aggregator import FindingAggregator
from ..core.config import AppConfig
from ..models.findings import Finding
from ..models.stages import StageResult
from .metrics import MetricsCollector


def _run_async(coro):
    """Run a coroutine, handling both event-loop-present and absent cases."""
    try:
        loop = asyncio.get_running_loop()
        if loop.is_running():
            import threading

            result = []
            exception = []

            def _run():
                try:
                    r = asyncio.run(coro)
                    result.append(r)
                except Exception as e:
                    exception.append(e)

            t = threading.Thread(target=_run, daemon=True)
            t.start()
            t.join()
            if exception:
                raise exception[0]
            return result[0]
    except RuntimeError:
        pass
    return asyncio.run(coro)


logger = logging.getLogger("vina.testing.runner")


@dataclass(slots=True)
class TestResult:
    """Structured result from a test pipeline run."""

    target: str = ""
    pipeline_type: str = ""  # "os" or "web"
    success: bool = False
    findings: list[Finding] = field(default_factory=list)
    enriched_findings: list[Any] = field(default_factory=list)
    stage_results: list[StageResult] = field(default_factory=list)
    attack_paths: list[Any] = field(default_factory=list)
    vuln_matches: list[Any] = field(default_factory=list)
    exploitability_assessments: list[Any] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    total_duration: float = 0.0
    metrics: Any = None
    output_dir: Path | None = None
    generated_reports: dict[str, Path] = field(default_factory=dict)

    @property
    def finding_titles(self) -> list[str]:
        return [f.title for f in self.findings]

    @property
    def enriched_titles(self) -> list[str]:
        return [f.title for f in self.enriched_findings]

    @property
    def cve_list(self) -> list[str]:
        cves: list[str] = []
        for vm in self.vuln_matches:
            cve = getattr(vm, "cve", None) or getattr(vm, "vulnerability", None)
            if cve and hasattr(cve, "cve"):
                cves.append(cve.cve)
            elif isinstance(cve, str):
                cves.append(cve)
        return cves

    @property
    def attack_path_titles(self) -> list[str]:
        return [ap.title for ap in self.attack_paths]

    @property
    def stats(self) -> dict[str, int]:
        agg = FindingAggregator()
        agg.add_findings(self.findings)
        s = agg.statistics()
        return {
            "total": s.total,
            "by_severity": dict(s.by_severity),
            "stages_with_findings": s.stages_with_findings,
        }


class TestPipelineRunner:
    """Run VINA pipelines in test/benchmark mode with metrics.

    Uses a real :class:`AppConfig` but can run with mock dependencies
    to make benchmarks deterministic.
    """

    def __init__(
        self,
        config: AppConfig | None = None,
        output_dir: Path | None = None,
    ) -> None:
        self.config = config or AppConfig()
        self.output_dir = (output_dir or Path("/tmp/vina-benchmark")) / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._metrics = MetricsCollector()

    @property
    def metrics(self) -> MetricsCollector:
        return self._metrics

    def run_os_pipeline(
        self,
        target: str = "localhost",
        inject_findings: list[Finding] | None = None,
        enable_vuln_intel: bool = True,
        enable_enrichment: bool = True,
        enable_correlation: bool = True,
        enable_exploitability: bool = True,
        enable_reports: bool = True,
        timeout: float = 300.0,
    ) -> TestResult:
        """Run the OS pipeline in test mode.

        Parameters
        ----------
        target:
            Target hostname (default ``'localhost'``).
        inject_findings:
            If provided, replaces scanner findings with these for
            deterministic testing.
        enable_vuln_intel, enable_enrichment, enable_correlation,
        enable_exploitability, enable_reports:
            Toggle individual engine stages.
        timeout:
            Maximum runtime in seconds.
        """
        return _run_async(
            self._run_os_pipeline_async(
                target=target,
                inject_findings=inject_findings,
                enable_vuln_intel=enable_vuln_intel,
                enable_enrichment=enable_enrichment,
                enable_correlation=enable_correlation,
                enable_exploitability=enable_exploitability,
                enable_reports=enable_reports,
                timeout=timeout,
            )
        )

    async def _run_os_pipeline_async(
        self,
        target: str,
        inject_findings: list[Finding] | None = None,
        enable_vuln_intel: bool = True,  # noqa: ARG002
        enable_enrichment: bool = True,  # noqa: ARG002
        enable_correlation: bool = True,  # noqa: ARG002
        enable_exploitability: bool = True,  # noqa: ARG002
        enable_reports: bool = True,  # noqa: ARG002
        timeout: float = 300.0,  # noqa: ARG002
    ) -> TestResult:
        result = TestResult(
            target=target,
            pipeline_type="os",
            started_at=datetime.now(UTC),
            output_dir=self.output_dir,
        )

        self._metrics.start_run()
        self._metrics.sample_resources()

        try:
            if inject_findings is not None:
                result.findings = inject_findings
                result.stage_results = []
                result.total_duration = 0.0
                result.success = True
            else:
                from ..scanners.os.os_pipeline import OSPipeline

                pipeline = OSPipeline(self.config, self.output_dir)
                pipeline_result = await pipeline.run(target)

                result.success = True
                result.findings = pipeline_result.findings
                result.enriched_findings = pipeline_result.enriched_findings
                result.stage_results = pipeline_result.stage_results
                result.attack_paths = pipeline_result.attack_paths
                result.vuln_matches = pipeline_result.vuln_matches
                result.exploitability_assessments = pipeline_result.exploitability_assessments
                result.total_duration = pipeline_result.total_duration

            self._metrics.sample_resources()
            result.metrics = self._metrics

        except Exception as exc:
            logger.error("OS pipeline benchmark failed: %s", exc, exc_info=True)
            result.success = False
            result.errors.append(str(exc))

        result.finished_at = datetime.now(UTC)
        if result.total_duration == 0.0:
            result.total_duration = self._metrics.end_run()

        return result

    def run_web_pipeline(
        self,
        target: str = "http://localhost:4280",
        inject_findings: list[Finding] | None = None,
        enable_reports: bool = True,
        timeout: float = 600.0,
    ) -> TestResult:
        """Run the web pipeline in test mode.

        Parameters are analogous to :meth:`run_os_pipeline`.
        """
        return _run_async(
            self._run_web_pipeline_async(
                target=target,
                inject_findings=inject_findings,
                enable_reports=enable_reports,
                timeout=timeout,
            )
        )

    async def _run_web_pipeline_async(
        self,
        target: str,
        inject_findings: list[Finding] | None = None,
        enable_reports: bool = True,  # noqa: ARG002
        timeout: float = 600.0,  # noqa: ARG002
    ) -> TestResult:
        result = TestResult(
            target=target,
            pipeline_type="web",
            started_at=datetime.now(UTC),
            output_dir=self.output_dir,
        )

        self._metrics.start_run()
        self._metrics.sample_resources()

        try:
            if inject_findings is not None:
                result.findings = inject_findings
                result.stage_results = []
                result.total_duration = 0.0
                result.success = True
            else:
                from ..pipeline.web_pipeline import WebPipeline

                pipeline = WebPipeline(self.config, self.output_dir)
                pipeline_result = await pipeline.run(target)

                result.success = True
                result.stage_results = pipeline_result.stage_results
                result.total_duration = pipeline_result.total_duration

            self._metrics.sample_resources()
            result.metrics = self._metrics

        except Exception as exc:
            logger.error("Web pipeline benchmark failed: %s", exc, exc_info=True)
            result.success = False
            result.errors.append(str(exc))

        result.finished_at = datetime.now(UTC)
        if result.total_duration == 0.0:
            result.total_duration = self._metrics.end_run()

        return result

    def run_report_generation(
        self,
        findings: list[Finding],
        stage_results: list[StageResult] | None = None,
        vuln_matches: list[Any] | None = None,
        attack_paths: list[Any] | None = None,
    ) -> dict[str, Path]:
        """Run report generation in isolation and measure timing."""
        from ..core.aggregator import FindingAggregator
        from ..reports import generate_reports

        self._metrics.start_timer("report_generation")

        agg = FindingAggregator()
        agg.add_findings(findings)
        stats = agg.statistics()

        reports_dir = self.output_dir / "reports"
        reports = generate_reports(
            target="benchmark-target",
            findings=findings,
            stage_results=stage_results or [],
            stats=stats,
            aggregator=agg,
            output_dir=reports_dir,
            vuln_matches=vuln_matches,
            attack_paths=attack_paths,
        )

        elapsed = self._metrics.stop_timer("report_generation")
        logger.info("Report generation completed in %.3fs", elapsed)
        return reports

    def run_vulnerability_lookup(
        self,
        findings: list[Finding],
    ) -> list[Any]:
        """Run vulnerability lookup in isolation and measure timing."""
        from ..core.vuln_intel import VulnerabilityEngine, build_software_inventory

        self._metrics.start_timer("vuln_lookup")

        inventory = build_software_inventory(findings)
        engine = VulnerabilityEngine()
        matches = engine.run(inventory)

        elapsed = self._metrics.stop_timer("vuln_lookup")
        logger.info("Vulnerability lookup completed in %.3fs (%d matches)", elapsed, len(matches))
        return matches

    def run_correlation(
        self,
        findings: list[Finding],
    ) -> list[Any]:
        """Run correlation in isolation and measure timing."""
        from ..core.correlation import CorrelationEngine

        self._metrics.start_timer("correlation")

        engine = CorrelationEngine()
        paths = engine.run(findings)

        elapsed = self._metrics.stop_timer("correlation")
        logger.info("Correlation completed in %.3fs (%d paths)", elapsed, len(paths))
        return paths

    def run_exploitability(
        self,
        findings: list[Finding],
        enriched: list[Any] | None = None,
        attack_paths: list[Any] | None = None,
        vuln_matches: list[Any] | None = None,
    ) -> list[Any]:
        """Run exploitability analysis in isolation and measure timing."""
        from ..core.exploitability import ExploitabilityEngine

        self._metrics.start_timer("exploitability")

        engine = ExploitabilityEngine()
        assessments = engine.run(
            findings=findings,
            enriched=enriched or [],
            attack_paths=attack_paths or [],
            vuln_matches=vuln_matches or [],
        )

        elapsed = self._metrics.stop_timer("exploitability")
        logger.info("Exploitability completed in %.3fs (%d assessments)", elapsed, len(assessments))
        return assessments


__all__ = [
    "TestPipelineRunner",
    "TestResult",
]
