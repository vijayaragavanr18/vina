"""High-level VINA pipeline orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..models.common import ReportArtifact, TargetInput
from ..modules.aggregate import AggregateModule, AggregateResult
from ..modules.ai_analysis import AIAnalysisModule, AnalysisResult
from ..modules.common import ModuleContext
from ..modules.crawl import CrawlModule, CrawlResult
from ..modules.historical_urls import HistoricalUrlModule, HistoricalUrlResult
from ..modules.host_discovery import HostDiscoveryModule, HostDiscoveryResult
from ..modules.parameter_discovery import ParameterDiscoveryModule, ParameterDiscoveryResult
from ..modules.port_scan import PortScanModule, PortScanResult
from ..modules.tech_detection import TechnologyDetectionModule, TechnologyDetectionResult
from ..modules.vulnerability_scan import VulnerabilityScanModule, VulnerabilityScanResult
from ..reports.html import render_html
from ..reports.markdown import render_markdown
from ..scanners.recon import ReconModule, ReconResult
from .config import AppConfig
from .runner import AsyncCommandRunner
from .storage import JsonStore


@dataclass(slots=True)
class PipelineResult:
    target: TargetInput
    recon: ReconResult
    hosts: HostDiscoveryResult
    ports: PortScanResult
    technologies: TechnologyDetectionResult
    crawl: CrawlResult
    history: HistoricalUrlResult
    parameters: ParameterDiscoveryResult
    findings: VulnerabilityScanResult
    aggregate: AggregateResult
    analysis: AnalysisResult
    report: ReportArtifact


class ScanPipeline:
    def __init__(self, config: AppConfig, output_dir: Path | None = None) -> None:
        self.config = config
        self.run_dir = self._create_run_dir(output_dir or config.output_dir)
        self.store = JsonStore(self.run_dir)
        self.runner = AsyncCommandRunner()
        self.context = ModuleContext(self.runner, self.store, self.config.timeout_seconds)

    async def run(self, target: str) -> PipelineResult:
        target_input = TargetInput.from_raw(target)

        recon = await ReconModule(self.config, self.context).run(target_input)
        self.store.save("recon/result.json", recon)

        hosts = await HostDiscoveryModule(self.config, self.context).run(recon.assets)
        self.store.save("hosts/result.json", hosts)

        ports = await PortScanModule(self.config, self.context).run(hosts.hosts)
        self.store.save("ports/result.json", ports)

        technologies = await TechnologyDetectionModule(self.config, self.context).run(hosts.hosts)
        self.store.save("technologies/result.json", technologies)

        crawl = await CrawlModule(self.config, self.context).run(hosts.hosts)
        self.store.save("crawl/result.json", crawl)

        history = await HistoricalUrlModule(self.config, self.context).run(target_input)
        self.store.save("history/result.json", history)

        parameter_urls = [entry.discovered_url for entry in crawl.entries] + [entry.url for entry in history.urls]
        parameters = await ParameterDiscoveryModule(self.config, self.context).run(parameter_urls)
        self.store.save("parameters/result.json", parameters)

        all_urls = [host.url for host in hosts.hosts] + parameter_urls
        findings = await VulnerabilityScanModule(self.config, self.context).run(all_urls, parameters.parameters)
        self.store.save("findings/result.json", findings)

        aggregate = AggregateModule().run(
            ports=ports.ports,
            technologies=technologies.technologies,
            crawl_entries=crawl.entries,
            history_entries=history.urls,
            parameter_candidates=parameters.parameters,
            findings=findings.findings,
        )
        self.store.save("aggregate/result.json", aggregate)

        analysis = AIAnalysisModule().run(
            findings=aggregate.findings,
            ports=aggregate.ports,
            technologies=aggregate.technologies,
            parameters=aggregate.parameter_candidates,
        )
        self.store.save("analysis/result.json", analysis)

        report = self._render_report(target_input, aggregate, analysis)
        return PipelineResult(
            target=target_input,
            recon=recon,
            hosts=hosts,
            ports=ports,
            technologies=technologies,
            crawl=crawl,
            history=history,
            parameters=parameters,
            findings=findings,
            aggregate=aggregate,
            analysis=analysis,
            report=report,
        )

    def _render_report(
        self, target: TargetInput, aggregate: AggregateResult, analysis: AnalysisResult
    ) -> ReportArtifact:
        markdown = render_markdown(
            target=target.normalized,
            findings=aggregate.findings,
            analysis=analysis.items,
            ports=aggregate.ports,
            technologies=aggregate.technologies,
            crawl_entries=aggregate.crawl_entries,
            history_entries=aggregate.history_entries,
            parameter_candidates=aggregate.parameter_candidates,
        )
        html = render_html(
            target=target.normalized,
            findings=aggregate.findings,
            analysis=analysis.items,
            ports=aggregate.ports,
            technologies=aggregate.technologies,
            crawl_entries=aggregate.crawl_entries,
            history_entries=aggregate.history_entries,
            parameter_candidates=aggregate.parameter_candidates,
        )
        markdown_path = self.run_dir / "reports" / "report.md"
        html_path = self.run_dir / "reports" / "report.html"
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(markdown, encoding="utf-8")
        html_path.write_text(html, encoding="utf-8")
        return ReportArtifact(markdown_path=str(markdown_path), html_path=str(html_path))

    @staticmethod
    def _create_run_dir(root: Path) -> Path:
        timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        run_dir = root / timestamp
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir
