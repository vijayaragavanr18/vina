"""Aggregation and deduplication stage."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models.common import CrawlEntry, HistoricalUrlEntry, ParameterCandidate, PortEntry, TechnologyEntry
from ..models.findings import Finding


@dataclass(slots=True)
class AggregateResult:
    ports: list[PortEntry] = field(default_factory=list)
    technologies: list[TechnologyEntry] = field(default_factory=list)
    crawl_entries: list[CrawlEntry] = field(default_factory=list)
    history_entries: list[HistoricalUrlEntry] = field(default_factory=list)
    parameter_candidates: list[ParameterCandidate] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class AggregateModule:
    def run(
        self,
        ports: list[PortEntry],
        technologies: list[TechnologyEntry],
        crawl_entries: list[CrawlEntry],
        history_entries: list[HistoricalUrlEntry],
        parameter_candidates: list[ParameterCandidate],
        findings: list[Finding],
    ) -> AggregateResult:
        return AggregateResult(
            ports=self._dedupe_ports(ports),
            technologies=self._dedupe_tech(technologies),
            crawl_entries=self._dedupe_crawl(crawl_entries),
            history_entries=self._dedupe_history(history_entries),
            parameter_candidates=self._dedupe_parameters(parameter_candidates),
            findings=self._dedupe_findings(findings),
        )

    @staticmethod
    def _dedupe_ports(ports: list[PortEntry]) -> list[PortEntry]:
        seen: set[tuple[str, int, str]] = set()
        deduped: list[PortEntry] = []
        for port in ports:
            key = (port.host, port.port, port.protocol)
            if key not in seen:
                seen.add(key)
                deduped.append(port)
        return deduped

    @staticmethod
    def _dedupe_tech(technologies: list[TechnologyEntry]) -> list[TechnologyEntry]:
        seen: set[tuple[str, str, str | None]] = set()
        deduped: list[TechnologyEntry] = []
        for tech in technologies:
            key = (tech.host, tech.name, tech.version)
            if key not in seen:
                seen.add(key)
                deduped.append(tech)
        return deduped

    @staticmethod
    def _dedupe_crawl(entries: list[CrawlEntry]) -> list[CrawlEntry]:
        seen: set[str] = set()
        deduped: list[CrawlEntry] = []
        for entry in entries:
            if entry.discovered_url not in seen:
                seen.add(entry.discovered_url)
                deduped.append(entry)
        return deduped

    @staticmethod
    def _dedupe_history(entries: list[HistoricalUrlEntry]) -> list[HistoricalUrlEntry]:
        seen: set[str] = set()
        deduped: list[HistoricalUrlEntry] = []
        for entry in entries:
            if entry.url not in seen:
                seen.add(entry.url)
                deduped.append(entry)
        return deduped

    @staticmethod
    def _dedupe_parameters(entries: list[ParameterCandidate]) -> list[ParameterCandidate]:
        seen: set[tuple[str, str]] = set()
        deduped: list[ParameterCandidate] = []
        for entry in entries:
            key = (entry.url, entry.parameter)
            if key not in seen:
                seen.add(key)
                deduped.append(entry)
        return deduped

    @staticmethod
    def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, str]] = set()
        deduped: list[Finding] = []
        for finding in findings:
            key = (finding.source_stage, finding.target, finding.title)
            if key not in seen:
                seen.add(key)
                deduped.append(finding)
        return deduped
