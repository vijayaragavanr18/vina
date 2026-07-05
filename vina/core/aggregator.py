"""Finding aggregation, deduplication, and statistics.

The :class:`FindingAggregator` collects findings from multiple scanner
stages, deduplicates them, groups by severity and category, and
provides summary statistics.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..models.findings import Finding, severity_key


@dataclass(slots=True)
class AggregatorStats:
    total: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    unique_hosts: int = 0
    unique_urls: int = 0
    stages_with_findings: int = 0
    attack_paths_total: int = 0
    attack_paths_by_severity: dict[str, int] = field(default_factory=dict)
    highest_attack_severity: str = ""
    average_attack_confidence: float = 0.0
    overall_risk_score: float = 0.0
    critical_chains: int = 0
    high_chains: int = 0


class FindingAggregator:
    """Collect, deduplicate, and analyse findings from pipeline stages."""

    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._seen_keys: set[tuple[str, str, str]] = set()

    def add_finding(self, finding: Finding) -> None:
        key = (
            finding.title.strip().lower(),
            finding.target.strip().lower(),
            finding.source_stage.strip().lower(),
        )
        if key not in self._seen_keys:
            self._seen_keys.add(key)
            self._findings.append(finding)

    def add_findings(self, findings: list[Finding]) -> None:
        for f in findings:
            self.add_finding(f)

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    @findings.setter
    def findings(self, value: list[Finding]) -> None:
        self._findings = []
        self._seen_keys.clear()
        self.add_findings(value)

    def deduplicate(self) -> list[Finding]:
        seen: set[tuple[str, str, str]] = set()
        deduped: list[Finding] = []
        for f in self._findings:
            key = (
                f.title.strip().lower(),
                f.target.strip().lower(),
                f.source_stage.strip().lower(),
            )
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    def group_by_severity(self) -> dict[str, list[Finding]]:
        groups: dict[str, list[Finding]] = {}
        for f in self._findings:
            groups.setdefault(f.severity, []).append(f)
        return groups

    def group_by_category(self) -> dict[str, list[Finding]]:
        groups: dict[str, list[Finding]] = {}
        for f in self._findings:
            groups.setdefault(f.category, []).append(f)
        return groups

    def sorted_by_severity(self, reverse: bool = True) -> list[Finding]:
        return sorted(
            self._findings,
            key=lambda f: severity_key(f.severity),
            reverse=reverse,
        )

    def statistics(self) -> AggregatorStats:
        if not self._findings:
            return AggregatorStats()

        sev_counter: Counter[str] = Counter()
        cat_counter: Counter[str] = Counter()
        hosts: set[str] = set()
        urls: set[str] = set()
        stages: set[str] = set()

        for f in self._findings:
            sev_counter[f.severity] += 1
            cat_counter[f.category] += 1
            if f.host:
                hosts.add(f.host)
            if f.url:
                urls.add(f.url)
            if f.source_stage:
                stages.add(f.source_stage)

        # Order severities by importance
        ordered_sev: dict[str, int] = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            ordered_sev[sev] = sev_counter.get(sev, 0)

        return AggregatorStats(
            total=len(self._findings),
            by_severity=ordered_sev,
            by_category=dict(cat_counter.most_common()),
            unique_hosts=len(hosts),
            unique_urls=len(urls),
            stages_with_findings=len(stages),
        )


__all__ = [
    "AggregatorStats",
    "FindingAggregator",
]
