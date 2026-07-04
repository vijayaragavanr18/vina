"""Markdown report generation."""

from __future__ import annotations

from collections import Counter

from ..models.common import AnalysisItem, CrawlEntry, Finding, HistoricalUrlEntry, ParameterCandidate, PortEntry, TechnologyEntry


def render_markdown(
    target: str,
    findings: list[Finding],
    analysis: list[AnalysisItem],
    ports: list[PortEntry],
    technologies: list[TechnologyEntry],
    crawl_entries: list[CrawlEntry],
    history_entries: list[HistoricalUrlEntry],
    parameter_candidates: list[ParameterCandidate],
) -> str:
    severity_counts = Counter(finding.severity.lower() for finding in findings)
    lines: list[str] = [f"# VINA Report: {target}", ""]
    lines.append("## Summary")
    lines.append(f"- Findings: {len(findings)}")
    lines.append(f"- Analysis items: {len(analysis)}")
    lines.append(f"- Open ports: {len(ports)}")
    lines.append(f"- Technologies: {len(technologies)}")
    lines.append(f"- Crawled URLs: {len(crawl_entries)}")
    lines.append(f"- Historical URLs: {len(history_entries)}")
    lines.append(f"- Parameter candidates: {len(parameter_candidates)}")
    lines.append("")
    lines.append("## Severity Distribution")
    if severity_counts:
        for severity, count in sorted(severity_counts.items()):
            lines.append(f"- {severity.title()}: {count}")
    else:
        lines.append("- No findings recorded")
    lines.append("")
    lines.append("## Analysis")
    if analysis:
        for item in analysis:
            lines.append(f"### {item.finding_title}")
            lines.append(f"- Score: {item.score}")
            lines.append(f"- Rationale: {item.rationale}")
            if item.manual_verification:
                lines.append("- Manual verification:")
                for step in item.manual_verification:
                    lines.append(f"  - {step}")
            if item.payload_ideas:
                lines.append("- Payload ideas:")
                for payload in item.payload_ideas:
                    lines.append(f"  - {payload}")
            lines.append("")
    else:
        lines.append("No ranked analysis was produced.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
