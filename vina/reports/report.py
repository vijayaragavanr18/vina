"""Report generation coordinator for VINA.

Generates JSON, Markdown, and HTML reports from pipeline results
and aggregated findings.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..core.aggregator import AggregatorStats, FindingAggregator
from ..core.correlation import AttackPath, CorrelationEngine, compute_correlation_stats
from ..core.exploitability import ExploitabilityAssessment, ExploitabilitySummary, compute_exploitability_summary
from ..core.knowledge import EnrichmentEngine
from ..core.vuln_intel import VulnerabilityMatch, VulnStats, compute_vuln_stats
from ..models.findings import Finding
from ..models.stages import StageResult
from ..plugins.registry import get_registry
from .html import render_html
from .markdown import render_markdown


def _build_enrichment_engine() -> EnrichmentEngine:
    """Build an EnrichmentEngine that incorporates plugin-provided rules."""
    registry = get_registry()
    extra = registry.get_enrichment_rules()
    if not extra:
        return EnrichmentEngine()
    from ..core.knowledge import ALL_RULES

    return EnrichmentEngine(rules=list(ALL_RULES) + extra)


def _build_correlation_engine() -> CorrelationEngine:
    """Build a CorrelationEngine that incorporates plugin-provided rules."""
    registry = get_registry()
    extra = registry.get_correlation_rules()
    if not extra:
        return CorrelationEngine()
    from ..core.correlation import _CORRELATION_RULES

    return CorrelationEngine(rules=list(_CORRELATION_RULES) + extra)


_ENRICHMENT_ENGINE = _build_enrichment_engine()
_CORRELATION_ENGINE = _build_correlation_engine()


def _pipeline_overview(stage_results: list[StageResult]) -> dict[str, Any]:
    stages_by_status: dict[str, int] = {}
    for sr in stage_results:
        status = sr.status.value if hasattr(sr.status, "value") else str(sr.status)
        stages_by_status[status] = stages_by_status.get(status, 0) + 1
    return {
        "total_stages": len(stage_results),
        "stages_by_status": stages_by_status,
    }


def _stage_rows(stage_results: list[StageResult]) -> list[dict[str, Any]]:
    return [
        {
            "name": sr.name,
            "status": sr.status.value if hasattr(sr.status, "value") else str(sr.status),
            "record_count": sr.record_count,
            "duration": round(sr.duration, 2),
            "warnings": sr.warnings,
        }
        for sr in stage_results
    ]


def generate_json_report(
    target: str,
    findings: list[Finding],
    stage_results: list[StageResult],
    stats: AggregatorStats,
    aggregator: FindingAggregator,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    *,
    enrich: bool = True,
    correlate_enabled: bool = True,
    attack_paths: list[AttackPath] | None = None,
    vuln_matches: list[VulnerabilityMatch] | None = None,
    vuln_stats: VulnStats | None = None,
    exploitability_assessments: list[ExploitabilityAssessment] | None = None,
    exploitability_summary: ExploitabilitySummary | None = None,
) -> dict[str, Any]:
    enriched_findings = _ENRICHMENT_ENGINE.enrich_all(findings) if enrich else findings
    paths = (
        attack_paths
        if attack_paths is not None
        else (_CORRELATION_ENGINE.run(enriched_findings) if correlate_enabled else [])
    )
    ac_stats = compute_correlation_stats(paths)
    vstats = vuln_stats or compute_vuln_stats(vuln_matches or [])
    exp_assessments = exploitability_assessments or []
    exp_summary = exploitability_summary or compute_exploitability_summary(exp_assessments)

    result: dict[str, Any] = {
        "report_type": "vina-json",
        "version": "2.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "target": target,
        "pipeline": {
            "started_at": started_at.isoformat() if started_at else "",
            "finished_at": finished_at.isoformat() if finished_at else "",
        },
        "summary": {
            "total_findings": stats.total,
            "by_severity": stats.by_severity,
            "by_category": stats.by_category,
            "unique_hosts": stats.unique_hosts,
            "unique_urls": stats.unique_urls,
            "total_stages": len(stage_results),
            "stages_with_findings": stats.stages_with_findings,
            "attack_paths": {
                "total": ac_stats.total_paths,
                "by_severity": ac_stats.by_severity,
                "highest_severity": ac_stats.highest_severity,
                "highest_score": ac_stats.highest_score,
                "average_confidence": ac_stats.average_confidence,
                "critical_chains": ac_stats.critical_chains,
                "high_chains": ac_stats.high_chains,
                "overall_risk_score": ac_stats.overall_risk_score,
            },
            "vulnerabilities": {
                "total": vstats.total_vulnerabilities,
                "by_severity": vstats.by_severity,
                "total_components": vstats.total_components,
                "critical_cves": vstats.critical_cves,
                "kev_count": vstats.kev_count,
                "public_exploits": vstats.public_exploits,
                "overall_score": vstats.overall_score,
                "db_version": vstats.db_version,
                "feed_age_hours": vstats.feed_age_hours,
                "last_updated": vstats.last_updated,
                "is_offline": vstats.is_offline,
            },
        },
        "findings": [f.to_dict() for f in enriched_findings],
        "attack_paths": [p.to_dict() for p in paths],
        "exploitability": {
            "total_assessments": exp_summary.total_assessments,
            "critical_exploitable": exp_summary.critical_exploitable,
            "high_exploitable": exp_summary.high_exploitable,
            "medium_exploitable": exp_summary.medium_exploitable,
            "low_exploitable": exp_summary.low_exploitable,
            "average_score": exp_summary.average_score,
            "highest_score": exp_summary.highest_score,
            "top_exploits": exp_summary.top_exploits,
            "assessments": [a.to_dict() for a in exp_assessments],
        },
        "vulnerabilities": vstats.top_cves,
        "components": [
            {
                "cve": m.vulnerability.cve,
                "component": m.component.name,
                "installed": m.component.version,
                "fixed": m.fixed_version,
            }
            for m in (vuln_matches or [])
        ],
        "stages": _stage_rows(stage_results),
        "findings_by_severity": {
            sev: [f.to_dict() for f in flist] for sev, flist in aggregator.group_by_severity().items()
        },
    }

    return result


def _write_report(
    output_dir: Path,
    filename: str,
    content: str,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(content, encoding="utf-8")
    return path


def generate_reports(
    target: str,
    findings: list[Finding],
    stage_results: list[StageResult],
    stats: AggregatorStats,
    aggregator: FindingAggregator,
    output_dir: Path,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    *,
    formats: set[str] | None = None,
    enrich: bool = True,
    correlate_enabled: bool = True,
    vuln_matches: list[VulnerabilityMatch] | None = None,
    vuln_stats: VulnStats | None = None,
    attack_paths: list[AttackPath] | None = None,
    exploitability_assessments: list[ExploitabilityAssessment] | None = None,
    exploitability_summary: ExploitabilitySummary | None = None,
) -> dict[str, Path]:
    """Generate report files in the requested formats.

    Parameters
    ----------
    target:
        The scanned target (domain or URL).
    findings:
        Full list of findings.
    stage_results:
        Stage results from the scheduler.
    stats:
        Pre-computed aggregator statistics.
    aggregator:
        The aggregator instance (used for groupings).
    output_dir:
        Directory for report files (``output/reports/``).
    started_at, finished_at:
        Pipeline timing.
    formats:
        Set of formats to generate.  If ``None``, all three are generated.
    enrich:
        Whether to enrich findings with knowledge-base data before rendering.
    correlate_enabled:
        Whether to run the correlation engine on enriched findings.
    vuln_matches:
        Vulnerability matches from the VulnerabilityEngine.
    vuln_stats:
        Pre-computed vulnerability statistics.
    attack_paths:
        Pre-computed attack paths (if None, correlation engine runs).
    exploitability_assessments:
        Pre-computed exploitability assessments.
    exploitability_summary:
        Pre-computed exploitability summary.

    Returns
    -------
    dict[str, Path]
        Mapping from format name to file path.
    """
    if formats is None:
        formats = {"json", "markdown", "html"}

    enriched_findings = _ENRICHMENT_ENGINE.enrich_all(findings) if enrich else findings
    computed_paths = (
        attack_paths
        if attack_paths is not None
        else (_CORRELATION_ENGINE.run(enriched_findings) if correlate_enabled else [])
    )
    ac_stats = compute_correlation_stats(computed_paths)

    # Compute vuln stats if not provided
    vstats = vuln_stats or compute_vuln_stats(vuln_matches or [])
    exp_assessments = exploitability_assessments or []
    exp_summary = exploitability_summary or compute_exploitability_summary(exp_assessments)

    # Update stats with attack path data
    stats.attack_paths_total = ac_stats.total_paths
    stats.attack_paths_by_severity = ac_stats.by_severity
    stats.highest_attack_severity = ac_stats.highest_severity
    stats.average_attack_confidence = ac_stats.average_confidence
    stats.overall_risk_score = ac_stats.overall_risk_score
    stats.critical_chains = ac_stats.critical_chains
    stats.high_chains = ac_stats.high_chains

    generated: dict[str, Path] = {}
    safe_target = target.replace("/", "_").replace(":", "_")

    if "json" in formats:
        data = generate_json_report(
            target,
            findings,
            stage_results,
            stats,
            aggregator,
            started_at,
            finished_at,
            enrich=enrich,
            correlate_enabled=correlate_enabled,
            attack_paths=computed_paths,
            vuln_matches=vuln_matches,
            vuln_stats=vstats,
            exploitability_assessments=exp_assessments,
            exploitability_summary=exp_summary,
        )
        path = _write_report(output_dir, f"{safe_target}_report.json", json.dumps(data, indent=2, default=str))
        generated["json"] = path

    if "markdown" in formats:
        md = render_markdown(
            target=target,
            findings=enriched_findings,
            stage_results=stage_results,
            stats=stats,
            aggregator=aggregator,
            attack_paths=computed_paths,
            vuln_matches=vuln_matches,
            vuln_stats=vstats,
            exploitability_assessments=exp_assessments,
            exploitability_summary=exp_summary,
        )
        path = _write_report(output_dir, f"{safe_target}_report.md", md)
        generated["markdown"] = path

    if "html" in formats:
        rendered_html = render_html(
            target=target,
            findings=enriched_findings,
            stage_results=stage_results,
            stats=stats,
            aggregator=aggregator,
            attack_paths=computed_paths,
            vuln_matches=vuln_matches,
            vuln_stats=vstats,
            exploitability_assessments=exp_assessments,
            exploitability_summary=exp_summary,
        )
        path = _write_report(output_dir, f"{safe_target}_report.html", rendered_html)
        generated["html"] = path

    return generated


__all__ = [
    "generate_json_report",
    "generate_reports",
]
