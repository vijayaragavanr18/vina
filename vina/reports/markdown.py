"""Markdown report generation for VINA."""

from __future__ import annotations

from typing import Any

from ..core.aggregator import AggregatorStats, FindingAggregator
from ..core.correlation import AttackPath
from ..core.exploitability import ExploitabilityAssessment, ExploitabilitySummary
from ..core.knowledge import EnrichedFinding
from ..core.vuln_intel import VulnerabilityMatch, VulnStats
from ..models.findings import Finding, Severity, severity_key
from ..models.stages import StageResult


def _esc_md(text: str) -> str:
    return text.replace("|", "\\|").replace("*", "\\*").replace("_", "\\_").replace("[", "\\[")


def _severity_badge(sev: str) -> str:
    sev_lower = sev.lower()
    colors = {
        "critical": "#e11d48",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#3b82f6",
        "info": "#6b7280",
    }
    color = colors.get(sev_lower, "#6b7280")
    return f"[{sev.upper()}]({color})"


def _is_enriched(f: Finding | EnrichedFinding) -> bool:
    return isinstance(f, EnrichedFinding) and f.has_enrichment()


def _chain_lines(chain: list[str]) -> str:
    return "\n".join(f"    {line}" for line in chain)


def render_markdown(
    target: str,
    findings: list[Finding],
    stage_results: list[StageResult],
    stats: AggregatorStats,
    aggregator: FindingAggregator,
    attack_paths: list[AttackPath] | None = None,
    vuln_matches: list[VulnerabilityMatch] | None = None,
    vuln_stats: VulnStats | None = None,
    exploitability_assessments: list[ExploitabilityAssessment] | None = None,
    exploitability_summary: ExploitabilitySummary | None = None,
) -> str:
    paths = attack_paths or []
    vmatches = vuln_matches or []
    exp_assessments = exploitability_assessments or []
    exp_summary = exploitability_summary

    lines: list[str] = []

    # ── Title ──────────────────────────────────────────────────────────────
    lines.append(f"# VINA Security Report: {_esc_md(target)}")
    lines.append("")
    lines.append(f"*Generated on {__import__('datetime').datetime.now():%Y-%m-%d %H:%M:%S UTC}*")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Executive Summary ──────────────────────────────────────────────────
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"This report presents the results of an automated security reconnaissance scan ")
    lines.append(f"performed against **{_esc_md(target)}**.")
    lines.append("")

    if stats.total > 0:
        critical = stats.by_severity.get("critical", 0)
        high = stats.by_severity.get("high", 0)
        medium = stats.by_severity.get("medium", 0)
        low = stats.by_severity.get("low", 0)
        info = stats.by_severity.get("info", 0)
        lines.append(f"- **Total Findings**: {stats.total}")
        if critical:
            lines.append(f"- **Critical**: {critical}")
        if high:
            lines.append(f"- **High**: {high}")
        if medium:
            lines.append(f"- **Medium**: {medium}")
        if low:
            lines.append(f"- **Low**: {low}")
        if info:
            lines.append(f"- **Info**: {info}")
        lines.append(f"- **Unique Hosts**: {stats.unique_hosts}")
        lines.append(f"- **Unique URLs**: {stats.unique_urls}")
    else:
        lines.append("No findings were discovered during this scan.")

    # ── Executive Vulnerability Summary ────────────────────────────────────
    if vmatches:
        vs = vuln_stats
        lines.append("")
        lines.append("### Executive Vulnerability Summary")
        lines.append("")
        lines.append(f"- **Software Components**: {vs.total_components if vs else 0}")
        lines.append(f"- **Known Vulnerabilities**: {vs.total_vulnerabilities if vs else len(vmatches)}")
        if vs:
            if vs.critical_cves:
                lines.append(f"- **Critical CVEs**: {vs.critical_cves}")
            if vs.kev_count:
                lines.append(f"- **KEV (Known Exploited Vulnerabilities)** : {vs.kev_count}")
            if vs.public_exploits:
                lines.append(f"- **Public Exploits Available**: {vs.public_exploits}")
            lines.append(f"- **Overall Vulnerability Score**: {vs.overall_score}/100")
            # Feed info
            status_str = "Offline" if vs.is_offline else "Online"
            lines.append(f"- **Database Version**: {vs.db_version}")
            if vs.last_updated:
                lines.append(f"- **Last Updated**: {vs.last_updated[:19]}")
            if vs.feed_age_hours >= 0:
                age_str = f"{vs.feed_age_hours:.1f}h" if vs.feed_age_hours < 24 else f"{vs.feed_age_hours / 24:.1f}d"
                lines.append(f"- **Feed Age**: {age_str}")
            lines.append(f"- **Status**: {status_str}")
        lines.append("")

    # ── Executive Attack Summary ───────────────────────────────────────────
    if stats.attack_paths_total > 0:
        lines.append("")
        lines.append("### Executive Attack Summary")
        lines.append("")
        lines.append(f"- **Attack Paths**: {stats.attack_paths_total}")
        if stats.critical_chains:
            lines.append(f"- **Critical Attach Paths**: {stats.critical_chains}")
        if stats.high_chains:
            lines.append(f"- **High Risk Attach Paths**: {stats.high_chains}")
        lines.append(f"- **Overall Risk Score**: {stats.overall_risk_score}/100")
        if stats.highest_attack_severity:
            lines.append(f"- **Highest Severity**: {stats.highest_attack_severity.title()}")
        if stats.highest_attack_severity in ("critical", "high"):
            lines.append("- **Potential Root Compromise**: YES")
        has_cred = any(p.attack_type == "credential_exposure" for p in paths)
        has_lat = any(p.attack_type == "lateral_movement" for p in paths)
        has_persist = any(p.attack_type == "persistence" for p in paths)
        if has_cred:
            lines.append("- **Credential Exposure**: YES")
        if has_lat:
            lines.append("- **Lateral Movement Risk**: YES")
        if has_persist:
            persist_count = sum(1 for p in paths if p.attack_type == "persistence")
            lines.append(f"- **Persistence Opportunities**: {persist_count}")
        lines.append("")

    lines.append("")

    # ── Pipeline Overview ──────────────────────────────────────────────────
    lines.append("## Pipeline Overview")
    lines.append("")
    lines.append(f"The web reconnaissance pipeline ran **{len(stage_results)}** stages across the target.")
    lines.append("")

    stage_statuses: dict[str, int] = {}
    for sr in stage_results:
        status = sr.status.value if hasattr(sr.status, "value") else str(sr.status)
        stage_statuses[status] = stage_statuses.get(status, 0) + 1
    for status, count in stage_statuses.items():
        lines.append(f"- **{status.title()}**: {count}")
    lines.append("")

    # ── Stage Execution Table ──────────────────────────────────────────────
    lines.append("## Stage Execution Details")
    lines.append("")
    lines.append("| Stage | Status | Records | Duration |")
    lines.append("|-------|--------|---------|----------|")
    for sr in stage_results:
        status = sr.status.value if hasattr(sr.status, "value") else str(sr.status)
        lines.append(f"| {_esc_md(sr.name)} | {status} | {sr.record_count} | {sr.duration:.1f}s |")
    lines.append("")

    # ── Attack Paths ───────────────────────────────────────────────────────
    if paths:
        lines.append("## Attack Paths")
        lines.append("")
        for path in paths:
            color = _severity_color_md(path.severity)
            lines.append(f"### {path.title}")
            lines.append("")
            lines.append(f"- **Severity**: {_severity_badge(path.severity)}")
            lines.append(f"- **Score**: {path.score}/100")
            lines.append(f"- **Confidence**: {path.confidence:.0%}")
            lines.append(f"- **Type**: {path.attack_type.replace('_', ' ').title()}")
            lines.append("")
            if path.description:
                lines.append(f"{path.description}")
                lines.append("")
            if path.attack_chain:
                lines.append("**Attack Chain:**")
                lines.append("")
                lines.append("```")
                lines.append(_chain_lines(path.attack_chain))
                lines.append("```")
                lines.append("")
            if path.explanation:
                lines.append(f"**Explanation:** {path.explanation}")
                lines.append("")
            if path.evidence:
                lines.append("**Supporting Findings:**")
                for line in path.evidence.split("\n"):
                    lines.append(f"- {_esc_md(line)}")
                lines.append("")
            if path.remediation:
                lines.append(f"**Remediation:** {path.remediation}")
                lines.append("")
            if path.mitre_attack:
                for ta in path.mitre_attack:
                    lines.append(f"- **MITRE ATT&CK**: {ta}")
            if path.cwe:
                lines.append(f"- **CWE**: {path.cwe}")
            if path.cis_controls:
                for cc in path.cis_controls:
                    lines.append(f"- **CIS**: {cc}")
            if path.references:
                for ref in path.references:
                    lines.append(f"- **Reference**: {ref}")
            lines.append("")

    # ── Exploitability Analysis ───────────────────────────────────────────
    if exp_assessments:
        lines.append("## Exploitability Analysis")
        lines.append("")
        es = exp_summary
        if es:
            lines.append(f"- **Total Assessments**: {es.total_assessments}")
            lines.append(f"- **Critical (score ≥75)** : {es.critical_exploitable}")
            lines.append(f"- **High (score 55-74)** : {es.high_exploitable}")
            lines.append(f"- **Medium (score 35-54)** : {es.medium_exploitable}")
            lines.append(f"- **Low (score <35)** : {es.low_exploitable}")
            lines.append(f"- **Average Score**: {es.average_score}/100")
            lines.append(f"- **Highest Score**: {es.highest_score}/100")
            lines.append("")

        for idx, a in enumerate(exp_assessments):
            color = _severity_color_md(a.complexity)
            lines.append(f"### {a.title}")
            lines.append("")
            lines.append(f"- **Score**: {a.overall_score}/100")
            lines.append(f"- **Confidence**: {a.confidence:.0%}")
            lines.append(f"- **Complexity**: {a.complexity.replace('_', ' ').title()}")
            lines.append(f"- **Attack Vector**: {a.attack_vector.replace('_', ' ').title()}")
            lines.append(f"- **Required Access**: {a.required_access.replace('_', ' ').title()}")
            lines.append(f"- **Required Privileges**: {a.required_privileges.title()}")
            lines.append(f"- **Estimated Time**: {a.estimated_time_to_exploit}")
            if a.attack_surface:
                lines.append(f"- **Attack Surface**: {a.attack_surface.replace('_', ' ').title()}")
            if a.exploit_maturity:
                lines.append(f"- **Exploit Maturity**: {a.exploit_maturity.replace('_', ' ').title()}")
            if a.reason:
                lines.append("")
                lines.append(f"**Reason:** {a.reason}")
            if a.score_breakdown:
                sb = a.score_breakdown
                lines.append("")
                lines.append("**Score Breakdown:**")
                lines.append(f"- Attack Surface: {sb.attack_surface_score}")
                lines.append(f"- Privilege Requirement: {sb.privilege_requirement_score}")
                lines.append(f"- Network Exposure: {sb.network_exposure_score}")
                lines.append(f"- Exploit Maturity: {sb.exploit_maturity_score}")
                lines.append(f"- Public Exploit: {sb.public_exploit_score}")
                lines.append(f"- Mitigation Bypass: {sb.mitigation_bypass_score}")
                lines.append(f"- Environmental: {sb.environmental_score}")
                lines.append(f"- Confidence Multiplier: {sb.confidence_multiplier}")
            if a.exploit_paths:
                lines.append("")
                lines.append("**Exploit Path:**")
                for ep in a.exploit_paths:
                    step_line = f"- {ep.step}"
                    if ep.severity:
                        step_line += f" *({ep.severity})*"
                    lines.append(step_line)
            if a.mitigations_present:
                lines.append("")
                lines.append(f"**Active Mitigations:** {', '.join(a.mitigations_present)}")
            if a.mitigations_absent:
                lines.append("")
                lines.append(f"**Missing Mitigations:** {', '.join(a.mitigations_absent)}")
            if a.blocking_controls:
                lines.append("")
                lines.append(f"**Blocking Controls:** {', '.join(a.blocking_controls)}")
            if a.missing_prerequisites:
                lines.append("")
                lines.append(f"**Missing Prerequisites:** {', '.join(a.missing_prerequisites)}")
            if a.recommended_next_steps:
                lines.append("")
                lines.append("**Recommended Next Steps:**")
                for s in a.recommended_next_steps:
                    lines.append(f"- {s}")
            lines.append("")

    # ── Known Vulnerabilities ──────────────────────────────────────────────
    if vmatches:
        lines.append("## Known Vulnerabilities")
        lines.append("")
        lines.append("| CVE | Severity | CVSS | EPSS | KEV | Component | Installed | Fixed |")
        lines.append("|-----|----------|------|------|-----|-----------|-----------|-------|")
        for m in sorted(vmatches, key=lambda x: (x.vulnerability.severity, x.risk_score), reverse=True):
            sev = m.vulnerability.severity
            color = _severity_color_md(sev)
            sev_label = f"[{sev.upper()}]({color})"
            kev_flag = "Y" if m.vulnerability.kev else ""
            cvss = f"{m.vulnerability.cvss_v3:.1f}" if m.vulnerability.cvss_v3 else ""
            epss = f"{m.vulnerability.epss:.4f}" if m.vulnerability.epss else ""
            lines.append(
                f"| {_esc_md(m.vulnerability.cve)} | {sev_label} "
                f"| {cvss} | {epss} | {kev_flag} "
                f"| {_esc_md(m.component.name)} "
                f"| {_esc_md(m.component.version)} "
                f"| {_esc_md(m.fixed_version or 'N/A')} |"
            )
        lines.append("")

    # ── Findings by Severity ───────────────────────────────────────────────
    lines.append("## Findings by Severity")
    lines.append("")
    by_severity = aggregator.group_by_severity()
    for sev in ("critical", "high", "medium", "low", "info"):
        flist = by_severity.get(sev, [])
        if not flist:
            continue
        lines.append(f"### {sev.title()} ({len(flist)})")
        lines.append("")
        has_enriched = any(_is_enriched(f) for f in flist)
        if has_enriched:
            lines.append("| # | Title | Target | Category | Evidence | Explanation | Impact | Remediation |")
            lines.append("|---|-------|--------|----------|----------|-------------|--------|-------------|")
        else:
            lines.append("| # | Title | Target | Category | Evidence |")
            lines.append("|---|-------|--------|----------|----------|")
        for i, f_in in enumerate(flist, 1):
            evidence = _esc_md(f_in.evidence[:80]) if f_in.evidence else ""
            if has_enriched and _is_enriched(f_in):
                exp = _esc_md(f_in.explanation[:80]) if f_in.explanation else ""
                imp = _esc_md(f_in.security_impact[:80]) if f_in.security_impact else ""
                rem = _esc_md(f_in.remediation[:80]) if f_in.remediation else ""
                lines.append(f"| {i} | {_esc_md(f_in.title)} | {_esc_md(f_in.target)} | {f_in.category} | {evidence} | {exp} | {imp} | {rem} |")
            else:
                lines.append(f"| {i} | {_esc_md(f_in.title)} | {_esc_md(f_in.target)} | {f_in.category} | {evidence} |")
        lines.append("")

    # ── Findings by Category ───────────────────────────────────────────────
    lines.append("## Findings by Category")
    lines.append("")
    by_category = aggregator.group_by_category()
    for cat in sorted(by_category.keys()):
        flist = by_category[cat]
        lines.append(f"### {cat.replace('_', ' ').title()} ({len(flist)})")
        lines.append("")
        lines.append("| # | Title | Severity | Target |")
        lines.append("|---|-------|----------|--------|")
        for i, f in enumerate(flist, 1):
            lines.append(f"| {i} | {_esc_md(f.title)} | {f.severity} | {_esc_md(f.target)} |")
        lines.append("")

    # ── Detailed Findings (with enrichment) ────────────────────────────────
    enriched_list = [f for f in findings if _is_enriched(f)]
    if enriched_list:
        lines.append("## Detailed Findings")
        lines.append("")
        for f_in in enriched_list:
            lines.append(f"### {_esc_md(f_in.title)}")
            lines.append("")
            lines.append(f"- **Severity**: {_esc_md(f_in.severity)}")
            lines.append(f"- **Target**: {_esc_md(f_in.target)}")
            lines.append(f"- **Source**: {f_in.source_stage if f_in.source_stage else 'N/A'}")
            lines.append(f"- **Confidence**: {f_in.confidence_score:.0%}" if f_in.confidence_score else "")
            if f_in.explanation:
                lines.append("")
                lines.append(f"**Explanation:** {f_in.explanation}")
            if f_in.security_impact:
                lines.append("")
                lines.append(f"**Impact:** {f_in.security_impact}")
            if f_in.evidence:
                lines.append("")
                lines.append(f"**Evidence:** `{_esc_md(f_in.evidence)}`")
            if f_in.remediation:
                lines.append("")
                lines.append(f"**Remediation:** {f_in.remediation}")
            if f_in.cis_control:
                lines.append("")
                lines.append(f"- **CIS**: {f_in.cis_control}")
            if f_in.mitre_attack:
                for ta in f_in.mitre_attack:
                    lines.append(f"- **MITRE ATT&CK**: {ta}")
            if f_in.cwe:
                lines.append(f"- **CWE**: {f_in.cwe}")
            if f_in.enriched_references:
                for ref in f_in.enriched_references:
                    lines.append(f"- **Reference**: {ref}")
            if f_in.gtfo_bins:
                for gb in f_in.gtfo_bins:
                    lines.append(f"- **GTFOBins**: [{gb.get('binary', '')}]({gb.get('url', '')})")
                    if gb.get("technique"):
                        lines.append(f"  - Technique: `{gb['technique']}`")
            if f_in.enriched_tags:
                lines.append(f"- **Tags**: {', '.join(f_in.enriched_tags)}")
            lines.append("")

    # ── Recommendations ────────────────────────────────────────────────────
    lines.append("## Recommendations")
    lines.append("")
    def _get_remediation(f: Finding | EnrichedFinding) -> str:
        if _is_enriched(f):
            return f.remediation or f.recommendation
        return f.recommendation

    recommendations = [f for f in findings if f.recommendation or (_is_enriched(f) and f.remediation)]
    if recommendations:
        for f_in in recommendations:
            lines.append(f"### {_esc_md(f_in.title)}")
            lines.append("")
            lines.append(f"- **Severity**: {f_in.severity}")
            lines.append(f"- **Target**: {_esc_md(f_in.target)}")
            rem = _get_remediation(f_in)
            if rem:
                lines.append(f"- **Recommendation**: {rem}")
            if f_in.references:
                for ref in f_in.references:
                    lines.append(f"- Reference: {ref}")
            if _is_enriched(f_in) and f_in.enriched_references:
                for ref in f_in.enriched_references:
                    lines.append(f"- Reference: {ref}")
            lines.append("")
    else:
        lines.append("No specific recommendations were generated.")
        lines.append("")

    # ── Appendix ───────────────────────────────────────────────────────────
    lines.append("## Appendix: Raw Stage Outputs")
    lines.append("")
    for sr in stage_results:
        status = sr.status.value if hasattr(sr.status, "value") else str(sr.status)
        lines.append(f"### {sr.name}")
        lines.append(f"- **Status**: {status}")
        lines.append(f"- **Command**: `{_esc_md(sr.command)}`")
        lines.append(f"- **Duration**: {sr.duration:.1f}s")
        if sr.warnings:
            lines.append("- **Warnings**:")
            for w in sr.warnings:
                lines.append(f"  - {_esc_md(w)}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _severity_color_md(sev: str) -> str:
    colors = {
        "critical": "ff4444",
        "high": "ff8800",
        "medium": "ffcc00",
        "low": "4488ff",
        "info": "888888",
    }
    return colors.get(sev.lower(), "888888")


__all__ = ["render_markdown"]
