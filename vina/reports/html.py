"""HTML report generation for VINA."""

from __future__ import annotations

import html
from typing import Any

from ..core.aggregator import AggregatorStats, FindingAggregator
from ..core.correlation import AttackPath
from ..core.exploitability import ExploitabilityAssessment, ExploitabilitySummary
from ..core.knowledge import EnrichedFinding
from ..core.vuln_intel import VulnerabilityMatch, VulnStats
from ..models.findings import Finding, Severity, severity_key
from ..models.stages import StageResult


def _esc(value: str | int | float | None) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _severity_color(sev: str) -> str:
    colors = {
        "critical": "#e11d48",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#3b82f6",
        "info": "#6b7280",
    }
    return colors.get(sev.lower(), "#6b7280")


def _collapse_section(section_id: str, title: str, content: str, open_default: bool = True) -> str:
    details_open = " open" if open_default else ""
    return f"""<details{details_open}>
  <summary>{_esc(title)}</summary>
  <div class="section-body">
    {content}
  </div>
</details>"""


def _is_enriched(f: Finding | EnrichedFinding) -> bool:
    return isinstance(f, EnrichedFinding) and f.has_enrichment()


def _enrichment_badges(f: Finding | EnrichedFinding) -> str:
    if not _is_enriched(f):
        return ""
    badges = ""
    if f.cis_control:
        short = f.cis_control.split(" - ")[0] if " - " in f.cis_control else f.cis_control[:40]
        badges += f"<span class='badge badge-cis' title='{_esc(f.cis_control)}'>{_esc(short)}</span> "
    if f.mitre_attack:
        for ta in f.mitre_attack:
            tid = ta.split(" - ")[0] if " - " in ta else ta[:20]
            badges += f"<span class='badge badge-mitre' title='{_esc(ta)}'>{_esc(tid)}</span> "
    if f.cwe:
        badge = f.cwe.split(":")[0] if ":" in f.cwe else f.cwe
        badges += f"<span class='badge badge-cwe' title='{_esc(f.cwe)}'>{_esc(badge)}</span> "
    if f.gtfo_bins:
        for gb in f.gtfo_bins:
            badges += f"<span class='badge badge-gtfo' title='{_esc(gb.get('description', ''))}'>{_esc('GTFO: ' + gb.get('binary', ''))}</span> "
    if f.confidence_score:
        pct = int(f.confidence_score * 100)
        color = "#22c55e" if pct >= 80 else "#eab308" if pct >= 50 else "#6b7280"
        badges += f"<span class='badge badge-conf' style='color:{color}'>{pct}% confidence</span> "
    return badges


def _findings_table(flist: list[Finding], show_evidence: bool = True) -> str:
    if not flist:
        return "<p class='empty'>No findings.</p>"
    rows = ""
    for f in flist:
        color = _severity_color(f.severity)
        evidence = f"<td>{_esc(f.evidence[:100])}</td>" if show_evidence and f.evidence else "<td></td>"
        badges = _enrichment_badges(f)
        rows += (
            f"<tr>"
            f"<td><span class='sev-badge' style='background:{color}'>{_esc(f.severity)}</span></td>"
            f"<td>{_esc(f.title)}</td>"
            f"<td>{_esc(f.target)}</td>"
            f"<td>{_esc(f.category)}</td>"
            f"{evidence}"
            f"<td>{badges}</td>"
            f"</tr>"
        )
    return f"""<table>
  <thead>
    <tr>
      <th>Severity</th>
      <th>Title</th>
      <th>Target</th>
      <th>Category</th>
      {("<th>Evidence</th>" if show_evidence else "")}
      <th>References</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>"""


def _attack_path_card(path: AttackPath, idx: int) -> str:
    color = _severity_color(path.severity)
    lines = ""

    lines += f"<p><strong>Score:</strong> <span class='score-badge'>{path.score}/100</span></p>"
    lines += f"<p><strong>Confidence:</strong> {path.confidence:.0%}</p>"
    lines += f"<p><strong>Type:</strong> {path.attack_type.replace('_', ' ').title()}</p>"

    if path.description:
        lines += f"<p><strong>Description:</strong> {_esc(path.description)}</p>"

    if path.attack_chain:
        chain_items = "".join(f"<li><code>{_esc(step)}</code></li>" for step in path.attack_chain)
        lines += f"<p><strong>Attack Chain:</strong></p><ul>{chain_items}</ul>"

    if path.explanation:
        lines += f"<p><strong>Explanation:</strong> {_esc(path.explanation)}</p>"

    if path.evidence:
        ev_lines = "".join(f"<li>{_esc(l)}</li>" for l in path.evidence.split("\n"))
        lines += f"<p><strong>Supporting Findings:</strong></p><ul>{ev_lines}</ul>"

    if path.remediation:
        lines += f"<p><strong>Remediation:</strong> {_esc(path.remediation)}</p>"

    meta = ""
    if path.mitre_attack:
        for ta in path.mitre_attack:
            meta += f"<li><strong>MITRE ATT&CK:</strong> {_esc(ta)}</li>"
    if path.cwe:
        meta += f"<li><strong>CWE:</strong> {_esc(path.cwe)}</li>"
    if path.cis_controls:
        for cc in path.cis_controls:
            meta += f"<li><strong>CIS:</strong> {_esc(cc)}</li>"
    if path.references:
        for ref in path.references:
            meta += f"<li><strong>Reference:</strong> <a href='{_esc(ref)}'>{_esc(ref)}</a></li>"

    meta_html = f"<ul>{meta}</ul>" if meta else ""

    return f"""<div class='attack-card' style='border-left:4px solid {color}' id='attack-{idx}'>
  <h4>{_esc(path.title)} <span class='sev-badge' style='background:{color}'>{_esc(path.severity)}</span></h4>
  {lines}
  {meta_html}
</div>"""


def _detailed_finding_card(f: Finding | EnrichedFinding, idx: int) -> str:
    color = _severity_color(f.severity)
    sections = ""

    if hasattr(f, "explanation") and f.explanation:
        sections += f"<p><strong>Explanation:</strong> {_esc(f.explanation)}</p>"
    if hasattr(f, "security_impact") and f.security_impact:
        sections += f"<p><strong>Impact:</strong> {_esc(f.security_impact)}</p>"
    if f.evidence:
        sections += f"<p><strong>Evidence:</strong> <code>{_esc(f.evidence[:200])}</code></p>"
    rem = _esc(f.remediation) if f.remediation else ""
    if hasattr(f, "remediation") and f.remediation and not f.remediation:
        rem = _esc(f.remediation)
    if rem:
        sections += f"<p><strong>Remediation:</strong> {rem}</p>"
    if hasattr(f, "recommendation") and f.recommendation and not rem:
        sections += f"<p><strong>Recommendation:</strong> {_esc(f.recommendation)}</p>"

    meta = ""
    if hasattr(f, "cis_control") and f.cis_control:
        meta += f"<li><strong>CIS:</strong> {_esc(f.cis_control)}</li>"
    if hasattr(f, "mitre_attack") and f.mitre_attack:
        for ta in f.mitre_attack:
            meta += f"<li><strong>MITRE ATT&CK:</strong> {_esc(ta)}</li>"
    if hasattr(f, "cwe") and f.cwe:
        meta += f"<li><strong>CWE:</strong> {_esc(f.cwe)}</li>"
    if hasattr(f, "enriched_references") and f.enriched_references:
        for ref in f.enriched_references:
            meta += f"<li><strong>Reference:</strong> <a href='{_esc(ref)}'>{_esc(ref)}</a></li>"
    if hasattr(f, "gtfo_bins") and f.gtfo_bins:
        for gb in f.gtfo_bins:
            url = gb.get("url", "")
            meth = gb.get("technique", "")
            meta += f"<li><strong>GTFOBins</strong> (<a href='{_esc(url)}'>{_esc(gb.get('binary', ''))}</a>): <code>{_esc(meth)}</code></li>"
    if hasattr(f, "confidence_score") and f.confidence_score:
        meta += f"<li><strong>Confidence:</strong> {f.confidence_score:.0%}</li>"

    meta_html = f"<ul>{meta}</ul>" if meta else ""

    if not sections and not meta_html:
        return ""

    return f"""<div class='detail-card' style='border-left:4px solid {color}' id='detail-{idx}'>
  <h4>{_esc(f.title)} <span class='sev-badge' style='background:{color}'>{_esc(f.severity)}</span></h4>
  <p class='detail-meta'>
    <strong>Target:</strong> {_esc(f.target)} |
    <strong>Source:</strong> {_esc(f.source_stage) if f.source_stage else 'N/A'}
  </p>
  {sections}
  {meta_html}
</div>"""


def _exploitability_assessment_card(a: ExploitabilityAssessment, idx: int) -> str:
    color_map = {"critical": "#e11d48", "high": "#f97316", "medium": "#eab308", "low": "#3b82f6"}
    score_color = color_map.get(_exploitability_tier(a.overall_score), "#6b7280")
    complexity_color = color_map.get(a.complexity.split("_")[0] if "_" in a.complexity else a.complexity, "#6b7280")

    lines = ""
    lines += f"<p><strong>Score:</strong> <span class='score-badge' style='color:{score_color}'>{a.overall_score}/100</span></p>"
    lines += f"<p><strong>Confidence:</strong> {a.confidence:.0%}</p>"
    lines += f"<p><strong>Complexity:</strong> <span class='sev-badge' style='background:{complexity_color}'>{a.complexity.replace('_', ' ').title()}</span></p>"
    lines += f"<p><strong>Attack Vector:</strong> {a.attack_vector.replace('_', ' ').title()}</p>"
    lines += f"<p><strong>Required Access:</strong> {a.required_access.replace('_', ' ').title()}</p>"
    lines += f"<p><strong>Required Privileges:</strong> {a.required_privileges.title()}</p>"
    lines += f"<p><strong>Estimated Time:</strong> {a.estimated_time_to_exploit}</p>"
    if a.attack_surface:
        lines += f"<p><strong>Attack Surface:</strong> {a.attack_surface.replace('_', ' ').title()}</p>"
    if a.exploit_maturity:
        lines += f"<p><strong>Exploit Maturity:</strong> {a.exploit_maturity.replace('_', ' ').title()}</p>"

    if a.reason:
        lines += f"<p><strong>Reason:</strong> {_esc(a.reason)}</p>"

    if a.exploit_paths:
        path_items = "".join(
            f"<li><code>{_esc(p.step)}</code>{f' <em>({_esc(p.severity)})</em>' if p.severity else ''}</li>"
            for p in a.exploit_paths
        )
        lines += f"<p><strong>Exploit Path:</strong></p><ul>{path_items}</ul>"

    meta = ""
    if a.score_breakdown:
        sb = a.score_breakdown
        meta += "<li><strong>Score Breakdown:</strong><ul>"
        meta += f"<li>Attack Surface: {sb.attack_surface_score}</li>"
        meta += f"<li>Privilege Requirement: {sb.privilege_requirement_score}</li>"
        meta += f"<li>Network Exposure: {sb.network_exposure_score}</li>"
        meta += f"<li>Exploit Maturity: {sb.exploit_maturity_score}</li>"
        meta += f"<li>Public Exploit: {sb.public_exploit_score}</li>"
        meta += f"<li>Mitigation Bypass: {sb.mitigation_bypass_score}</li>"
        meta += f"<li>Environmental: {sb.environmental_score}</li>"
        meta += f"<li>Confidence Multiplier: {sb.confidence_multiplier}</li>"
        meta += "</ul></li>"
    if a.mitigations_present:
        meta += f"<li><strong>Active Mitigations:</strong> {', '.join(_esc(m) for m in a.mitigations_present)}</li>"
    if a.mitigations_absent:
        meta += f"<li><strong>Missing Mitigations:</strong> {', '.join(_esc(m) for m in a.mitigations_absent)}</li>"
    if a.blocking_controls:
        meta += f"<li><strong>Blocking Controls:</strong> {', '.join(_esc(b) for b in a.blocking_controls)}</li>"
    if a.missing_prerequisites:
        meta += f"<li><strong>Missing Prerequisites:</strong> {', '.join(_esc(p) for p in a.missing_prerequisites)}</li>"
    if a.recommended_next_steps:
        steps = "".join(f"<li>{_esc(s)}</li>" for s in a.recommended_next_steps)
        meta += f"<li><strong>Recommended Next Steps:</strong><ul>{steps}</ul></li>"
    meta_html = f"<ul>{meta}</ul>" if meta else ""

    color = score_color
    return f"""<div class='exploit-card' style='border-left:4px solid {color}' id='exploit-{idx}'>
  <h4>{_esc(a.title)}</h4>
  {lines}
  {meta_html}
</div>"""


def _vuln_feed_status(vs: VulnStats | None) -> str:
    if vs is None:
        return ""
    status_label = "Offline" if vs.is_offline else "Online"
    last_up = vs.last_updated[:19] if vs.last_updated else "Never"
    age = f"{vs.feed_age_hours:.1f}h" if vs.feed_age_hours >= 0 else "N/A"
    return (
        f'<p style="color:#94a3b8;font-size:0.82rem;margin:4px 0 12px;">'
        f'DB v{_esc(str(vs.db_version))} | {status_label} | '
        f'Last updated: {_esc(last_up)} | Feed age: {_esc(age)}'
        f'</p>'
    )


def _exploitability_tier(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _exploitability_section(
    assessments: list[ExploitabilityAssessment],
    summary: ExploitabilitySummary | None,
) -> str:
    if not assessments:
        return _collapse_section(
            'exploitability', 'Exploitability Analysis (0)',
            "<p class='empty'>No exploitability assessments were generated.</p>",
            open_default=False,
        )

    es = summary
    stat_cards = ""
    if es:
        stat_cards = (
            f"<div class='stat-card' style='border-left:4px solid #e11d48'><span class='stat-label'>Assessments</span><span class='stat-value'>{es.total_assessments}</span></div>"
            f"<div class='stat-card' style='border-left:4px solid #e11d48'><span class='stat-label'>Critical</span><span class='stat-value'>{es.critical_exploitable}</span></div>"
            f"<div class='stat-card' style='border-left:4px solid #f97316'><span class='stat-label'>High</span><span class='stat-value'>{es.high_exploitable}</span></div>"
            f"<div class='stat-card' style='border-left:4px solid #eab308'><span class='stat-label'>Medium</span><span class='stat-value'>{es.medium_exploitable}</span></div>"
            f"<div class='stat-card' style='border-left:4px solid #a855f7'><span class='stat-label'>Avg Score</span><span class='stat-value'>{es.average_score}</span></div>"
            f"<div class='stat-card' style='border-left:4px solid #22c55e'><span class='stat-label'>Highest</span><span class='stat-value'>{es.highest_score}</span></div>"
        )

    cards = "".join(_exploitability_assessment_card(a, i) for i, a in enumerate(assessments))
    content = f"<div class='stats-grid'>{stat_cards}</div>{cards}"
    return _collapse_section('exploitability',
        f'Exploitability Analysis ({len(assessments)})',
        content, open_default=bool(assessments))


def render_html(
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
    sev_groups = aggregator.group_by_severity()
    cat_groups = aggregator.group_by_category()

    # -- Severity cards --
    severity_order = ["critical", "high", "medium", "low", "info"]
    sev_cards = ""
    for sev in severity_order:
        count = stats.by_severity.get(sev, 0)
        color = _severity_color(sev)
        sev_cards += (
            f"<div class='stat-card' style='border-left:4px solid {color}'>"
            f"<span class='stat-label'>{sev.title()}</span>"
            f"<span class='stat-value'>{count}</span>"
            f"</div>"
        )

    # -- Attack path stat cards --
    if stats.attack_paths_total > 0:
        attack_cards = (
            f"<div class='stat-card' style='border-left:4px solid #a855f7'><span class='stat-label'>Attack Paths</span><span class='stat-value'>{stats.attack_paths_total}</span></div>"
            f"<div class='stat-card' style='border-left:4px solid #e11d48'><span class='stat-label'>Critical</span><span class='stat-value'>{stats.critical_chains}</span></div>"
            f"<div class='stat-card' style='border-left:4px solid #f97316'><span class='stat-label'>High</span><span class='stat-value'>{stats.high_chains}</span></div>"
            f"<div class='stat-card' style='border-left:4px solid #22c55e'><span class='stat-label'>Risk Score</span><span class='stat-value'>{stats.overall_risk_score}</span></div>"
            f"<div class='stat-card' style='border-left:4px solid #eab308'><span class='stat-label'>Avg Confidence</span><span class='stat-value'>{stats.average_attack_confidence:.0%}</span></div>"
        )
    else:
        attack_cards = "<p class='empty'>No attack paths identified.</p>"

    # -- Vulnerability stat cards --
    if vmatches:
        vs = vuln_stats
        vuln_cards = ""
        if vs:
            vuln_cards = (
                f"<div class='stat-card' style='border-left:4px solid #e11d48'><span class='stat-label'>CVEs</span><span class='stat-value'>{vs.total_vulnerabilities}</span></div>"
                f"<div class='stat-card' style='border-left:4px solid #e11d48'><span class='stat-label'>Critical</span><span class='stat-value'>{vs.critical_cves}</span></div>"
                f"<div class='stat-card' style='border-left:4px solid #f97316'><span class='stat-label'>KEV</span><span class='stat-value'>{vs.kev_count}</span></div>"
                f"<div class='stat-card' style='border-left:4px solid #a855f7'><span class='stat-label'>Exploits</span><span class='stat-value'>{vs.public_exploits}</span></div>"
                f"<div class='stat-card' style='border-left:4px solid #22c55e'><span class='stat-label'>Vuln Score</span><span class='stat-value'>{vs.overall_score}</span></div>"
            )
    else:
        vuln_cards = ""

    # -- Summary stats --
    enriched_count = sum(1 for f in findings if _is_enriched(f))
    summary_cards = (
        f"<div class='stat-card'><span class='stat-label'>Total</span><span class='stat-value'>{stats.total}</span></div>"
        f"<div class='stat-card'><span class='stat-label'>Hosts</span><span class='stat-value'>{stats.unique_hosts}</span></div>"
        f"<div class='stat-card'><span class='stat-label'>URLs</span><span class='stat-value'>{stats.unique_urls}</span></div>"
        f"<div class='stat-card'><span class='stat-label'>Stages</span><span class='stat-value'>{stats.stages_with_findings}</span></div>"
        f"<div class='stat-card'><span class='stat-label'>Enriched</span><span class='stat-value'>{enriched_count}</span></div>"
    )

    # -- Stage table --
    stage_rows = ""
    for sr in stage_results:
        status = sr.status.value if hasattr(sr.status, "value") else str(sr.status)
        color = _severity_color(status)
        stage_rows += (
            f"<tr>"
            f"<td>{_esc(sr.name)}</td>"
            f"<td><span class='sev-badge' style='background:{color}'>{status}</span></td>"
            f"<td>{sr.record_count}</td>"
            f"<td>{sr.duration:.1f}s</td>"
            f"</tr>"
        )

    stage_table = f"""<table>
  <thead>
    <tr><th>Stage</th><th>Status</th><th>Records</th><th>Duration</th></tr>
  </thead>
  <tbody>{stage_rows}</tbody>
</table>"""

    # -- Findings by severity sections --
    sev_sections = ""
    for sev in severity_order:
        flist = sev_groups.get(sev, [])
        if not flist:
            continue
        color = _severity_color(sev)
        content = f"<h4 style='color:{color}'>{sev.title()} — {len(flist)} findings</h4>" + _findings_table(flist)
        sev_sections += _collapse_section(f"sev-{sev}", f"{sev.title()} ({len(flist)})", content)

    if not sev_sections:
        sev_sections = "<p class='empty'>No findings recorded.</p>"

    # -- Attack path section --
    attack_path_content = ""
    if paths:
        path_cards = "".join(_attack_path_card(p, i) for i, p in enumerate(paths))
        attack_path_content = f"<div class='stats-grid'>{attack_cards}</div>{path_cards}"
    else:
        attack_path_content = "<p class='empty'>No correlatable attack paths were identified.</p>"

    # -- Findings by category sections --
    cat_sections = ""
    for cat in sorted(cat_groups.keys()):
        flist = cat_groups[cat]
        content = _findings_table(flist, show_evidence=False)
        cat_sections += _collapse_section(f"cat-{cat}", f"{cat.replace('_', ' ').title()} ({len(flist)})", content, open_default=False)

    if not cat_sections:
        cat_sections = "<p class='empty'>No categories.</p>"

    # -- Detailed findings (with enrichment) --
    detail_cards = ""
    for idx, f in enumerate(findings):
        if _is_enriched(f):
            card = _detailed_finding_card(f, idx)
            if card:
                detail_cards += card
    if not detail_cards:
        detail_cards = "<p class='empty'>No enriched findings to display.</p>"

    # -- Recommendations --
    rec_items = ""
    for f in findings:
        rem = f.remediation if _is_enriched(f) and f.remediation else f.recommendation
        if not rem:
            continue
        color = _severity_color(f.severity)
        refs = "".join(f"<li>{_esc(r)}</li>" for r in f.references)
        if _is_enriched(f) and f.enriched_references:
            refs += "".join(f"<li>{_esc(r)}</li>" for r in f.enriched_references)
        rec_items += (
            f"<div class='rec-item' style='border-left:4px solid {color}'>"
            f"<h4>{_esc(f.title)}</h4>"
            f"<p><strong>Severity:</strong> <span class='sev-badge' style='background:{color}'>{_esc(f.severity)}</span></p>"
            f"<p><strong>Target:</strong> {_esc(f.target)}</p>"
            f"<p><strong>Recommendation:</strong> {_esc(rem)}</p>"
            f"{('<ul>' + refs + '</ul>') if refs else ''}"
            f"</div>"
        )
    if not rec_items:
        rec_items = "<p class='empty'>No specific recommendations were generated.</p>"

    # -- Appendix: Raw stage outputs --
    appendix_items = ""
    for sr in stage_results:
        status = sr.status.value if hasattr(sr.status, "value") else str(sr.status)
        warnings = ""
        if sr.warnings:
            warnings = "<ul>" + "".join(f"<li>{_esc(w)}</li>" for w in sr.warnings) + "</ul>"
        appendix_items += (
            f"<div class='stage-box'>"
            f"<h4>{_esc(sr.name)}</h4>"
            f"<p><strong>Status:</strong> {status}</p>"
            f"<p><strong>Command:</strong> <code>{_esc(sr.command)}</code></p>"
            f"<p><strong>Duration:</strong> {sr.duration:.1f}s</p>"
            f"<p><strong>Records:</strong> {sr.record_count}</p>"
            f"{warnings}"
            f"</div>"
        )

    # -- Assemble page --
    return f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>VINA Report — {_esc(target)}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
            background: #0b1020; color: #e2e8f0; line-height: 1.6; }}
    main {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px 80px; }}

    h1 {{ font-size: 1.75rem; margin-bottom: 4px; }}
    h2 {{ font-size: 1.35rem; margin: 28px 0 12px; }}
    h3 {{ font-size: 1.15rem; margin: 20px 0 8px; }}
    h4 {{ font-size: 1rem; margin: 12px 0 6px; }}
    p  {{ margin-bottom: 8px; }}
    a  {{ color: #60a5fa; }}
    code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}

    .subtitle {{ color: #94a3b8; font-size: 0.88rem; margin-bottom: 24px; }}

    /* -- Filter / search -- */
    .filter-bar {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 20px 0; }}
    .filter-bar input, .filter-bar select {{
      background: #1e293b; border: 1px solid #334155; color: #e2e8f0;
      padding: 8px 12px; border-radius: 8px; font-size: 0.9rem;
    }}
    .filter-bar input {{ flex: 1; min-width: 200px; }}
    .filter-bar select {{ cursor: pointer; }}

    /* -- Layout -- */
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                   gap: 12px; margin-bottom: 24px; }}
    .stat-card {{ background: #1e293b; border-radius: 10px; padding: 14px 16px; text-align: center; }}
    .stat-label {{ display: block; font-size: 0.78rem; color: #94a3b8; text-transform: uppercase;
                   letter-spacing: 0.5px; }}
    .stat-value {{ display: block; font-size: 1.55rem; font-weight: 700; margin-top: 2px; }}

    .sev-badge {{ display: inline-block; padding: 2px 10px; border-radius: 999px;
                  font-size: 0.72rem; font-weight: 600; text-transform: uppercase;
                  color: #fff; letter-spacing: 0.3px; }}

    .score-badge {{ display: inline-block; padding: 2px 10px; border-radius: 999px;
                   background: #1e293b; border: 1px solid #a855f7;
                   font-size: 0.85rem; font-weight: 700; color: #c4b5fd; }}

    /* -- Badges -- */
    .badge {{ display: inline-block; padding: 1px 6px; border-radius: 4px;
              font-size: 0.68rem; margin: 1px; white-space: nowrap; }}
    .badge-cis {{ background: #1e3a5f; color: #93c5fd; border: 1px solid #3b82f6; }}
    .badge-mitre {{ background: #3b1f3b; color: #c4b5fd; border: 1px solid #8b5cf6; }}
    .badge-cwe {{ background: #1f3b2f; color: #86efac; border: 1px solid #22c55e; }}
    .badge-gtfo {{ background: #3b2f1f; color: #fde68a; border: 1px solid #f59e0b; }}
    .badge-conf {{ background: #1e293b; border: 1px solid #334155; }}

    /* -- Tables -- */
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
    th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #1e293b; }}
    th {{ background: #1e293b; font-size: 0.8rem; text-transform: uppercase;
          color: #94a3b8; letter-spacing: 0.3px; }}
    td {{ font-size: 0.9rem; }}

    /* -- Collapsible -- */
    details {{ background: #1e293b; border-radius: 10px; margin: 10px 0; overflow: hidden; }}
    summary {{ padding: 12px 16px; cursor: pointer; font-weight: 600;
               background: #1e293b; border-bottom: 1px solid transparent; }}
    details[open] summary {{ border-bottom-color: #334155; }}
    .section-body {{ padding: 12px 16px 16px; }}

    /* -- Detail cards -- */
    .detail-card, .attack-card {{ background: #1e293b; border-radius: 10px; padding: 16px; margin: 10px 0; }}
    .detail-card h4, .attack-card h4 {{ margin-top: 0; }}
    .detail-card ul, .attack-card ul {{ margin: 8px 0 0 20px; font-size: 0.88rem; }}
    .detail-card li, .attack-card li {{ margin: 2px 0; }}
    .detail-meta {{ color: #94a3b8; font-size: 0.85rem; }}

    /* -- Recs -- */
    .rec-item {{ background: #1e293b; border-radius: 10px; padding: 16px; margin: 10px 0; }}
    .rec-item h4 {{ margin-top: 0; }}

    /* -- Stage box -- */
    .stage-box {{ background: #1e293b; border-radius: 8px; padding: 12px 16px; margin: 8px 0; }}

    /* -- Empty -- */
    .empty {{ color: #64748b; font-style: italic; }}

    /* -- Responsive -- */
    @media (max-width: 640px) {{
      main {{ padding: 20px 12px 60px; }}
      .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
      table {{ font-size: 0.82rem; }}
      th, td {{ padding: 6px 8px; }}
    }}
  </style>
</head>
<body>
  <main>
    <h1>VINA Security Report</h1>
    <p class='subtitle'>Target: <code>{_esc(target)}</code></p>

    <div class='filter-bar'>
      <input type='text' id='searchBox' placeholder='Search findings...' oninput='filterFindings()'>
      <select id='sevFilter' onchange='filterFindings()'>
        <option value=''>All severities</option>
        <option value='critical'>Critical</option>
        <option value='high'>High</option>
        <option value='medium'>Medium</option>
        <option value='low'>Low</option>
        <option value='info'>Info</option>
      </select>
      <select id='catFilter' onchange='filterFindings()'>
        <option value=''>All categories</option>
        {''.join(f"<option value='{c}'>{c.replace('_', ' ').title()}</option>" for c in sorted(cat_groups.keys()))}
      </select>
    </div>

    {_collapse_section('summary', 'Executive Summary', f'''
    <div class="stats-grid">{sev_cards}</div>
    <div class="stats-grid">{summary_cards}</div>
    ''')}

    {_collapse_section('vulnerabilities', f'Known Vulnerabilities ({len(vmatches)})', f'''
    <div class="stats-grid">{vuln_cards}</div>
    {_vuln_feed_status(vuln_stats)}
    <table>
      <thead>
        <tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Component</th><th>Installed</th><th>Fixed</th></tr>
      </thead>
      <tbody>
        {''.join(
          f"<tr>"
          f"<td>{_esc(m.vulnerability.cve)}</td>"
          f"<td><span class='sev-badge' style='background:{_severity_color(m.vulnerability.severity)}'>{_esc(m.vulnerability.severity)}</span></td>"
          f"<td>{f'{m.vulnerability.cvss_v3:.1f}' if m.vulnerability.cvss_v3 else ''}</td>"
          f"<td>{f'{m.vulnerability.epss:.4f}' if m.vulnerability.epss else ''}</td>"
          f"<td>{'Y' if m.vulnerability.kev else ''}</td>"
          f"<td>{_esc(m.component.name)}</td>"
          f"<td>{_esc(m.component.version)}</td>"
          f"<td>{_esc(m.fixed_version or 'N/A')}</td>"
          f"</tr>"
          for m in sorted(vmatches, key=lambda x: (x.vulnerability.severity, x.risk_score), reverse=True)
        )}
      </tbody>
    </table>
    ''', open_default=bool(vmatches))}

    {_collapse_section('attack-paths', f'Attack Paths ({stats.attack_paths_total})', attack_path_content, open_default=bool(paths))}

    {_exploitability_section(exp_assessments, exp_summary)}

    {_collapse_section('stages', 'Stage Execution', stage_table)}

    {_collapse_section('findings-sev', 'Findings by Severity', sev_sections)}

    {_collapse_section('findings-cat', 'Findings by Category', cat_sections, open_default=False)}

    {_collapse_section('detail-enrichment', 'Detailed Findings (Enriched)', detail_cards, open_default=False)}

    {_collapse_section('recommendations', 'Recommendations', rec_items, open_default=False)}

    {_collapse_section('appendix', 'Appendix: Raw Stage Outputs', appendix_items, open_default=False)}

  </main>
  <script>
    function filterFindings() {{
      const q = (document.getElementById('searchBox').value || '').toLowerCase();
      const sev = (document.getElementById('sevFilter').value || '').toLowerCase();
      const cat = (document.getElementById('catFilter').value || '').toLowerCase();

      document.querySelectorAll('details').forEach(det => {{
        const rows = det.querySelectorAll('tbody tr');
        if (!rows.length) return;
        let visibleCount = 0;
        rows.forEach(row => {{
          const text = row.textContent.toLowerCase();
          const rowSev = (row.querySelector('.sev-badge')?.textContent || '').toLowerCase().trim();
          const rowCat = (row.cells[3]?.textContent || '').toLowerCase().trim();
          const matchText = !q || text.includes(q);
          const matchSev = !sev || rowSev === sev;
          const matchCat = !cat || rowCat === cat;
          const show = matchText && matchSev && matchCat;
          row.style.display = show ? '' : 'none';
          if (show) visibleCount++;
        }});
        det.style.display = visibleCount === 0 && (q || sev || cat) ? 'none' : '';
      }});
    }}
  </script>
</body>
</html>"""


__all__ = ["render_html"]
