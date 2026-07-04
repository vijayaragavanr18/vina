"""HTML report generation."""

from __future__ import annotations

import html

from ..models.common import AnalysisItem, CrawlEntry, Finding, HistoricalUrlEntry, ParameterCandidate, PortEntry, TechnologyEntry


def render_html(
    target: str,
    findings: list[Finding],
    analysis: list[AnalysisItem],
    ports: list[PortEntry],
    technologies: list[TechnologyEntry],
    crawl_entries: list[CrawlEntry],
    history_entries: list[HistoricalUrlEntry],
    parameter_candidates: list[ParameterCandidate],
) -> str:
    def esc(value: str) -> str:
        return html.escape(value)

    cards = "".join(
        [
            f"<div class='card'><span>{esc(label)}</span><strong>{value}</strong></div>"
            for label, value in [
                ("Findings", len(findings)),
                ("Analysis", len(analysis)),
                ("Ports", len(ports)),
                ("Tech", len(technologies)),
                ("Crawl URLs", len(crawl_entries)),
                ("History URLs", len(history_entries)),
                ("Parameters", len(parameter_candidates)),
            ]
        ]
    )
    analysis_items = "".join(
        [
            f"<article><h3>{esc(item.finding_title)}</h3><p><strong>Score:</strong> {item.score}</p><p>{esc(item.rationale)}</p></article>"
            for item in analysis
        ]
    ) or "<p>No ranked analysis was produced.</p>"
    return f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>VINA Report - {esc(target)}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 0; background: #0b1020; color: #e8ecf3; }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 64px; }}
    h1, h2, h3 {{ line-height: 1.15; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; }}
    .card, article {{ background: #121a33; border: 1px solid #243054; border-radius: 14px; padding: 16px; }}
    .card span {{ display: block; font-size: 0.82rem; color: #92a0c5; }}
    .card strong {{ font-size: 1.5rem; }}
    section {{ margin-top: 28px; }}
    code {{ background: #1a2445; padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
  <main>
    <h1>VINA Report</h1>
    <p>Target: <code>{esc(target)}</code></p>
    <section>
      <h2>Snapshot</h2>
      <div class='grid'>{cards}</div>
    </section>
    <section>
      <h2>Analysis</h2>
      {analysis_items}
    </section>
  </main>
</body>
</html>
"""
