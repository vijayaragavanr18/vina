"""Tests for report generation."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from vina.core.aggregator import FindingAggregator
from vina.models.findings import Finding, make_finding
from vina.models.stages import StageResult, StageState
from vina.reports.html import render_html
from vina.reports.markdown import render_markdown
from vina.reports.report import generate_json_report, generate_reports


def _finding(
    title: str = "Test Finding",
    severity: str = "medium",
    category: str = "vulnerability",
    source_stage: str = "nuclei",
    target: str = "example.com",
    host: str = "example.com",
    url: str = "https://example.com/vuln",
    evidence: str = "evidence text",
    recommendation: str = "",
) -> Finding:
    return make_finding(
        title=title,
        severity=severity,
        category=category,
        source_stage=source_stage,
        target=target,
        host=host,
        url=url,
        evidence=evidence,
        recommendation=recommendation,
    )


def _stage(
    name: str = "subfinder",
    status: StageState = StageState.SUCCESS,
    record_count: int = 5,
    duration: float = 1.0,
) -> StageResult:
    return StageResult(
        name=name,
        status=status,
        command=f"tool-{name}",
        exit_code=0,
        duration=duration,
        record_count=record_count,
    )


class MarkdownReportTests(unittest.TestCase):
    def test_empty_report(self) -> None:
        agg = FindingAggregator()
        md = render_markdown(
            target="example.com",
            findings=[],
            stage_results=[],
            stats=agg.statistics(),
            aggregator=agg,
        )
        self.assertIn("VINA Security Report", md)
        self.assertIn("example.com", md)
        self.assertIn("No findings", md)

    def test_report_with_findings(self) -> None:
        agg = FindingAggregator()
        findings = [
            _finding(title="Critical Vuln", severity="critical", recommendation="Fix it"),
            _finding(title="Info Finding", severity="info"),
        ]
        agg.add_findings(findings)
        stages = [_stage("subfinder", record_count=10)]
        md = render_markdown(
            target="example.com",
            findings=findings,
            stage_results=stages,
            stats=agg.statistics(),
            aggregator=agg,
        )
        self.assertIn("Critical Vuln", md)
        self.assertIn("Info Finding", md)
        self.assertIn("subfinder", md)
        self.assertIn("Recommendations", md)
        self.assertIn("Fix it", md)

    def test_severity_sections(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Critical", severity="critical"))
        agg.add_finding(_finding(title="Info", severity="info"))
        md = render_markdown(
            target="t.com",
            findings=agg.findings,
            stage_results=[_stage()],
            stats=agg.statistics(),
            aggregator=agg,
        )
        self.assertIn("Critical (1)", md)
        self.assertIn("Info (1)", md)

    def test_no_recommendations_section(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Test", severity="info"))
        md = render_markdown(
            target="t.com",
            findings=agg.findings,
            stage_results=[_stage()],
            stats=agg.statistics(),
            aggregator=agg,
        )
        self.assertIn("No specific recommendations", md)


class HtmlReportTests(unittest.TestCase):
    def test_empty_report(self) -> None:
        agg = FindingAggregator()
        html = render_html(
            target="example.com",
            findings=[],
            stage_results=[],
            stats=agg.statistics(),
            aggregator=agg,
        )
        self.assertIn("VINA Security Report", html)
        self.assertIn("example.com", html)
        self.assertIn("No findings", html)

    def test_has_collapsible_sections(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Test", severity="high"))
        html = render_html(
            target="t.com",
            findings=agg.findings,
            stage_results=[_stage("nuclei")],
            stats=agg.statistics(),
            aggregator=agg,
        )
        self.assertIn("<details", html)
        self.assertIn("<summary>", html)
        self.assertIn("Executive Summary", html)
        self.assertIn("Findings by Severity", html)
        self.assertIn("Findings by Category", html)

    def test_severity_color_coding(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Critical", severity="critical"))
        agg.add_finding(_finding(title="Info", severity="info"))
        html = render_html(
            target="t.com",
            findings=agg.findings,
            stage_results=[_stage()],
            stats=agg.statistics(),
            aggregator=agg,
        )
        # Should include severity badge colors
        self.assertIn("#e11d48", html)  # critical red
        self.assertIn("#6b7280", html)  # info gray

    def test_search_filter_box(self) -> None:
        agg = FindingAggregator()
        html = render_html(
            target="t.com",
            findings=[],
            stage_results=[],
            stats=agg.statistics(),
            aggregator=agg,
        )
        self.assertIn("searchBox", html)
        self.assertIn("sevFilter", html)
        self.assertIn("catFilter", html)

    def test_responsive_meta(self) -> None:
        agg = FindingAggregator()
        html = render_html(
            target="t.com",
            findings=[],
            stage_results=[],
            stats=agg.statistics(),
            aggregator=agg,
        )
        self.assertIn("viewport", html)
        self.assertIn("@media", html)

    def test_stage_table(self) -> None:
        agg = FindingAggregator()
        stages = [
            _stage("subfinder", StageState.SUCCESS, 10, 1.5),
            _stage("httpx", StageState.FAILED, 0, 0.5),
        ]
        html = render_html(
            target="t.com",
            findings=[],
            stage_results=stages,
            stats=agg.statistics(),
            aggregator=agg,
        )
        self.assertIn("subfinder", html)
        self.assertIn("httpx", html)
        self.assertIn("success", html)
        self.assertIn("failed", html)


class JsonReportTests(unittest.TestCase):
    def test_json_structure(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Test Finding", severity="high"))
        stages = [_stage("nuclei")]
        data = generate_json_report(
            target="example.com",
            findings=agg.findings,
            stage_results=stages,
            stats=agg.statistics(),
            aggregator=agg,
        )
        self.assertEqual(data["report_type"], "vina-json")
        self.assertEqual(data["target"], "example.com")
        self.assertIn("findings", data)
        self.assertIn("stages", data)
        self.assertIn("summary", data)
        self.assertIn("findings_by_severity", data)

    def test_json_finding_fields(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Critical Vuln", severity="critical", category="vulnerability"))
        data = generate_json_report(
            target="t.com",
            findings=agg.findings,
            stage_results=[_stage()],
            stats=agg.statistics(),
            aggregator=agg,
        )
        f = data["findings"][0]
        self.assertEqual(f["title"], "Critical Vuln")
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["category"], "vulnerability")


class GenerateReportsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(__file__).resolve().parent / "_test_reports"
        self.tmpdir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        import shutil
        if self.tmpdir.exists():
            shutil.rmtree(self.tmpdir)

    def test_generate_all_formats(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Test"))
        stages = [_stage()]
        generated = generate_reports(
            target="example.com",
            findings=agg.findings,
            stage_results=stages,
            stats=agg.statistics(),
            aggregator=agg,
            output_dir=self.tmpdir,
        )
        self.assertIn("json", generated)
        self.assertIn("markdown", generated)
        self.assertIn("html", generated)
        for path in generated.values():
            self.assertTrue(path.exists())

    def test_generate_single_format(self) -> None:
        agg = FindingAggregator()
        generated = generate_reports(
            target="example.com",
            findings=[],
            stage_results=[],
            stats=agg.statistics(),
            aggregator=agg,
            output_dir=self.tmpdir,
            formats={"json"},
        )
        self.assertIn("json", generated)
        self.assertNotIn("markdown", generated)
        self.assertNotIn("html", generated)

    def test_json_file_content(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="JSON Test", severity="low"))
        generated = generate_reports(
            target="t.com",
            findings=agg.findings,
            stage_results=[_stage()],
            stats=agg.statistics(),
            aggregator=agg,
            output_dir=self.tmpdir,
            formats={"json"},
        )
        data = json.loads(generated["json"].read_text())
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["title"], "JSON Test")

    def test_markdown_file_content(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="MD Test"))
        generated = generate_reports(
            target="t.com",
            findings=agg.findings,
            stage_results=[_stage()],
            stats=agg.statistics(),
            aggregator=agg,
            output_dir=self.tmpdir,
            formats={"markdown"},
        )
        content = generated["markdown"].read_text()
        self.assertIn("MD Test", content)
        self.assertIn("t.com", content)

    def test_html_file_content(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="HTML Test"))
        generated = generate_reports(
            target="t.com",
            findings=agg.findings,
            stage_results=[_stage()],
            stats=agg.statistics(),
            aggregator=agg,
            output_dir=self.tmpdir,
            formats={"html"},
        )
        content = generated["html"].read_text()
        self.assertIn("HTML Test", content)
        self.assertIn("<html", content)


if __name__ == "__main__":
    unittest.main()
