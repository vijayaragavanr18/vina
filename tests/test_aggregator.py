"""Tests for the FindingAggregator."""

from __future__ import annotations

import unittest

from vina.core.aggregator import AggregatorStats, FindingAggregator
from vina.models.findings import Finding, make_finding
from vina.pipeline.aggregator import Aggregator


def _finding(
    title: str = "Test Finding",
    severity: str = "medium",
    category: str = "vulnerability",
    source_stage: str = "nuclei",
    target: str = "example.com",
    host: str = "",
    url: str = "",
) -> Finding:
    return make_finding(
        title=title,
        severity=severity,
        category=category,
        source_stage=source_stage,
        target=target,
        host=host,
        url=url,
    )


class FindingAggregatorTests(unittest.TestCase):
    def test_empty_aggregator(self) -> None:
        agg = FindingAggregator()
        self.assertEqual(agg.findings, [])
        self.assertEqual(agg.statistics().total, 0)

    def test_add_single_finding(self) -> None:
        agg = FindingAggregator()
        f = _finding()
        agg.add_finding(f)
        self.assertEqual(len(agg.findings), 1)

    def test_add_findings_list(self) -> None:
        agg = FindingAggregator()
        agg.add_findings([_finding(title="A"), _finding(title="B")])
        self.assertEqual(len(agg.findings), 2)

    def test_deduplication(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Same"))
        agg.add_finding(_finding(title="Same"))
        self.assertEqual(len(agg.findings), 1)

    def test_deduplication_by_title_target_source(self) -> None:
        agg = FindingAggregator()
        # Same title, target, and source_stage → deduplicated
        agg.add_finding(_finding(title="X", source_stage="a", target="t.com"))
        agg.add_finding(_finding(title="X", source_stage="a", target="t.com"))
        self.assertEqual(len(agg.findings), 1)

    def test_no_deduplication_different_title(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="A"))
        agg.add_finding(_finding(title="B"))
        self.assertEqual(len(agg.findings), 2)

    def test_no_deduplication_different_source(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="X", source_stage="subfinder"))
        agg.add_finding(_finding(title="X", source_stage="httpx"))
        self.assertEqual(len(agg.findings), 2)

    def test_no_deduplication_different_target(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="X", target="a.com"))
        agg.add_finding(_finding(title="X", target="b.com"))
        self.assertEqual(len(agg.findings), 2)

    def test_setter_replaces_findings(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Original"))
        agg.findings = [_finding(title="Replacement")]
        self.assertEqual(len(agg.findings), 1)
        self.assertEqual(agg.findings[0].title, "Replacement")

    def test_setter_replaces_and_deduplicates(self) -> None:
        agg = FindingAggregator()
        agg.findings = [_finding(title="A"), _finding(title="A")]
        self.assertEqual(len(agg.findings), 1)


class GroupBySeverityTests(unittest.TestCase):
    def test_group_by_severity(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Critical Vuln", severity="critical"))
        agg.add_finding(_finding(title="High Vuln", severity="high"))
        agg.add_finding(_finding(title="Medium Vuln", severity="medium"))
        agg.add_finding(_finding(title="Low Vuln", severity="low"))
        agg.add_finding(_finding(title="Info Note", severity="info"))
        groups = agg.group_by_severity()
        self.assertEqual(len(groups["critical"]), 1)
        self.assertEqual(len(groups["high"]), 1)
        self.assertEqual(len(groups["medium"]), 1)
        self.assertEqual(len(groups["low"]), 1)
        self.assertEqual(len(groups["info"]), 1)

    def test_group_by_severity_empty(self) -> None:
        agg = FindingAggregator()
        self.assertEqual(agg.group_by_severity(), {})


class GroupByCategoryTests(unittest.TestCase):
    def test_group_by_category(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Vuln X", category="vulnerability"))
        agg.add_finding(_finding(title="Port Y", category="open_port"))
        agg.add_finding(_finding(title="Sub Z", category="subdomain"))
        groups = agg.group_by_category()
        self.assertEqual(len(groups["vulnerability"]), 1)
        self.assertEqual(len(groups["open_port"]), 1)
        self.assertEqual(len(groups["subdomain"]), 1)


class SortBySeverityTests(unittest.TestCase):
    def test_sorted_descending(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Info", severity="info"))
        agg.add_finding(_finding(title="Critical", severity="critical"))
        agg.add_finding(_finding(title="Medium", severity="medium"))
        sorted_findings = agg.sorted_by_severity(reverse=True)
        self.assertEqual(sorted_findings[0].title, "Critical")
        self.assertEqual(sorted_findings[1].title, "Medium")
        self.assertEqual(sorted_findings[2].title, "Info")

    def test_sorted_ascending(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Critical", severity="critical"))
        agg.add_finding(_finding(title="Info", severity="info"))
        agg.add_finding(_finding(title="Medium", severity="medium"))
        sorted_findings = agg.sorted_by_severity(reverse=False)
        self.assertEqual(sorted_findings[0].title, "Info")
        self.assertEqual(sorted_findings[1].title, "Medium")
        self.assertEqual(sorted_findings[2].title, "Critical")


class StatisticsTests(unittest.TestCase):
    def test_statistics_counts(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="Critical Vuln", severity="critical", category="vulnerability", host="a.com"))
        agg.add_finding(_finding(title="High Vuln", severity="high", category="vulnerability", host="a.com"))
        agg.add_finding(
            _finding(title="Open Port", severity="medium", category="open_port", host="b.com", url="http://b.com:80")
        )
        stats = agg.statistics()
        self.assertEqual(stats.total, 3)
        self.assertEqual(stats.by_severity.get("critical"), 1)
        self.assertEqual(stats.by_severity.get("high"), 1)
        self.assertEqual(stats.by_severity.get("medium"), 1)
        self.assertEqual(stats.by_severity.get("low"), 0)
        self.assertEqual(stats.by_severity.get("info"), 0)
        self.assertEqual(stats.by_category.get("vulnerability"), 2)
        self.assertEqual(stats.by_category.get("open_port"), 1)

    def test_statistics_unique_hosts_urls(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="P1", host="a.com", url="http://a.com/page1"))
        agg.add_finding(_finding(title="P2", host="a.com", url="http://a.com/page2"))
        agg.add_finding(_finding(title="P3", host="b.com", url="http://b.com/page1"))
        stats = agg.statistics()
        self.assertEqual(stats.unique_hosts, 2)
        self.assertEqual(stats.unique_urls, 3)

    def test_statistics_empty(self) -> None:
        stats = FindingAggregator().statistics()
        self.assertEqual(stats.total, 0)
        self.assertEqual(stats.unique_hosts, 0)
        self.assertEqual(stats.unique_urls, 0)
        self.assertEqual(stats.stages_with_findings, 0)

    def test_statistics_stages(self) -> None:
        agg = FindingAggregator()
        agg.add_finding(_finding(title="A", source_stage="subfinder"))
        agg.add_finding(_finding(title="B", source_stage="httpx"))
        agg.add_finding(_finding(title="C", source_stage="httpx"))
        stats = agg.statistics()
        self.assertEqual(stats.stages_with_findings, 2)


class AggregatorStatsDataclassTests(unittest.TestCase):
    def test_defaults(self) -> None:
        s = AggregatorStats()
        self.assertEqual(s.total, 0)
        self.assertEqual(s.by_severity, {})
        self.assertEqual(s.by_category, {})

    def test_full_construction(self) -> None:
        s = AggregatorStats(
            total=10,
            by_severity={"critical": 3, "high": 2},
            by_category={"vulnerability": 5},
            unique_hosts=3,
            unique_urls=8,
            stages_with_findings=4,
        )
        self.assertEqual(s.total, 10)
        self.assertEqual(s.by_severity["critical"], 3)

    def test_merge_hosts_static_method_no_self(self) -> None:
        """Regression: _merge_hosts is @staticmethod and must not reference self."""
        from vina.core.runner import CommandResult
        from vina.scanners.web.gau import GauResult
        from vina.scanners.web.httpx import HttpxResult
        from vina.scanners.web.katana import KatanaResult
        from vina.scanners.web.naabu import NaabuResult
        from vina.scanners.web.nmap import NmapResult
        from vina.scanners.web.recon import WebReconResult
        from vina.scanners.web.whatweb import WhatWebResult

        cr = CommandResult(
            command="test",
            args=(),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.0,
        )
        subfinder = WebReconResult(target="example.com", command_result=cr, subdomains=["example.com"])
        httpx = HttpxResult(
            target="example.com",
            command_result=cr,
            records=[],
            alive_hosts=["https://example.com"],
        )
        naabu = NaabuResult(target="example.com", command_result=cr, open_ports=[])
        nmap = NmapResult(target="example.com", command_result=cr, hosts=[], services=[])
        whatweb = WhatWebResult(target="example.com", command_result=cr, hosts=[])
        katana = KatanaResult(target="example.com", command_result=cr, endpoints=[])
        gau = GauResult(target="example.com", command_result=cr, urls=[])

        hosts = Aggregator._merge_hosts(subfinder, httpx, naabu, nmap, whatweb, katana, gau)
        self.assertIsInstance(hosts, list)


if __name__ == "__main__":
    unittest.main()
