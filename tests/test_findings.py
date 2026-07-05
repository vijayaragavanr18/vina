"""Tests for the unified Finding model."""

from __future__ import annotations

import unittest

from vina.models.findings import (
    Finding,
    FindingCategory,
    Severity,
    make_finding,
    severity_key,
)


class SeverityTests(unittest.TestCase):
    def test_values(self) -> None:
        self.assertEqual(Severity.INFO, "info")
        self.assertEqual(Severity.LOW, "low")
        self.assertEqual(Severity.MEDIUM, "medium")
        self.assertEqual(Severity.HIGH, "high")
        self.assertEqual(Severity.CRITICAL, "critical")

    def test_order(self) -> None:
        self.assertGreater(severity_key("critical"), severity_key("high"))
        self.assertGreater(severity_key("high"), severity_key("medium"))
        self.assertGreater(severity_key("medium"), severity_key("low"))
        self.assertGreater(severity_key("low"), severity_key("info"))

    def test_unknown_severity_returns_zero(self) -> None:
        self.assertEqual(severity_key("unknown"), 0)

    def test_severity_enum_as_key(self) -> None:
        self.assertEqual(severity_key(Severity.CRITICAL), 5)


class FindingCategoryTests(unittest.TestCase):
    def test_values(self) -> None:
        self.assertEqual(FindingCategory.VULNERABILITY, "vulnerability")
        self.assertEqual(FindingCategory.SUBDOMAIN, "subdomain")
        self.assertEqual(FindingCategory.OPEN_PORT, "open_port")
        self.assertEqual(FindingCategory.ALIVE_HOST, "alive_host")


class FindingCreationTests(unittest.TestCase):
    def test_create_minimal(self) -> None:
        f = Finding()
        self.assertEqual(f.severity, "info")
        self.assertEqual(f.category, "other")

    def test_create_full(self) -> None:
        f = Finding(
            id="test/example.com/test-finding",
            title="Test Finding",
            description="A test finding",
            severity="high",
            category="vulnerability",
            source_stage="nuclei",
            target="example.com",
            evidence="https://example.com/vuln",
            recommendation="Patch it",
            references=["https://cve.com/CVE-1234"],
            timestamp="2025-01-01T00:00:00Z",
        )
        self.assertEqual(f.title, "Test Finding")
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.recommendation, "Patch it")
        self.assertEqual(f.references, ["https://cve.com/CVE-1234"])

    def test_to_dict(self) -> None:
        f = Finding(
            id="t1",
            title="Test",
            severity="critical",
            category="vulnerability",
            source_stage="nuclei",
            target="example.com",
            host="example.com",
            port=443,
        )
        d = f.to_dict()
        self.assertEqual(d["id"], "t1")
        self.assertEqual(d["title"], "Test")
        self.assertEqual(d["severity"], "critical")
        self.assertEqual(d["port"], 443)
        self.assertEqual(d["host"], "example.com")


class MakeFindingTests(unittest.TestCase):
    def test_make_basic(self) -> None:
        f = make_finding(
            title="Subdomain: admin.example.com",
            severity="info",
            category="subdomain",
            source_stage="subfinder",
            target="example.com",
            host="admin.example.com",
        )
        self.assertEqual(f.title, "Subdomain: admin.example.com")
        self.assertEqual(f.severity, "info")
        self.assertEqual(f.source_stage, "subfinder")
        self.assertEqual(f.host, "admin.example.com")
        self.assertIn("T", f.timestamp)  # ISO format

    def test_make_with_all_fields(self) -> None:
        f = make_finding(
            title="Open port: 443/tcp",
            description="Discovered open port",
            severity="medium",
            category="open_port",
            source_stage="naabu",
            target="example.com",
            evidence="example.com:443/tcp",
            recommendation="Restrict access",
            references=["https://docs.example.com"],
            host="example.com",
            port=443,
            protocol="tcp",
            url="https://example.com",
            confidence=0.95,
            tags=["ssl", "https"],
        )
        self.assertEqual(f.port, 443)
        self.assertEqual(f.protocol, "tcp")
        self.assertEqual(f.confidence, 0.95)
        self.assertEqual(f.tags, ["ssl", "https"])
        self.assertEqual(f.references, ["https://docs.example.com"])

    def test_make_generates_id(self) -> None:
        f = make_finding(
            title="Test",
            source_stage="subfinder",
            target="example.com",
        )
        self.assertEqual(f.id, "subfinder/example.com/Test")

    def test_make_empty_fields_default(self) -> None:
        f = make_finding(title="Test")
        self.assertEqual(f.references, [])
        self.assertEqual(f.tags, [])


if __name__ == "__main__":
    unittest.main()
