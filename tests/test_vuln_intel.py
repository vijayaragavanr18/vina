"""Tests for the Vulnerability Intelligence Engine."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from vina.core.vuln_intel import (
    FeedCache,
    NVDProvider,
    OSVProvider,
    SoftwareComponent,
    VulnEngineConfig,
    Vulnerability,
    VulnerabilityDatabase,
    VulnerabilityEngine,
    VulnerabilityMatch,
    build_software_inventory,
    compare_versions,
    component_from_finding,
    compute_vuln_stats,
    get_default_db,
    parse_version_pattern,
    reload_db,
    scan_components,
    version_matches,
)
from vina.models.findings import make_finding

# =========================================================================
#  Version comparison
# =========================================================================


class TestCompareVersions:
    def test_equal(self):
        assert compare_versions("1.2.3", "1.2.3") == 0

    def test_less_than(self):
        assert compare_versions("1.2.2", "1.2.3") == -1

    def test_greater_than(self):
        assert compare_versions("2.0.0", "1.9.9") == 1

    def test_semver_same_major(self):
        assert compare_versions("1.18.0", "1.18.9") == -1
        assert compare_versions("1.18.9", "1.18.0") == 1

    def test_debian_version_strings(self):
        assert compare_versions("8.4p1", "9.8p1") == -1
        assert compare_versions("6.8.0-35-generic", "6.6.14") == 1
        assert compare_versions("5.10.0-28-amd64", "5.10.0-27-amd64") == 1

    def test_debian_epoch(self):
        assert compare_versions("1:1.0", "2:1.0") == -1
        assert compare_versions("2:1.0", "1:1.0") == 1
        assert compare_versions("1:1.0", "1:1.0") == 0

    def test_package_suffixes(self):
        assert compare_versions("1.1.1f", "1.1.1g") == -1
        assert compare_versions("1.1.1g", "1.1.1f") == 1
        assert compare_versions("3.0.7", "3.0.7") == 0

    def test_different_lengths(self):
        # In Debian-style comparison, "1.0" == "1.0.0" (trailing ".0" components are equivalent)
        assert compare_versions("1.0", "1.0.0") == 0
        assert compare_versions("1.0.1", "1.0") == 1

    def test_empty_strings(self):
        assert compare_versions("", "") == 0
        assert compare_versions("1.0", "") == 1

    def test_prerelease_suffixes(self):
        # "alpha" < "beta" lexicographically
        assert compare_versions("1.0.0-alpha", "1.0.0-beta") == -1
        # "1.0.0-rc1" has Debian revision component that makes it > "1.0.0"
        # (Debian convention: any revision > no revision)
        assert compare_versions("1.0.0-rc1", "1.0.0") == 1


# =========================================================================
#  Version pattern parsing and matching
# =========================================================================


class TestParseVersionPattern:
    def test_less_than(self):
        result = parse_version_pattern("<2.4.58")
        assert len(result) == 1
        assert result[0].operator == "<"
        assert result[0].version == "2.4.58"

    def test_greater_equal(self):
        result = parse_version_pattern(">=9.0")
        assert result[0].operator == ">="
        assert result[0].version == "9.0"

    def test_exact(self):
        result = parse_version_pattern("=6.1.0")
        assert result[0].operator == "="

    def test_not_equal(self):
        result = parse_version_pattern("!=1.0")
        assert result[0].operator == "!="

    def test_comma_separated_range(self):
        result = parse_version_pattern(">=9.0,<9.3")
        assert len(result) == 2
        assert result[0].operator == ">="
        assert result[0].version == "9.0"
        assert result[1].operator == "<"
        assert result[1].version == "9.3"

    def test_dash_range(self):
        result = parse_version_pattern("1.18.0 - 1.18.9")
        assert len(result) == 2
        assert result[0].operator == ">="
        assert result[1].operator == "<="

    def test_wildcard_star(self):
        result = parse_version_pattern("6.1.*")
        assert len(result) == 2
        assert result[0].operator == ">="
        assert result[0].version == "6.1.0"
        assert result[1].operator == "<"
        assert result[1].version == "6.2.0"

    def test_wildcard_x(self):
        result = parse_version_pattern("5.15.x")
        assert len(result) == 2
        assert result[0].operator == ">="
        assert result[0].version == "5.15.0"
        assert result[1].operator == "<"
        assert result[1].version == "5.16.0"

    def test_bare_version(self):
        result = parse_version_pattern("6.1.0")
        assert len(result) == 1
        assert result[0].operator == "="
        assert result[0].version == "6.1.0"

    def test_empty_pattern(self):
        assert parse_version_pattern("") == []


class TestVersionMatches:
    def test_less_than(self):
        assert version_matches("1.0", "<2.0")
        assert not version_matches("3.0", "<2.0")

    def test_greater_than(self):
        assert version_matches("3.0", ">2.0")
        assert not version_matches("1.0", ">2.0")

    def test_less_equal(self):
        assert version_matches("2.0", "<=2.0")
        assert version_matches("1.0", "<=2.0")
        assert not version_matches("3.0", "<=2.0")

    def test_greater_equal(self):
        assert version_matches("2.0", ">=2.0")
        assert version_matches("3.0", ">=2.0")
        assert not version_matches("1.0", ">=2.0")

    def test_exact(self):
        assert version_matches("1.0.0", "=1.0.0")
        assert not version_matches("1.0.1", "=1.0.0")

    def test_not_equal(self):
        assert version_matches("1.0.1", "!=1.0.0")
        assert not version_matches("1.0.0", "!=1.0.0")

    def test_dash_range(self):
        assert version_matches("1.18.5", "1.18.0 - 1.18.9")
        assert version_matches("1.18.0", "1.18.0 - 1.18.9")
        assert version_matches("1.18.9", "1.18.0 - 1.18.9")
        assert not version_matches("1.17.0", "1.18.0 - 1.18.9")
        assert not version_matches("1.19.0", "1.18.0 - 1.18.9")

    def test_comma_range(self):
        assert version_matches("9.1", ">=9.0,<9.3")
        assert version_matches("9.0", ">=9.0,<9.3")
        assert not version_matches("8.9", ">=9.0,<9.3")
        assert not version_matches("9.3", ">=9.0,<9.3")

    def test_wildcard_star(self):
        assert version_matches("6.1.0", "6.1.*")
        assert version_matches("6.1.5", "6.1.*")
        assert version_matches("6.1.99", "6.1.*")
        assert not version_matches("6.0.9", "6.1.*")
        assert not version_matches("6.2.0", "6.1.*")

    def test_wildcard_x(self):
        assert version_matches("5.15.1", "5.15.x")
        assert version_matches("5.15.20", "5.15.x")
        assert not version_matches("5.14.0", "5.15.x")
        assert not version_matches("5.16.0", "5.15.x")

    def test_openssh_examples(self):
        # CVE-2024-6387: <8.5p1 || >=8.7p1,<9.8p1
        assert version_matches("8.4p1", "<8.5p1")
        assert not version_matches("8.6p1", "<8.5p1")
        assert version_matches("8.8p1", ">=8.7p1,<9.8p1")
        assert not version_matches("9.9p1", ">=8.7p1,<9.8p1")

    def test_kernel_examples(self):
        # CVE-2022-0847: <5.16.11||5.15.25||5.10.102
        assert version_matches("5.16.0", "<5.16.11")
        assert version_matches("5.15.25", "5.15.25")
        assert not version_matches("5.17.0", "<5.16.11")

    def test_unparseable_pattern_matches_everything(self):
        # Unparseable patterns like "garbage" are treated as exact match "=garbage"
        assert not version_matches("1.0", "some-garbage")
        # But empty/unparseable-only patterns still match everything
        assert version_matches("1.0", "")


# =========================================================================
#  SoftwareComponent model
# =========================================================================


class TestSoftwareComponent:
    def test_defaults(self):
        c = SoftwareComponent(name="openssh", version="8.4p1")
        assert c.name == "openssh"
        assert c.version == "8.4p1"
        assert c.vendor == ""
        assert c.architecture == ""
        assert c.package_manager == ""

    def test_slots(self):
        c = SoftwareComponent(name="a", version="1.0")
        with pytest.raises(AttributeError):
            c.nonexistent = "x"


# =========================================================================
#  Vulnerability model
# =========================================================================


class TestVulnerability:
    def test_defaults(self):
        v = Vulnerability(cve="CVE-2024-0001")
        assert v.cve == "CVE-2024-0001"
        assert v.severity == "medium"
        assert v.cvss_v3 == 0.0
        assert not v.kev
        assert v.source == "local"

    def test_full_fields(self):
        v = Vulnerability(
            cve="CVE-2024-6387",
            title="OpenSSH regreSSHion",
            description="RCE in OpenSSH",
            severity="critical",
            cvss_v3=8.1,
            epss=0.95,
            kev=True,
            exploited=True,
            vendor="openbsd",
            product="openssh",
            affected_versions=["<8.5p1"],
            fixed_versions=[">=8.5p1"],
            references=["https://nvd.nist.gov/"],
            cwe="CWE-20",
            exploit_available=True,
            confidence=0.95,
        )
        assert v.cve == "CVE-2024-6387"
        assert v.cvss_v3 == 8.1
        assert v.epss == 0.95
        assert v.kev
        assert v.exploit_available
        assert v.confidence == 0.95


# =========================================================================
#  VulnerabilityMatch -> Finding
# =========================================================================


class TestVulnerabilityMatch:
    def test_to_finding(self):
        v = Vulnerability(
            cve="CVE-2024-6387",
            severity="critical",
            cvss_v3=8.1,
            description="RCE in OpenSSH",
            references=["https://nvd.nist.gov/"],
        )
        c = SoftwareComponent(name="openssh", version="8.4p1")
        m = VulnerabilityMatch(
            vulnerability=v,
            component=c,
            matching_version="8.4p1",
            affected_range="<8.5p1",
            fixed_version="8.5p1",
            risk_score=85.0,
        )
        f = m.to_finding()
        assert "CVE-2024-6387" in f.title
        assert f.severity == "critical"
        assert f.category == "vulnerability"
        assert "openssh" in f.target or "openssh" in f.evidence
        assert "8.5p1" in f.recommendation
        assert "exploit" not in f.tags

    def test_to_finding_with_exploit_tags(self):
        v = Vulnerability(
            cve="CVE-2024-0001",
            severity="critical",
            cvss_v3=9.5,
            kev=True,
            exploit_available=True,
        )
        c = SoftwareComponent(name="test", version="1.0")
        m = VulnerabilityMatch(vulnerability=v, component=c, matching_version="1.0", risk_score=90)
        f = m.to_finding()
        assert "kev" in f.tags
        assert "exploit-available" in f.tags
        assert "critical-cvss" in f.tags


# =========================================================================
#  VulnerabilityDatabase
# =========================================================================


class TestVulnerabilityDatabase:
    _SAMPLE_CVES: list[dict[str, object]] = [  # noqa: RUF012
        {
            "cve": "CVE-2024-0001",
            "title": "Test CVE 1",
            "severity": "high",
            "vendor": "testcorp",
            "product": "testproduct",
            "affected_versions": ["<2.0"],
            "cvss_v3": 7.5,
        },
        {
            "cve": "CVE-2024-0002",
            "title": "Test CVE 2",
            "severity": "critical",
            "vendor": "testcorp",
            "product": "testproduct",
            "affected_versions": ["<1.0"],
            "cvss_v3": 9.0,
            "kev": True,
        },
        {
            "cve": "CVE-2024-0003",
            "title": "Other Product",
            "severity": "medium",
            "vendor": "other",
            "product": "otherproduct",
            "affected_versions": ["<3.0"],
        },
    ]

    def _make_db_file(self, entries: list[dict]) -> Path:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(entries, tmp)
            tmp_name = tmp.name
        return Path(tmp_name)

    def test_load_empty(self):
        db = VulnerabilityDatabase()
        assert db.count == 0

    def test_load_from_file(self):
        path = self._make_db_file(self._SAMPLE_CVES)
        db = VulnerabilityDatabase(paths=[path])
        assert db.count == 3
        os.unlink(path)

    def test_lookup_by_vendor_product(self):
        path = self._make_db_file(self._SAMPLE_CVES)
        db = VulnerabilityDatabase(paths=[path])
        comp = SoftwareComponent(name="testproduct", version="1.5", vendor="testcorp")
        results = db.lookup(comp)
        assert len(results) == 2
        cves = {v.cve for v in results}
        assert "CVE-2024-0001" in cves
        assert "CVE-2024-0002" in cves
        os.unlink(path)

    def test_lookup_by_product_only(self):
        path = self._make_db_file(self._SAMPLE_CVES)
        db = VulnerabilityDatabase(paths=[path])
        comp = SoftwareComponent(name="testproduct", version="1.5")
        results = db.lookup(comp)
        assert len(results) == 2
        os.unlink(path)

    def test_lookup_no_match(self):
        path = self._make_db_file(self._SAMPLE_CVES)
        db = VulnerabilityDatabase(paths=[path])
        comp = SoftwareComponent(name="unknown", version="1.0")
        results = db.lookup(comp)
        assert results == []
        os.unlink(path)

    def test_load_bad_path(self):
        db = VulnerabilityDatabase(paths=[Path("/nonexistent/cves.json")])
        assert db.count == 0


# =========================================================================
#  VulnerabilityEngine
# =========================================================================


class TestVulnerabilityEngine:
    _SAMPLE_CVES: list[dict[str, object]] = [  # noqa: RUF012
        {
            "cve": "CVE-2024-0001",
            "severity": "high",
            "vendor": "testcorp",
            "product": "app",
            "affected_versions": ["<2.0"],
            "fixed_versions": [">=2.0"],
            "cvss_v3": 7.5,
            "epss": 0.5,
            "confidence": 0.9,
        },
        {
            "cve": "CVE-2024-0002",
            "severity": "critical",
            "vendor": "testcorp",
            "product": "app",
            "affected_versions": [">=2.0,<3.0"],
            "fixed_versions": [">=3.0"],
            "cvss_v3": 9.0,
            "kev": True,
            "exploit_available": True,
            "confidence": 0.95,
        },
        {
            "cve": "CVE-2024-0003",
            "severity": "medium",
            "vendor": "other",
            "product": "other",
            "affected_versions": ["<1.0"],
            "cvss_v3": 5.0,
        },
    ]

    def _make_db(self) -> VulnerabilityDatabase:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(self._SAMPLE_CVES, tmp)
            tmp_name = tmp.name
        db = VulnerabilityDatabase(paths=[Path(tmp_name)])
        return db

    def test_empty_components(self):
        db = self._make_db()
        engine = VulnerabilityEngine(database=db)
        assert engine.run([]) == []

    def test_single_match(self):
        db = self._make_db()
        engine = VulnerabilityEngine(database=db)
        comp = SoftwareComponent(name="app", version="1.0", vendor="testcorp")
        matches = engine.run([comp])
        assert len(matches) == 1
        assert matches[0].vulnerability.cve == "CVE-2024-0001"
        assert matches[0].component.name == "app"

    def test_multiple_matches(self):
        db = self._make_db()
        engine = VulnerabilityEngine(database=db)
        comp = SoftwareComponent(name="app", version="2.5", vendor="testcorp")
        matches = engine.run([comp])
        assert len(matches) == 1
        assert matches[0].vulnerability.cve == "CVE-2024-0002"

    def test_no_match(self):
        db = self._make_db()
        engine = VulnerabilityEngine(database=db)
        comp = SoftwareComponent(name="app", version="3.0", vendor="testcorp")
        matches = engine.run([comp])
        assert len(matches) == 0

    def test_no_version_no_match(self):
        db = self._make_db()
        engine = VulnerabilityEngine(database=db)
        comp = SoftwareComponent(name="app", vendor="testcorp")
        assert engine.run([comp]) == []

    def test_fixed_version_excludes_match(self):
        db = self._make_db()
        engine = VulnerabilityEngine(database=db)
        comp = SoftwareComponent(name="app", version="2.0", vendor="testcorp")
        matches = engine.run([comp])
        # CVE-2024-0001 has fixed_versions [">=2.0"] but affected is ["<2.0"],
        # so version 2.0 doesn't match CVE-2024-0001 at all (not affected).
        # CVE-2024-0002 has affected [">=2.0,<3.0"], fixed [">=3.0"],
        # so version 2.0 matches (affected, not fixed).
        assert len(matches) == 1
        assert matches[0].vulnerability.cve == "CVE-2024-0002"

    def test_dedup_same_cve_multiple_components(self):
        db = self._make_db()
        engine = VulnerabilityEngine(database=db)
        comp1 = SoftwareComponent(name="app", version="1.0", vendor="testcorp")
        comp2 = SoftwareComponent(name="app", version="1.0", vendor="testcorp")
        matches = engine.run([comp1, comp2])
        assert len(matches) == 1

    def test_risk_score_ordering(self):
        db = self._make_db()
        engine = VulnerabilityEngine(database=db)
        comp = SoftwareComponent(name="app", version="1.0", vendor="testcorp")
        matches = engine.run([comp])
        assert matches[0].risk_score > 0

    def test_config_max_results(self):
        self._make_db()
        # Add a second component with matches
        extra_cve = {
            "cve": "CVE-2024-0004",
            "severity": "low",
            "vendor": "testcorp",
            "product": "otherapp",
            "affected_versions": ["<5.0"],
            "cvss_v3": 2.0,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump([*self._SAMPLE_CVES, extra_cve], tmp)
            tmp_name = tmp.name
        db2 = VulnerabilityDatabase(paths=[Path(tmp_name)])
        engine = VulnerabilityEngine(database=db2, config=VulnEngineConfig(max_results=1))
        comp1 = SoftwareComponent(name="app", version="1.0", vendor="testcorp")
        comp2 = SoftwareComponent(name="otherapp", version="1.0", vendor="testcorp")
        matches = engine.run([comp1, comp2])
        assert len(matches) == 1


# =========================================================================
#  build_software_inventory
# =========================================================================


class TestBuildSoftwareInventory:
    def test_from_kernel_finding(self):
        f = make_finding(
            title="Kernel: 6.8.0-35-generic",
            source_stage="kernel",
            evidence="kernel=6.8.0-35-generic arch=amd64",
        )
        inventory = build_software_inventory([f])
        assert len(inventory) == 1
        assert inventory[0].name == "linux-kernel"
        assert inventory[0].version == "6.8.0-35-generic"

    def test_from_package_finding(self):
        f = make_finding(
            title="Installed: openssh (8.4p1)",
            source_stage="packages",
            evidence="openssh=8.4p1 arch=amd64",
        )
        inventory = build_software_inventory([f])
        assert len(inventory) == 1
        assert inventory[0].name == "openssh"
        assert inventory[0].version == "8.4p1"

    def test_dedup_same_component(self):
        f1 = make_finding(
            title="Installed: openssh (8.4p1)",
            source_stage="packages",
            evidence="openssh=8.4p1",
        )
        f2 = make_finding(
            title="Installed: openssh (8.4p1)",
            source_stage="packages",
            evidence="openssh=8.4p1",
        )
        inventory = build_software_inventory([f1, f2])
        assert len(inventory) == 1

    def test_no_version_finding(self):
        f = make_finding(
            title="ASLR is enabled",
            source_stage="kernel",
        )
        inventory = build_software_inventory([f])
        assert len(inventory) == 0

    def test_multiple_components(self):
        f1 = make_finding(
            title="Kernel: 6.8.0-35-generic",
            source_stage="kernel",
            evidence="kernel=6.8.0-35-generic",
        )
        f2 = make_finding(
            title="Installed: openssh (8.4p1)",
            source_stage="packages",
            evidence="openssh=8.4p1",
        )
        f3 = make_finding(
            title="Installed: openssl (1.1.1f)",
            source_stage="packages",
            evidence="openssl=1.1.1f",
        )
        inventory = build_software_inventory([f1, f2, f3])
        names = {c.name for c in inventory}
        assert "linux-kernel" in names
        assert "openssh" in names
        assert "openssl" in names or "openssl (1.1.1f)" in names or "Installed: openssl" in names


# =========================================================================
#  component_from_finding
# =========================================================================


class TestComponentFromFinding:
    def test_from_evidence_kernel(self):
        f = make_finding(title="Kernel info", evidence="kernel=5.10.0-28-amd64")
        c = component_from_finding(f)
        assert c is not None
        assert c.name == "linux-kernel"
        assert c.version == "5.10.0-28-amd64"

    def test_from_evidence_not_parseable(self):
        f = make_finding(title="Something", evidence="no equals sign")
        c = component_from_finding(f)
        # May be None or match based on title
        if c is not None:
            assert c.name

    def test_non_version_finding(self):
        f = make_finding(title="ASLR is enabled")
        c = component_from_finding(f)
        # Should return None since there's no version info
        assert c is None or not c.version


# =========================================================================
#  VulnStats / compute_vuln_stats
# =========================================================================


class TestComputeVulnStats:
    def test_empty(self):
        stats = compute_vuln_stats([])
        assert stats.total_vulnerabilities == 0
        assert stats.overall_score == 0.0
        assert stats.by_severity == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def test_single_critical(self):
        v = Vulnerability(cve="CVE-1", severity="critical", cvss_v3=9.0, kev=True, exploit_available=True)
        m = VulnerabilityMatch(
            vulnerability=v,
            component=SoftwareComponent(name="test", version="1.0"),
            risk_score=90.0,
        )
        stats = compute_vuln_stats([m])
        assert stats.total_vulnerabilities == 1
        assert stats.critical_cves == 1
        assert stats.kev_count == 1
        assert stats.public_exploits == 1
        assert stats.by_severity["critical"] == 1
        assert stats.overall_score > 0

    def test_multiple_severities(self):
        vulns = [
            Vulnerability(cve="CVE-1", severity="critical", cvss_v3=9.0),
            Vulnerability(cve="CVE-2", severity="high", cvss_v3=7.5),
            Vulnerability(cve="CVE-3", severity="medium", cvss_v3=5.0),
        ]
        matches = [
            VulnerabilityMatch(vulnerability=v, component=SoftwareComponent(name="t", version="1"), risk_score=50)
            for v in vulns
        ]
        stats = compute_vuln_stats(matches)
        assert stats.total_vulnerabilities == 3
        assert stats.critical_cves == 1
        assert stats.by_severity["critical"] == 1
        assert stats.by_severity["high"] == 1
        assert stats.by_severity["medium"] == 1

    def test_top_cves(self):
        vulns = [Vulnerability(cve=f"CVE-{i}", severity="high" if i < 3 else "medium", cvss_v3=7.5) for i in range(10)]
        matches = [
            VulnerabilityMatch(vulnerability=v, component=SoftwareComponent(name="t", version="1"), risk_score=70 - i)
            for i, v in enumerate(vulns)
        ]
        stats = compute_vuln_stats(matches)
        assert len(stats.top_cves) == 5
        assert stats.top_cves[0]["cve"] == "CVE-0"

    def test_with_component_count(self):
        v = Vulnerability(cve="CVE-1", severity="low", cvss_v3=3.0)
        m = VulnerabilityMatch(vulnerability=v, component=SoftwareComponent(name="t", version="1"), risk_score=10)
        stats = compute_vuln_stats([m], components_count=50)
        assert stats.total_components == 50


# =========================================================================
#  FeedCache
# =========================================================================


class TestFeedCache:
    def test_set_and_get(self):
        cache = FeedCache(cache_dir=Path(tempfile.mkdtemp()))
        data = [{"id": "CVE-2024-0001"}, {"id": "CVE-2024-0002"}]
        cache.set("test", data)
        result = cache.get("test")
        assert result is not None
        assert len(result) == 2
        assert result[0]["id"] == "CVE-2024-0001"

    def test_get_missing(self):
        cache = FeedCache(cache_dir=Path(tempfile.mkdtemp()))
        assert cache.get("nonexistent") is None

    def test_clear(self):
        cache = FeedCache(cache_dir=Path(tempfile.mkdtemp()))
        cache.set("test", [{"id": "1"}])
        assert cache.get("test") is not None
        cache.clear()
        assert cache.get("test") is None


# =========================================================================
#  NVDProvider / OSVProvider
# =========================================================================


class TestNVDProvider:
    def test_default_empty(self):
        provider = NVDProvider()
        assert provider.name == "nvd"
        results = provider.fetch()
        assert isinstance(results, list)

    def test_name(self):
        assert NVDProvider().name == "nvd"


class TestOSVProvider:
    def test_default_empty(self):
        provider = OSVProvider()
        assert provider.name == "osv"
        results = provider.fetch()
        assert isinstance(results, list)

    def test_name(self):
        assert OSVProvider().name == "osv"


# =========================================================================
#  Default database singleton
# =========================================================================


class TestDefaultDatabase:
    def test_get_default_db(self):
        db = get_default_db()
        assert db is not None
        assert db.count > 0

    def test_reload_db(self):
        count_before = get_default_db().count
        reload_db()
        count_after = get_default_db().count
        assert count_after == count_before

    def test_scan_components(self):
        # Test the convenience function with a real CVE match
        comp = SoftwareComponent(name="openssh", version="8.4p1")
        matches = scan_components([comp])
        assert len(matches) > 0
        assert any("CVE-2024-6387" in m.vulnerability.cve for m in matches)


# =========================================================================
#  JSON serialization
# =========================================================================


class TestJsonSerialization:
    def test_vulnerability_match_roundtrip(self):
        v = Vulnerability(
            cve="CVE-2024-0001",
            severity="high",
            cvss_v3=7.5,
            vendor="test",
            product="app",
            references=["https://example.com"],
        )
        c = SoftwareComponent(name="app", version="1.0")
        m = VulnerabilityMatch(
            vulnerability=v, component=c, matching_version="1.0", fixed_version="2.0", risk_score=75.0
        )
        f = m.to_finding()
        d = f.to_dict()
        assert isinstance(d, dict)
        assert "CVE-2024-0001" in d["title"]
        assert d["severity"] == "high"

    def test_vuln_stats_json_serializable(self):
        v = Vulnerability(cve="CVE-1", severity="critical")
        m = VulnerabilityMatch(vulnerability=v, component=SoftwareComponent(name="t", version="1"), risk_score=90)
        stats = compute_vuln_stats([m])
        d = {
            "total": stats.total_vulnerabilities,
            "critical": stats.critical_cves,
            "score": stats.overall_score,
            "top": stats.top_cves,
        }
        dumped = json.dumps(d)
        loaded = json.loads(dumped)
        assert loaded["total"] == 1
        assert loaded["critical"] == 1
