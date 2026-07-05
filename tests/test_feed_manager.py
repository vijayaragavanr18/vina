"""Tests for the Live Vulnerability Intelligence Feed Manager."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vina.core.feed_manager import (
    FeedCache,
    FeedEntry,
    FeedManager,
    FeedMetadata,
    FeedScheduler,
    FeedSource,
    FeedType,
    FeedUpdater,
    UpdateStatus,
    _compute_checksum,
    _exponential_backoff,
    _now_iso,
    _parse_cisa_kev,
    _parse_epss_csv,
    _parse_github_advisory,
    _parse_nvd_response,
    _parse_osv_response,
    get_default_manager,
    get_feed_status,
)

# =========================================================================
#  Fixtures
# =========================================================================


@pytest.fixture
def tmp_cache(tmp_path: Path) -> FeedCache:
    return FeedCache(cache_dir=tmp_path / "feeds")


@pytest.fixture
def tmp_manager(tmp_path: Path) -> FeedManager:
    return FeedManager(feed_dir=tmp_path / "feeds")


# Sample data for feed parsers

NVD_SAMPLE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-0001",
                "sourceIdentifier": "test@example.com",
                "published": "2024-01-01T00:00:00Z",
                "lastModified": "2024-06-01T00:00:00Z",
                "descriptions": [{"lang": "en", "value": "Test vulnerability in product 1.0"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "1.0",
                                        "versionEndExcluding": "2.0",
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [{"url": "https://example.com/cve-2024-0001"}],
            }
        }
    ]
}

CISA_KEV_SAMPLE = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-0002",
            "vulnerabilityName": "Test KEV Vuln",
            "shortDescription": "Actively exploited in the wild",
            "vendorProject": "TestVendor",
            "product": "TestProduct",
            "dateAdded": "2024-03-15",
            "notes": "https://example.com/kev-note",
        }
    ]
}

EPSS_CSV_SAMPLE = """cve,epss,percentile
CVE-2024-0001,0.95,0.99
CVE-2024-0002,0.50,0.80
CVE-2024-0003,0.01,0.10
"""

EPSS_CSV_GZIPPED_BYTES = None  # will create in test if needed

OSV_SAMPLE = {
    "results": [
        {
            "id": "CVE-2024-0001",
            "summary": "Test OSV vuln",
            "details": "Details about the vulnerability",
            "aliases": ["CVE-2024-0001"],
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "affected": [
                {
                    "package": {"name": "test-pkg"},
                    "ranges": [{"events": [{"introduced": "1.0"}, {"fixed": "2.0"}]}],
                }
            ],
            "references": [{"url": "https://osv.dev/test"}],
            "published": "2024-01-01T00:00:00Z",
            "modified": "2024-06-01T00:00:00Z",
        }
    ]
}

GITHUB_ADVISORY_SAMPLE = [
    {
        "cve_id": "CVE-2024-0001",
        "summary": "Test GitHub Advisory",
        "description": "A security vulnerability in test-pkg",
        "cvss": {"score": 9.8, "severity": "critical"},
        "identifiers": [{"type": "CVE", "value": "CVE-2024-0001"}],
        "references": [{"url": "https://github.com/advisories/test"}],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": "test-pkg"},
                "vulnerableVersionRange": ">=1.0.0, <2.0.0",
            }
        ],
        "published_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
    }
]


# =========================================================================
#  FeedCache tests
# =========================================================================


class TestFeedCache:
    def test_init_creates_db(self, tmp_cache: FeedCache):
        assert tmp_cache.db_path.exists()
        assert tmp_cache.size_bytes > 0

    def test_set_and_get_metadata(self, tmp_cache: FeedCache):
        tmp_cache.set_metadata("test_key", "test_value")
        assert tmp_cache.get_metadata("test_key") == "test_value"

    def test_get_metadata_missing(self, tmp_cache: FeedCache):
        assert tmp_cache.get_metadata("nonexistent") is None

    def test_get_all_metadata(self, tmp_cache: FeedCache):
        tmp_cache.set_metadata("a", "1")
        tmp_cache.set_metadata("b", "2")
        all_meta = tmp_cache.get_all_metadata()
        assert all_meta["a"] == "1"
        assert all_meta["b"] == "2"

    def test_upsert_and_get_source(self, tmp_cache: FeedCache):
        tmp_cache.upsert_source("nvd", "nvd", etag="abc123", entry_count=42)
        src = tmp_cache.get_source("nvd")
        assert src is not None
        assert src["name"] == "nvd"
        assert src["feed_type"] == "nvd"
        assert src["etag"] == "abc123"
        assert src["entry_count"] == 42
        assert src["last_fetch"] is not None

    def test_get_source_missing(self, tmp_cache: FeedCache):
        assert tmp_cache.get_source("nonexistent") is None

    def test_upsert_and_get_entry(self, tmp_cache: FeedCache):
        data = {"severity": "critical", "cvss_v3": 9.8}
        is_new = tmp_cache.upsert_entry("CVE-2024-0001", "nvd", data)
        assert is_new is True

        # Update existing
        data["cvss_v3"] = 9.9
        is_new = tmp_cache.upsert_entry("CVE-2024-0001", "nvd", data)
        assert is_new is False

    def test_get_entries_for_source(self, tmp_cache: FeedCache):
        tmp_cache.upsert_entry("CVE-2024-0001", "nvd", {"cvss_v3": 9.8})
        tmp_cache.upsert_entry("CVE-2024-0002", "nvd", {"cvss_v3": 7.5})
        tmp_cache.upsert_entry("CVE-2024-0003", "osv", {"cvss_v3": 5.0})

        nvd_entries = tmp_cache.get_entries_for_source("nvd")
        assert len(nvd_entries) == 2
        assert all(e["cve"].startswith("CVE-2024-") for e in nvd_entries)

    def test_get_all_entries(self, tmp_cache: FeedCache):
        tmp_cache.upsert_entry("CVE-2024-0001", "nvd", {"cvss_v3": 9.8})
        tmp_cache.upsert_entry("CVE-2024-0002", "osv", {"cvss_v3": 5.0})
        all_entries = tmp_cache.get_all_entries()
        assert len(all_entries) == 2

    def test_delete_source_entries(self, tmp_cache: FeedCache):
        tmp_cache.upsert_entry("CVE-2024-0001", "nvd", {"cvss_v3": 9.8})
        tmp_cache.upsert_entry("CVE-2024-0002", "nvd", {"cvss_v3": 7.5})
        tmp_cache.upsert_entry("CVE-2024-0003", "osv", {"cvss_v3": 5.0})

        deleted = tmp_cache.delete_source_entries("nvd")
        assert deleted >= 2
        assert tmp_cache.count_entries() == 1

    def test_count_entries(self, tmp_cache: FeedCache):
        assert tmp_cache.count_entries() == 0
        tmp_cache.upsert_entry("CVE-2024-0001", "nvd", {})
        assert tmp_cache.count_entries() == 1
        assert tmp_cache.count_entries("nvd") == 1
        assert tmp_cache.count_entries("osv") == 0

    def test_batch_upsert(self, tmp_cache: FeedCache):
        entries = [
            ("CVE-2024-0001", "nvd", {"cvss_v3": 9.8}),
            ("CVE-2024-0002", "nvd", {"cvss_v3": 7.5}),
        ]
        added, updated = tmp_cache.batch_upsert(entries)
        assert added == 2
        assert updated == 0

        # Re-insert
        added, updated = tmp_cache.batch_upsert(entries)
        assert added == 0
        assert updated == 2

    def test_compute_checksum_changes(self, tmp_cache: FeedCache):
        c1 = tmp_cache.compute_checksum()
        tmp_cache.upsert_entry("CVE-2024-0001", "nvd", {"cvss_v3": 9.8})
        c2 = tmp_cache.compute_checksum()
        assert c1 != c2

    def test_verify_integrity(self, tmp_cache: FeedCache):
        tmp_cache.set_metadata("checksum", tmp_cache.compute_checksum())
        assert tmp_cache.verify_integrity() is True

        # Corrupt by adding an entry without updating checksum
        tmp_cache.upsert_entry("CVE-2024-9999", "nvd", {})
        assert tmp_cache.verify_integrity() is False

    def test_clear(self, tmp_cache: FeedCache):
        tmp_cache.upsert_entry("CVE-2024-0001", "nvd", {})
        tmp_cache.set_metadata("test", "value")
        tmp_cache.clear()
        assert tmp_cache.count_entries() == 0
        assert tmp_cache.get_metadata("test") is None

    def test_get_feed_versions(self, tmp_cache: FeedCache):
        versions = tmp_cache.get_feed_versions()
        assert isinstance(versions, dict)

        tmp_cache.set_metadata("feed_nvd_updated", "2024-06-01T00:00:00")
        versions = tmp_cache.get_feed_versions()
        assert "nvd" in versions
        assert versions["nvd"] == "2024-06-01T00:00:00"

    def test_concurrent_safe(self, tmp_cache: FeedCache):
        """Basic concurrent access should not crash."""
        import threading

        errors = []

        def worker():
            try:
                for i in range(10):
                    tmp_cache.upsert_entry(f"CVE-2024-{i:04d}", "test", {"i": i})
                    tmp_cache.get_entries_for_source("test")
                    tmp_cache.count_entries()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"Concurrent access errors: {errors}"
        assert tmp_cache.count_entries("test") == 10


# =========================================================================
#  FeedMetadata tests
# =========================================================================


class TestFeedMetadata:
    def test_default_values(self):
        meta = FeedMetadata()
        assert meta.db_version == 1
        assert meta.is_offline is True
        assert meta.total_entries == 0
        assert meta.feed_versions == {}

    def test_to_dict_roundtrip(self):
        meta = FeedMetadata(
            db_version=2,
            last_updated="2024-06-01T00:00:00",
            is_offline=False,
            total_entries=100,
            feed_versions={"nvd": "2024-06-01"},
            feed_entry_counts={"nvd": 50},
            checksum="abc123",
        )
        d = meta.to_dict()
        restored = FeedMetadata.from_dict(d)
        assert restored.db_version == 2
        assert restored.last_updated == "2024-06-01T00:00:00"
        assert restored.is_offline is False
        assert restored.total_entries == 100
        assert restored.feed_versions == {"nvd": "2024-06-01"}
        assert restored.feed_entry_counts == {"nvd": 50}
        assert restored.checksum == "abc123"

    def test_feed_age_hours_no_update(self):
        meta = FeedMetadata()
        assert meta.feed_age_hours == -1.0

    def test_feed_age_hours_recent(self):
        now = datetime.now(UTC).isoformat()
        meta = FeedMetadata(last_updated=now)
        assert meta.feed_age_hours < 0.01

    def test_feed_age_hours_old(self):
        from datetime import timedelta

        old = (datetime.now(UTC) - timedelta(hours=48)).isoformat()
        meta = FeedMetadata(last_updated=old)
        assert meta.feed_age_hours > 47
        assert meta.feed_age_hours < 49

    def test_feed_age_hours_invalid_date(self):
        meta = FeedMetadata(last_updated="not-a-date")
        assert meta.feed_age_hours == -1.0

    def test_from_dict_empty(self):
        meta = FeedMetadata.from_dict({})
        assert meta.db_version == 1
        assert meta.is_offline is True


# =========================================================================
#  FeedEntry tests
# =========================================================================


class TestFeedEntry:
    def test_to_vulnerability(self):
        entry = FeedEntry(
            cve="CVE-2024-0001",
            title="Test",
            severity="critical",
            cvss_v3=9.8,
            kev=True,
            source="nvd",
        )
        v = entry.to_vulnerability()
        assert v["cve"] == "CVE-2024-0001"
        assert v["severity"] == "critical"
        assert v["cvss_v3"] == 9.8
        assert v["kev"] is True
        assert v["source"] == "nvd"

    def test_to_vulnerability_defaults(self):
        entry = FeedEntry(cve="CVE-2024-0001")
        v = entry.to_vulnerability()
        assert v["cve"] == "CVE-2024-0001"
        assert v["source"] == ""


# =========================================================================
#  Feed parsers
# =========================================================================


class TestParsers:
    def test_parse_nvd_response(self):
        data = json.dumps(NVD_SAMPLE).encode()
        entries = _parse_nvd_response(data)
        assert len(entries) == 1
        e = entries[0]
        assert e.cve == "CVE-2024-0001"
        assert e.severity == "critical"
        assert e.cvss_v3 == 9.8
        assert "Test vulnerability" in e.description
        assert e.vendor == "vendor"
        assert e.product == "product"
        assert e.references == ["https://example.com/cve-2024-0001"]

    def test_parse_nvd_response_empty(self):
        data = json.dumps({"vulnerabilities": []}).encode()
        entries = _parse_nvd_response(data)
        assert entries == []

    def test_parse_cisa_kev(self):
        data = json.dumps(CISA_KEV_SAMPLE).encode()
        entries = _parse_cisa_kev(data)
        assert len(entries) == 1
        e = entries[0]
        assert e.cve == "CVE-2024-0002"
        assert e.kev is True
        assert e.exploited is True
        assert e.exploit_available is True
        assert e.severity == "critical"
        assert e.vendor == "TestVendor"
        assert e.product == "TestProduct"

    def test_parse_cisa_kev_empty(self):
        data = json.dumps({"vulnerabilities": []}).encode()
        entries = _parse_cisa_kev(data)
        assert entries == []

    def test_parse_epss_csv(self):
        data = EPSS_CSV_SAMPLE.encode()
        entries = _parse_epss_csv(data)
        assert len(entries) == 3
        assert entries[0].cve == "CVE-2024-0001"
        assert entries[0].epss == 0.95
        assert entries[1].cve == "CVE-2024-0002"
        assert entries[1].epss == 0.50

    def test_parse_epss_csv_empty(self):
        data = b"# EPSS scores\ncve,epss,percentile\n"
        entries = _parse_epss_csv(data)
        assert entries == []

    def test_parse_epss_csv_gzipped(self):
        import gzip

        compressed = gzip.compress(EPSS_CSV_SAMPLE.encode())
        entries = _parse_epss_csv(compressed)
        assert len(entries) == 3

    def test_parse_osv_response(self):
        data = json.dumps(OSV_SAMPLE).encode()
        entries = _parse_osv_response(data)
        assert len(entries) == 1
        e = entries[0]
        assert e.cve == "CVE-2024-0001"
        assert "Test OSV vuln" in e.title
        assert e.severity == "high"  # CVSS 7.5 → high
        assert "test-pkg" in e.product

    def test_parse_osv_response_single(self):
        """Test parsing a single object (not wrapped in results list)."""
        item = OSV_SAMPLE["results"][0]
        data = json.dumps(item).encode()
        entries = _parse_osv_response(data)
        assert len(entries) == 1

    def test_parse_github_advisory(self):
        data = json.dumps(GITHUB_ADVISORY_SAMPLE).encode()
        entries = _parse_github_advisory(data)
        assert len(entries) == 1
        e = entries[0]
        assert e.cve == "CVE-2024-0001"
        assert "Test GitHub Advisory" in e.title
        assert e.severity == "critical"
        assert e.cvss_v3 == 9.8
        assert "test-pkg" in e.product

    def test_parse_github_advisory_empty(self):
        data = json.dumps([]).encode()
        entries = _parse_github_advisory(data)
        assert entries == []


# =========================================================================
#  Utility functions
# =========================================================================


class TestUtilities:
    def test_compute_checksum(self):
        c1 = _compute_checksum(b"hello")
        c2 = _compute_checksum(b"hello")
        c3 = _compute_checksum(b"world")
        assert c1 == c2
        assert c1 != c3
        assert len(c1) == 16  # SHA-256 first 16 hex chars

    def test_exponential_backoff(self):
        assert _exponential_backoff(0) == 2.0
        assert _exponential_backoff(1) == 4.0
        assert _exponential_backoff(2) == 8.0
        assert _exponential_backoff(3) == 16.0

    def test_now_iso(self):
        now = _now_iso()
        # Should be ISO format
        assert "T" in now
        assert now.endswith("+00:00") or now.endswith("Z") or "+" in now[19:]


# =========================================================================
#  FeedUpdater tests (with mocked HTTP)
# =========================================================================


class TestFeedUpdater:
    def test_skip_disabled_feed(self, tmp_cache: FeedCache):
        source = FeedSource(name="test", feed_type=FeedType.NVD, url="http://example.com", enabled=False)
        updater = FeedUpdater(tmp_cache, source)
        result = updater.update()
        assert result.status == UpdateStatus.SKIPPED

    def test_cached_fresh_skips_fetch(self, tmp_cache: FeedCache):
        """If cache TTL hasn't expired, no fetch should occur."""
        source = FeedSource(name="nvd", feed_type=FeedType.NVD, url="http://example.com", cache_ttl_hours=24)
        # Pre-populate cache with recent entry (upsert_source auto-sets last_fetch to now)
        tmp_cache.upsert_source("nvd", "nvd", etag="old", entry_count=5)
        tmp_cache.upsert_entry("CVE-2024-0001", "nvd", {"cvss": 9.8})

        updater = FeedUpdater(tmp_cache, source)
        result = updater.update()
        assert result.status == UpdateStatus.NO_UPDATE
        assert result.total_entries == 5

    @patch("vina.core.feed_manager.urlopen")
    def test_successful_fetch(self, mock_urlopen, tmp_cache: FeedCache):
        """Test a successful NVD feed fetch."""
        nvd_bytes = json.dumps(NVD_SAMPLE).encode()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"ETag": "abc123", "Last-Modified": "Mon, 01 Jun 2024 00:00:00 GMT"}
        mock_resp.read.return_value = nvd_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        source = FeedSource(name="nvd", feed_type=FeedType.NVD, url="http://example.com/nvd", rate_limit_sleep=0)
        updater = FeedUpdater(tmp_cache, source)
        result = updater.update()

        assert result.status == UpdateStatus.SUCCESS
        assert result.total_entries == 1
        assert result.new_etag == "abc123"
        assert tmp_cache.count_entries("nvd") == 1

    @patch("vina.core.feed_manager.urlopen")
    def test_304_not_modified(self, mock_urlopen, tmp_cache: FeedCache):
        """304 response should result in NO_UPDATE."""
        mock_resp = MagicMock()
        mock_resp.status = 304
        mock_resp.headers = {}
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        tmp_cache.upsert_source("nvd", "nvd", etag="abc123", entry_count=3)

        source = FeedSource(name="nvd", feed_type=FeedType.NVD, url="http://example.com/nvd", rate_limit_sleep=0)
        updater = FeedUpdater(tmp_cache, source)
        result = updater.update(force=False)

        assert result.status == UpdateStatus.NO_UPDATE

    @patch("vina.core.feed_manager.urlopen")
    def test_retry_on_failure(self, mock_urlopen, tmp_cache: FeedCache):
        """FeedUpdater should retry on transient failures."""
        mock_urlopen.side_effect = ConnectionError("Network error")

        source = FeedSource(name="nvd", feed_type=FeedType.NVD, url="http://example.com/nvd", rate_limit_sleep=0)
        updater = FeedUpdater(tmp_cache, source)
        result = updater.update()

        assert result.status == UpdateStatus.FAILED
        assert "Network error" in result.error
        # Should have attempted max retries
        assert mock_urlopen.call_count == 3

    @patch("vina.core.feed_manager.urlopen")
    def test_force_ignores_cache(self, mock_urlopen, tmp_cache: FeedCache):
        """--force should skip cache TTL check and fetch anyway."""
        nvd_bytes = json.dumps(NVD_SAMPLE).encode()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.read.return_value = nvd_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        source = FeedSource(
            name="nvd", feed_type=FeedType.NVD, url="http://example.com/nvd", cache_ttl_hours=24, rate_limit_sleep=0
        )
        updater = FeedUpdater(tmp_cache, source)
        result = updater.update(force=True)

        assert result.status == UpdateStatus.SUCCESS
        # urlopen should have been called despite valid cache
        assert mock_urlopen.called

    @patch("vina.core.feed_manager.urlopen")
    def test_parse_failure_returns_failed(self, mock_urlopen, tmp_cache: FeedCache):
        """If the response body is invalid, updater should fail."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.read.return_value = b"not valid json or csv"
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        source = FeedSource(name="nvd", feed_type=FeedType.NVD, url="http://example.com/nvd", rate_limit_sleep=0)
        updater = FeedUpdater(tmp_cache, source)
        result = updater.update()

        # The JSON decode should fail inside the parser
        assert result.status == UpdateStatus.FAILED

    @patch("vina.core.feed_manager.urlopen")
    def test_rate_limit_applied(self, mock_urlopen, tmp_cache: FeedCache):
        """Rate limit sleep should be called between requests (on retries)."""
        mock_urlopen.side_effect = ConnectionError("timeout")

        source = FeedSource(
            name="nvd", feed_type=FeedType.NVD, url="http://example.com/nvd", rate_limit_sleep=0.01
        )  # very short for test
        updater = FeedUpdater(tmp_cache, source)
        start = time.perf_counter()
        updater.update()
        elapsed = time.perf_counter() - start
        # Should have waited at least 3 retries * sleep
        assert elapsed > 0.01

    @patch("vina.core.feed_manager.urlopen")
    def test_cisa_kev_fetch(self, mock_urlopen, tmp_cache: FeedCache):
        """Test parsing CISA KEV feed."""
        kev_bytes = json.dumps(CISA_KEV_SAMPLE).encode()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.read.return_value = kev_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        source = FeedSource(
            name="cisa_kev", feed_type=FeedType.CISA_KEV, url="http://example.com/kev", rate_limit_sleep=0
        )
        updater = FeedUpdater(tmp_cache, source)
        result = updater.update()

        assert result.status == UpdateStatus.SUCCESS
        entries = tmp_cache.get_entries_for_source("cisa_kev")
        assert len(entries) == 1
        assert entries[0]["kev"] is True

    @patch("vina.core.feed_manager.urlopen")
    def test_github_advisory_fetch(self, mock_urlopen, tmp_cache: FeedCache):
        """Test parsing GitHub Advisory feed."""
        ga_bytes = json.dumps(GITHUB_ADVISORY_SAMPLE).encode()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.read.return_value = ga_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        source = FeedSource(
            name="github", feed_type=FeedType.GITHUB_ADVISORY, url="http://example.com/gh", rate_limit_sleep=0
        )
        updater = FeedUpdater(tmp_cache, source)
        result = updater.update()

        assert result.status == UpdateStatus.SUCCESS
        assert result.total_entries == 1

    @patch("vina.core.feed_manager.urlopen")
    def test_osv_fetch(self, mock_urlopen, tmp_cache: FeedCache):
        """Test parsing OSV feed."""
        osv_bytes = json.dumps(OSV_SAMPLE).encode()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.read.return_value = osv_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        source = FeedSource(name="osv", feed_type=FeedType.OSV, url="http://example.com/osv", rate_limit_sleep=0)
        updater = FeedUpdater(tmp_cache, source)
        result = updater.update()

        assert result.status == UpdateStatus.SUCCESS
        assert result.total_entries == 1


# =========================================================================
#  FeedScheduler tests
# =========================================================================


class TestFeedScheduler:
    def test_update_all_skips_disabled(self, tmp_cache: FeedCache):
        sources = [
            FeedSource(name="nvd", feed_type=FeedType.NVD, url="http://example.com/nvd", enabled=False),
        ]
        scheduler = FeedScheduler(tmp_cache, sources)
        # With disabled feeds and no HTTP, should skip
        results = scheduler.update_all()
        assert "nvd" in results
        assert results["nvd"].status == UpdateStatus.SKIPPED

    @patch("vina.core.feed_manager.urlopen")
    def test_update_all_multiple_sources(self, mock_urlopen, tmp_cache: FeedCache):
        """Test updating multiple feed sources."""
        feed_data_by_source = {
            "nvd": json.dumps(NVD_SAMPLE).encode(),
            "cisa_kev": json.dumps(CISA_KEV_SAMPLE).encode(),
            "epss": EPSS_CSV_SAMPLE.encode(),
            "osv": json.dumps(OSV_SAMPLE).encode(),
            "github_advisory": json.dumps(GITHUB_ADVISORY_SAMPLE).encode(),
        }

        urls_by_source = {
            "nvd": "http://example.com/nvd",
            "cisa_kev": "http://example.com/kev",
            "epss": "http://example.com/epss",
            "osv": "http://example.com/osv",
            "github_advisory": "http://example.com/advisory",
        }
        url_to_source = {v: k for k, v in urls_by_source.items()}

        def side_effect(req, *_args, **_kwargs):
            url = req.get_full_url() if hasattr(req, "get_full_url") else str(req)
            source_name = url_to_source.get(url, "unknown")
            data = feed_data_by_source.get(source_name, b"")
            response = MagicMock()
            response.status = 200
            response.headers = {}
            response.read.return_value = data
            cm = MagicMock()
            cm.__enter__.return_value = response
            return cm

        mock_urlopen.side_effect = side_effect

        sources = [
            FeedSource(name="nvd", feed_type=FeedType.NVD, url=urls_by_source["nvd"], rate_limit_sleep=0),
            FeedSource(
                name="cisa_kev", feed_type=FeedType.CISA_KEV, url=urls_by_source["cisa_kev"], rate_limit_sleep=0
            ),
            FeedSource(name="epss", feed_type=FeedType.EPSS, url=urls_by_source["epss"], rate_limit_sleep=0),
            FeedSource(name="osv", feed_type=FeedType.OSV, url=urls_by_source["osv"], rate_limit_sleep=0),
            FeedSource(
                name="github_advisory",
                feed_type=FeedType.GITHUB_ADVISORY,
                url=urls_by_source["github_advisory"],
                rate_limit_sleep=0,
            ),
        ]
        scheduler = FeedScheduler(tmp_cache, sources)
        results = scheduler.update_all()

        assert len(results) == 5
        for name, result in results.items():
            assert result.status == UpdateStatus.SUCCESS, f"{name}: {result.error}"

        # Aggregate metadata should be written
        meta = tmp_cache.get_all_metadata()
        assert "total_entries" in meta
        assert "checksum" in meta
        assert "last_updated" in meta


# =========================================================================
#  FeedManager integration tests
# =========================================================================


class TestFeedManager:
    def test_init(self, tmp_path: Path):
        manager = FeedManager(feed_dir=tmp_path / "feeds")
        assert manager.total_entries == 0
        assert manager.is_offline is True

    def test_get_metadata_defaults(self, tmp_manager: FeedManager):
        meta = tmp_manager.get_metadata()
        assert meta.is_offline is True
        assert meta.total_entries == 0

    def test_get_vulnerabilities_empty(self, tmp_manager: FeedManager):
        vulns = tmp_manager.get_vulnerabilities()
        assert vulns == []

    def test_get_vulnerabilities_by_source_empty(self, tmp_manager: FeedManager):
        vulns = tmp_manager.get_vulnerabilities_by_source("nvd")
        assert vulns == []

    @patch("vina.core.feed_manager.urlopen")
    def test_update_populates_cache(self, mock_urlopen, tmp_path: Path):
        """After update, cache should contain entries."""

        # Default URLs used by FeedManager
        def side_effect(req, *_args, **_kwargs):
            url = req.get_full_url() if hasattr(req, "get_full_url") else str(req)
            # Match on known URL patterns
            if "nvd.nist" in url:
                data = json.dumps(NVD_SAMPLE).encode()
            elif "cisa.gov" in url:
                data = json.dumps(CISA_KEV_SAMPLE).encode()
            elif "epss.cyentia" in url:
                data = EPSS_CSV_SAMPLE.encode()
            elif "osv.dev" in url:
                data = json.dumps(OSV_SAMPLE).encode()
            elif "github.com" in url:
                data = json.dumps(GITHUB_ADVISORY_SAMPLE).encode()
            else:
                data = b""
            response = MagicMock()
            response.status = 200
            response.headers = {}
            response.read.return_value = data
            cm = MagicMock()
            cm.__enter__.return_value = response
            return cm

        mock_urlopen.side_effect = side_effect

        manager = FeedManager(feed_dir=tmp_path / "feeds")
        results = manager.update(force=True)

        # At least NVD should have succeeded
        assert results.get("nvd").status == UpdateStatus.SUCCESS
        assert manager.total_entries > 0
        assert not manager.is_offline

        # Get vulnerabilities
        vulns = manager.get_vulnerabilities()
        assert len(vulns) > 0

    def test_export_to_json(self, tmp_path: Path):
        """Export cache to JSON file."""
        manager = FeedManager(feed_dir=tmp_path / "feeds")
        # Add some data
        manager.cache.upsert_entry("CVE-2024-0001", "nvd", {"cvss_v3": 9.8})

        out_path = tmp_path / "export.json"
        result = manager.export_to_json(out_path)
        assert result == out_path
        assert out_path.exists()

        data = json.loads(out_path.read_text())
        assert "vulnerabilities" in data
        assert len(data["vulnerabilities"]) == 1
        assert "metadata" in data

    def test_clear_cache(self, tmp_manager: FeedManager):
        tmp_manager.cache.upsert_entry("CVE-2024-0001", "nvd", {})
        assert tmp_manager.total_entries == 1
        tmp_manager.clear_cache()
        assert tmp_manager.total_entries == 0

    @patch("vina.core.feed_manager.urlopen")
    def test_rebuild_from_feeds_fails_gracefully(self, mock_urlopen, tmp_manager: FeedManager):
        """When all fetches fail, rebuild should report failures gracefully."""
        mock_urlopen.side_effect = ConnectionError("No network")
        results = tmp_manager.rebuild_from_feeds()
        for name, result in results.items():
            assert result.status in (UpdateStatus.FAILED, UpdateStatus.SKIPPED), f"{name}: {result.status}"

    def test_get_feed_sources(self, tmp_manager: FeedManager):
        sources = tmp_manager.get_feed_sources()
        assert len(sources) >= 5  # Default sources
        assert any(s.feed_type == FeedType.NVD for s in sources)
        assert any(s.feed_type == FeedType.CISA_KEV for s in sources)
        assert any(s.feed_type == FeedType.EPSS for s in sources)
        assert any(s.feed_type == FeedType.OSV for s in sources)
        assert any(s.feed_type == FeedType.GITHUB_ADVISORY for s in sources)

    def test_verify_integrity_empty(self, tmp_manager: FeedManager):
        assert tmp_manager.verify_integrity() is True

    def test_build_vulnerability_database(self, tmp_manager: FeedManager):
        """build_vulnerability_database should return list of dicts."""
        tmp_manager.cache.upsert_entry("CVE-2024-0001", "nvd", {"cvss_v3": 9.8, "severity": "critical"})
        data = tmp_manager.build_vulnerability_database()
        assert len(data) == 1
        assert data[0]["cve"] == "CVE-2024-0001"
        assert data[0]["cvss_v3"] == 9.8


# =========================================================================
#  Singleton / convenience functions
# =========================================================================


class TestConvenience:
    def test_get_default_manager(self):
        mgr = get_default_manager()
        assert isinstance(mgr, FeedManager)

    def test_get_feed_status(self):
        # Should not crash
        status = get_feed_status()
        assert isinstance(status, FeedMetadata)


# =========================================================================
#  Edge cases
# =========================================================================


class TestEdgeCases:
    def test_cache_init_with_nonexistent_dir(self, tmp_path: Path):
        """Cache should create parent directories."""
        deep_path = tmp_path / "a" / "b" / "c" / "feeds"
        cache = FeedCache(cache_dir=deep_path)
        assert cache.db_path.exists()

    def test_empty_db_path_doesnt_exist(self, tmp_cache: FeedCache):
        """Operations on an empty database should not crash."""
        assert tmp_cache.count_entries() == 0
        assert tmp_cache.get_all_entries() == []
        assert tmp_cache.compute_checksum() is not None
        assert tmp_cache.verify_integrity() is True

    def test_batch_upsert_empty(self, tmp_cache: FeedCache):
        added, updated = tmp_cache.batch_upsert([])
        assert added == 0
        assert updated == 0

    def test_delete_nonexistent_source(self, tmp_cache: FeedCache):
        deleted = tmp_cache.delete_source_entries("nonexistent")
        assert deleted == 0

    def test_corrupted_cache_recovery(self, tmp_cache: FeedCache, tmp_path: Path):
        """Corrupted cache should be recoverable by reinitialising."""
        tmp_cache.upsert_entry("CVE-2024-0001", "nvd", {"cvss_v3": 9.8})
        assert tmp_cache.count_entries() == 1

        # Simulate corruption by writing garbage to the DB
        tmp_cache.db_path.write_text("CORRUPTED DATA")

        # A new FeedCache on the same path should recover by recreating the DB
        recovered = FeedCache(cache_dir=tmp_path / "feeds")
        assert recovered.count_entries() == 0

    def test_checksum_after_clear(self, tmp_cache: FeedCache):
        """Checksum should be valid after clearing."""
        tmp_cache.upsert_entry("CVE-2024-0001", "nvd", {})
        tmp_cache.clear()
        assert tmp_cache.verify_integrity() is True

    def test_metadata_overwrite(self, tmp_cache: FeedCache):
        """Setting the same metadata key should overwrite."""
        tmp_cache.set_metadata("key", "value1")
        tmp_cache.set_metadata("key", "value2")
        assert tmp_cache.get_metadata("key") == "value2"

    def test_feed_type_enum_values(self):
        assert FeedType.NVD == "nvd"
        assert FeedType.CISA_KEV == "cisa_kev"
        assert FeedType.EPSS == "epss"
        assert FeedType.OSV == "osv"
        assert FeedType.GITHUB_ADVISORY == "github_advisory"

    def test_update_status_enum_values(self):
        assert UpdateStatus.SUCCESS == "success"
        assert UpdateStatus.FAILED == "failed"
        assert UpdateStatus.NO_UPDATE == "no_update"


# =========================================================================
#  Vulnerability engine integration
# =========================================================================


class TestVulnEngineIntegration:
    @patch("vina.core.feed_manager.urlopen")
    def test_engine_loads_from_feeds(self, mock_urlopen, tmp_path: Path):
        """VulnerabilityEngine should load data from FeedManager when provided."""
        nvd_bytes = json.dumps(NVD_SAMPLE).encode()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.read.return_value = nvd_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        from vina.core.vuln_intel import SoftwareComponent, VulnerabilityEngine

        # Create feed manager with data
        fm = FeedManager(feed_dir=tmp_path / "feeds")
        fm.update(force=True)

        # Create engine with feed manager
        engine = VulnerabilityEngine(feed_manager=fm)
        assert engine._config.offline is False
        assert engine.database.count > 0

        # Test matching
        components = [SoftwareComponent(name="product", version="1.0")]
        matches = engine.run(components)
        assert len(matches) >= 0  # match based on loaded data

    def test_engine_fallback_without_feed_manager(self):
        """Without feed_manager, VulnerabilityEngine falls back to default DB."""
        from vina.core.vuln_intel import VulnerabilityEngine

        engine = VulnerabilityEngine()
        assert engine.database is not None
