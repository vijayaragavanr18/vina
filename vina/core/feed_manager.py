"""Live Vulnerability Intelligence Update System for VINA.

Manages multiple external vulnerability feed providers with incremental
updates, automatic cache validation, offline mode, rate limiting, retry
with exponential backoff, ETag/Last-Modified support, and a local SQLite
cache.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import sqlite3
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

DEFAULT_FEED_DIR = Path.home() / ".vina" / "feeds"
DEFAULT_CACHE_TTL_HOURS = 6
DEFAULT_RATE_LIMIT_SLEEP = 1.5
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2.0
MAX_RESPONSE_BYTES = 50 * 1024 * 1024  # 50 MB
HTTP_TIMEOUT = 60

# Feed source URLs (official)
NVD_FEED_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
OSV_URL = "https://api.osv.dev/v1/query"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"

SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
#  Enums & models
# ---------------------------------------------------------------------------


class FeedType(StrEnum):
    NVD = "nvd"
    CISA_KEV = "cisa_kev"
    EPSS = "epss"
    OSV = "osv"
    GITHUB_ADVISORY = "github_advisory"


class UpdateStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    NO_UPDATE = "no_update"
    PARTIAL = "partial"


@dataclass(slots=True)
class FeedSource:
    """Configuration for a single vulnerability feed source."""

    name: str
    feed_type: FeedType
    url: str
    enabled: bool = True
    etag: str = ""
    last_modified: str = ""
    cache_ttl_hours: int = DEFAULT_CACHE_TTL_HOURS
    retry_count: int = 0
    rate_limit_sleep: float = DEFAULT_RATE_LIMIT_SLEEP
    api_key: str = ""
    timeout: int = HTTP_TIMEOUT
    max_response_bytes: int = MAX_RESPONSE_BYTES
    format: str = "json"  # json, csv, csv_gz


@dataclass(slots=True)
class FeedEntry:
    """A single entry from any vulnerability feed, normalized."""

    cve: str
    title: str = ""
    description: str = ""
    severity: str = "medium"
    cvss_v3: float = 0.0
    cvss_v4: float = 0.0
    epss: float = 0.0
    kev: bool = False
    exploited: bool = False
    vendor: str = ""
    product: str = ""
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    published: str = ""
    updated: str = ""
    references: list[str] = field(default_factory=list)
    cwe: str = ""
    mitre_attack: list[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_sources: list[str] = field(default_factory=list)
    confidence: float = 0.8
    source: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_vulnerability(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_v3": self.cvss_v3,
            "cvss_v4": self.cvss_v4,
            "epss": self.epss,
            "kev": self.kev,
            "exploited": self.exploited,
            "vendor": self.vendor,
            "product": self.product,
            "affected_versions": self.affected_versions,
            "fixed_versions": self.fixed_versions,
            "published": self.published,
            "updated": self.updated,
            "references": self.references,
            "cwe": self.cwe,
            "mitre_attack": self.mitre_attack,
            "exploit_available": self.exploit_available,
            "exploit_sources": self.exploit_sources,
            "confidence": self.confidence,
            "source": self.source,
        }


@dataclass(slots=True)
class FeedMetadata:
    """Persistent metadata for the local feed database."""

    db_version: int = SCHEMA_VERSION
    created_at: str = ""
    last_updated: str = ""
    last_update_attempt: str = ""
    update_status: str = "never"
    is_offline: bool = True
    total_entries: int = 0
    feed_versions: dict[str, str] = field(default_factory=dict)
    feed_last_updated: dict[str, str] = field(default_factory=dict)
    feed_entry_counts: dict[str, int] = field(default_factory=dict)
    checksum: str = ""
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "db_version": self.db_version,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "last_update_attempt": self.last_update_attempt,
            "update_status": self.update_status,
            "is_offline": self.is_offline,
            "total_entries": self.total_entries,
            "feed_versions": dict(self.feed_versions),
            "feed_last_updated": dict(self.feed_last_updated),
            "feed_entry_counts": dict(self.feed_entry_counts),
            "checksum": self.checksum,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FeedMetadata:
        return cls(
            db_version=data.get("db_version", SCHEMA_VERSION),
            created_at=data.get("created_at", ""),
            last_updated=data.get("last_updated", ""),
            last_update_attempt=data.get("last_update_attempt", ""),
            update_status=data.get("update_status", "never"),
            is_offline=data.get("is_offline", True),
            total_entries=data.get("total_entries", 0),
            feed_versions=dict(data.get("feed_versions", {})),
            feed_last_updated=dict(data.get("feed_last_updated", {})),
            feed_entry_counts=dict(data.get("feed_entry_counts", {})),
            checksum=data.get("checksum", ""),
        )

    @property
    def feed_age_hours(self) -> float:
        if not self.last_updated:
            return -1.0
        try:
            updated = datetime.fromisoformat(self.last_updated)
            return (datetime.now(UTC) - updated).total_seconds() / 3600
        except (ValueError, TypeError):
            return -1.0


@dataclass(slots=True)
class UpdateResult:
    status: UpdateStatus = UpdateStatus.SUCCESS
    feed_type: str = ""
    entries_added: int = 0
    entries_updated: int = 0
    duration_seconds: float = 0.0
    error: str = ""
    new_etag: str = ""
    new_last_modified: str = ""
    total_entries: int = 0


# ---------------------------------------------------------------------------
#  SQLite-backed feed cache
# ---------------------------------------------------------------------------

_CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS feed_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feed_sources (
    name TEXT PRIMARY KEY,
    feed_type TEXT NOT NULL,
    etag TEXT DEFAULT '',
    last_modified TEXT DEFAULT '',
    last_fetch TEXT,
    entry_count INTEGER DEFAULT 0,
    checksum TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS feed_entries (
    cve TEXT NOT NULL,
    source TEXT NOT NULL,
    data TEXT NOT NULL,
    added_at TEXT NOT NULL,
    checksum TEXT DEFAULT '',
    PRIMARY KEY (cve, source)
);

CREATE INDEX IF NOT EXISTS idx_feed_entries_cve ON feed_entries(cve);
CREATE INDEX IF NOT EXISTS idx_feed_entries_source ON feed_entries(source);

CREATE TABLE IF NOT EXISTS cache_stats (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class FeedCache:
    """SQLite-backed persistent cache for vulnerability feeds.

    Supports atomic writes, checksum validation, and incremental updates.
    """

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._cache_dir = Path(cache_dir) if cache_dir else DEFAULT_FEED_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._cache_dir / "feed_cache.sqlite"
        self._lock = Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            try:
                conn = sqlite3.connect(str(self._db_path), timeout=10)
                conn.executescript(_CACHE_SCHEMA)
                conn.commit()
                conn.close()
            except sqlite3.DatabaseError:
                # Recover from corrupted database by deleting and recreating
                self._db_path.unlink(missing_ok=True)
                conn = sqlite3.connect(str(self._db_path), timeout=10)
                conn.executescript(_CACHE_SCHEMA)
                conn.commit()
                conn.close()

    # -- Metadata operations --

    def get_metadata(self, key: str) -> str | None:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path), timeout=10)
            try:
                cur = conn.execute("SELECT value FROM feed_metadata WHERE key=?", (key,))
                row = cur.fetchone()
                return row[0] if row else None
            finally:
                conn.close()

    def set_metadata(self, key: str, value: str) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path), timeout=10)
            try:
                conn.execute("INSERT OR REPLACE INTO feed_metadata (key, value) VALUES (?, ?)", (key, value))
                conn.commit()
            finally:
                conn.close()

    def get_all_metadata(self) -> dict[str, str]:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path), timeout=10)
            try:
                cur = conn.execute("SELECT key, value FROM feed_metadata")
                return dict(cur.fetchall())
            finally:
                conn.close()

    # -- Feed source operations --

    def get_source(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path), timeout=10)
            try:
                cur = conn.execute(
                    "SELECT name, feed_type, etag, last_modified, last_fetch, entry_count, checksum "
                    "FROM feed_sources WHERE name=?",
                    (name,),
                )
                row = cur.fetchone()
                if row:
                    return {
                        "name": row[0],
                        "feed_type": row[1],
                        "etag": row[2],
                        "last_modified": row[3],
                        "last_fetch": row[4],
                        "entry_count": row[5],
                        "checksum": row[6],
                    }
                return None
            finally:
                conn.close()

    def upsert_source(
        self,
        name: str,
        feed_type: str,
        etag: str = "",
        last_modified: str = "",
        entry_count: int = 0,
        checksum: str = "",
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            conn = sqlite3.connect(str(self._db_path), timeout=10)
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO feed_sources "
                    "(name, feed_type, etag, last_modified, last_fetch, entry_count, checksum) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (name, feed_type, etag, last_modified, now, entry_count, checksum),
                )
                conn.commit()
            finally:
                conn.close()

    # -- Feed entries operations --

    def get_entries_for_source(self, source: str) -> list[dict[str, Any]]:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path), timeout=10)
            try:
                cur = conn.execute("SELECT cve, data FROM feed_entries WHERE source=?", (source,))
                results = []
                for cve, data_str in cur:
                    entry = json.loads(data_str)
                    entry["cve"] = cve
                    results.append(entry)
                return results
            finally:
                conn.close()

    def get_all_entries(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path), timeout=10)
            try:
                cur = conn.execute("SELECT cve, data FROM feed_entries")
                results = []
                for cve, data_str in cur:
                    entry = json.loads(data_str)
                    entry["cve"] = cve
                    results.append(entry)
                return results
            finally:
                conn.close()

    def upsert_entry(self, cve: str, source: str, data: dict[str, Any]) -> bool:
        """Insert or update a feed entry. Returns True if new, False if updated."""
        now = datetime.now(UTC).isoformat()
        data_str = json.dumps(data, default=str)
        checksum = hashlib.sha256(data_str.encode()).hexdigest()[:16]
        with self._lock:
            conn = sqlite3.connect(str(self._db_path), timeout=10)
            try:
                cur = conn.execute("SELECT checksum FROM feed_entries WHERE cve=? AND source=?", (cve, source))
                existing = cur.fetchone()
                is_new = existing is None
                conn.execute(
                    "INSERT OR REPLACE INTO feed_entries (cve, source, data, added_at, checksum) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (cve, source, data_str, now, checksum),
                )
                conn.commit()
                return is_new
            finally:
                conn.close()

    def batch_upsert(self, entries: list[tuple[str, str, dict[str, Any]]]) -> tuple[int, int]:
        """Batch upsert entries. Returns (added, updated)."""
        added = 0
        updated = 0
        for cve, source, data in entries:
            if self.upsert_entry(cve, source, data):
                added += 1
            else:
                updated += 1
        return added, updated

    def delete_source_entries(self, source: str) -> int:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path), timeout=10)
            try:
                cur = conn.execute("DELETE FROM feed_entries WHERE source=?", (source,))
                deleted = cur.rowcount
                conn.commit()
                return deleted
            finally:
                conn.close()

    def count_entries(self, source: str | None = None) -> int:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path), timeout=10)
            try:
                if source:
                    cur = conn.execute("SELECT COUNT(*) FROM feed_entries WHERE source=?", (source,))
                else:
                    cur = conn.execute("SELECT COUNT(*) FROM feed_entries")
                return cast(int, cur.fetchone()[0])
            finally:
                conn.close()

    # -- Checksum & integrity --

    def compute_checksum(self) -> str:
        """Compute a SHA-256 checksum of all entries for integrity verification."""
        entries = self.get_all_entries()
        ordered = sorted(json.dumps(e, sort_keys=True, default=str) for e in entries)
        return hashlib.sha256("".join(ordered).encode()).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify the stored checksum matches the computed checksum."""
        stored = self.get_metadata("checksum")
        if not stored:
            return True
        return self.compute_checksum() == stored

    def clear(self) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path), timeout=10)
            try:
                conn.executescript("DELETE FROM feed_entries; DELETE FROM feed_sources; DELETE FROM feed_metadata;")
                conn.commit()
            finally:
                conn.close()

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def size_bytes(self) -> int:
        try:
            return self._db_path.stat().st_size
        except OSError:
            return 0

    def get_feed_versions(self) -> dict[str, str]:
        versions: dict[str, str] = {}
        raw = self.get_metadata("feed_versions")
        if raw:
            with contextlib.suppress(json.JSONDecodeError, TypeError):
                versions = json.loads(raw)
        for ft in FeedType:
            ts = self.get_metadata(f"feed_{ft.value}_updated")
            if ts:
                versions[ft.value] = ts
        return versions


# ---------------------------------------------------------------------------
#  HTTP helpers
# ---------------------------------------------------------------------------


def _make_request(
    url: str, etag: str = "", last_modified: str = "", api_key: str = "", _timeout: int = HTTP_TIMEOUT
) -> Request:
    headers: dict[str, str] = {
        "User-Agent": "VINA/2.1 (Security Scanner; +https://vina.security)",
        "Accept": "application/json",
    }
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    if api_key:
        headers["apiKey"] = api_key
    return Request(url, headers=headers)


def _fetch_url(
    request: Request, timeout: int = HTTP_TIMEOUT, max_bytes: int = MAX_RESPONSE_BYTES
) -> tuple[bytes, str, str, int]:
    """Fetch a URL with retry support.

    Returns (body_bytes, etag, last_modified, status_code).
    """
    try:
        with urlopen(request, timeout=timeout) as resp:  # nosec: B310
            status = resp.status
            etag = resp.headers.get("ETag", "")
            last_modified = resp.headers.get("Last-Modified", "")
            body = resp.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise ValueError(f"Response exceeds {max_bytes} byte limit")
            return body, etag, last_modified, status
    except HTTPError as exc:
        if exc.code == 304:
            return b"", "", "", 304
        raise
    except URLError as exc:
        raise ConnectionError(f"Failed to connect to {request.full_url}: {exc.reason}") from exc


def _compute_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _exponential_backoff(attempt: int, base: float = RETRY_BACKOFF_BASE) -> float:
    return cast(float, base * (2**attempt))


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
#  Feed-specific parsers
# ---------------------------------------------------------------------------


def _parse_nvd_response(data: bytes) -> list[FeedEntry]:
    """Parse NVD CVE JSON 2.0 response into FeedEntry list."""
    raw = json.loads(data.decode("utf-8"))
    entries: list[FeedEntry] = []
    for item in raw.get("vulnerabilities", []):
        cve_data = item.get("cve", item)
        cve_id = cve_data.get("id", "")
        if not cve_id:
            continue

        descriptions = cve_data.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        metrics = cve_data.get("metrics", {})
        cvss_v3 = 0.0
        severity = "medium"
        for key in ("cvssMetricV31", "cvssMetricV30"):
            for m in metrics.get(key, []):
                cvss_data = m.get("cvssData", {})
                cvss_v3 = float(cvss_data.get("baseScore", 0))
                sev = cvss_data.get("baseSeverity", "").lower()
                if sev:
                    severity = sev
                break
            if cvss_v3:
                break
        if not cvss_v3:
            for m in metrics.get("cvssMetricV2", []):
                cvss_data = m.get("cvssData", {})
                cvss_v3 = float(cvss_data.get("baseScore", 0))

        cpe = cve_data.get("configurations", [])
        vendor = ""
        product = ""
        affected: list[str] = []
        fixed: list[str] = []
        for config in cpe:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                    version_start = match.get("versionStartIncluding", match.get("versionStartExcluding", ""))
                    version_end = match.get("versionEndIncluding", match.get("versionEndExcluding", ""))
                    if version_start and version_end:
                        affected.append(f">={version_start},<={version_end}")
                    elif version_start:
                        affected.append(f">={version_start}")
                    elif version_end:
                        affected.append(f"<={version_end}")
                    if match.get("versionEndExcluding"):
                        fixed.append(match["versionEndExcluding"])

        references = []
        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)

        entries.append(
            FeedEntry(
                cve=cve_id,
                title=cve_data.get("sourceIdentifier", ""),
                description=description,
                severity=severity,
                cvss_v3=cvss_v3,
                vendor=vendor,
                product=product,
                affected_versions=affected,
                fixed_versions=fixed,
                published=cve_data.get("published", ""),
                updated=cve_data.get("lastModified", ""),
                references=references,
                source="nvd",
                confidence=0.85,
                raw=cve_data,
            )
        )
    return entries


def _parse_cisa_kev(data: bytes) -> list[FeedEntry]:
    """Parse CISA KEV catalog into FeedEntry list."""
    raw = json.loads(data.decode("utf-8"))
    entries: list[FeedEntry] = []
    for item in raw.get("vulnerabilities", []):
        cve_id = item.get("cveID", "")
        if not cve_id:
            continue
        entries.append(
            FeedEntry(
                cve=cve_id,
                title=item.get("vulnerabilityName", ""),
                description=item.get("shortDescription", ""),
                severity="critical",
                kev=True,
                exploited=True,
                vendor=item.get("vendorProject", ""),
                product=item.get("product", ""),
                published=item.get("dateAdded", ""),
                updated=item.get("dateAdded", ""),
                references=[r for r in [item.get("notes", "")] if r],
                exploit_available=True,
                exploit_sources=["cisa_kev"],
                source="cisa_kev",
                confidence=0.95,
                raw=item,
            )
        )
    return entries


def _parse_epss_csv(data: bytes) -> list[FeedEntry]:
    """Parse EPSS CSV (possibly gzipped) into FeedEntry list."""
    try:
        import gzip

        raw_text = gzip.decompress(data).decode("utf-8")
    except (OSError, zlib.error):
        raw_text = data.decode("utf-8")

    entries: list[FeedEntry] = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("cve"):
            continue
        parts = line.split(",")
        if len(parts) < 2:
            continue
        cve_id = parts[0].strip().strip('"')
        if not cve_id.startswith("CVE-"):
            continue
        try:
            epss = float(parts[1].strip().strip('"'))
        except (ValueError, IndexError):
            epss = 0.0
        entries.append(
            FeedEntry(cve=cve_id, epss=epss, severity="info", source="epss", confidence=0.9, raw={"epss": epss})
        )
    return entries


def _parse_osv_response(data: bytes) -> list[FeedEntry]:
    """Parse OSV API response into FeedEntry list."""
    raw = json.loads(data.decode("utf-8"))
    entries: list[FeedEntry] = []
    items = raw if isinstance(raw, list) else raw.get("results", [raw])
    for item in items:
        cve_id = item.get("id", "")
        if not cve_id or not cve_id.startswith("CVE-"):
            continue
        aliases = item.get("aliases", [])
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        severity = "medium"
        for sev_ref in item.get("severity", []):
            sev_type = sev_ref.get("type", "")
            score = sev_ref.get("score", "")
            if sev_type == "CVSS_V3" and score:
                try:
                    s = float(score)
                    if s >= 9.0:
                        severity = "critical"
                    elif s >= 7.0:
                        severity = "high"
                    elif s >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"
                except (ValueError, TypeError):
                    pass

        affects = item.get("affected", [])
        packages = []
        affected_versions = []
        for aff in affects:
            pkg = aff.get("package", {})
            packages.append(pkg.get("name", ""))
            for r in aff.get("ranges", []):
                for ev in r.get("events", []):
                    if "introduced" in ev:
                        affected_versions.append(f">={ev['introduced']}")
                    if "fixed" in ev:
                        affected_versions.append(f"<{ev['fixed']}")

        references = []
        for ref in item.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)

        entries.append(
            FeedEntry(
                cve=cve_id,
                title=item.get("summary", ""),
                description=item.get("details", ""),
                severity=severity,
                vendor="",
                product=", ".join(packages) if packages else "",
                affected_versions=affected_versions,
                published=item.get("published", ""),
                updated=item.get("modified", ""),
                references=references,
                source="osv",
                confidence=0.8,
                raw=item,
            )
        )
    return entries


def _parse_github_advisory(data: bytes) -> list[FeedEntry]:
    """Parse GitHub Security Advisory API response into FeedEntry list."""
    raw = json.loads(data.decode("utf-8"))
    items = raw if isinstance(raw, list) else [raw]
    entries: list[FeedEntry] = []
    for item in items:
        cve_id = item.get("cve_id", "")
        if not cve_id:
            for ident in item.get("identifiers", []):
                if ident.get("type") == "CVE":
                    cve_id = ident.get("value", "")
                    break
        if not cve_id:
            continue

        cvss_score = 0.0
        severity = "medium"
        cvss = item.get("cvss", {})
        if cvss:
            cvss_score = float(cvss.get("score", 0))
            sev = cvss.get("severity", "").lower()
            if sev:
                severity = sev

        references = []
        for ref in item.get("references", []):
            url = ref if isinstance(ref, str) else ref.get("url", "")
            if url:
                references.append(url)

        vulnerabilities = item.get("vulnerabilities", [])
        vendor = ""
        product = ""
        affected_versions: list[str] = []
        fixed_versions: list[str] = []
        for vuln in vulnerabilities:
            pkg = vuln.get("package", {})
            vendor = pkg.get("ecosystem", "")
            product = pkg.get("name", "")
            for r in vuln.get("vulnerableVersionRange", "").split(","):
                r = r.strip()
                if r:
                    affected_versions.append(r)

        entries.append(
            FeedEntry(
                cve=cve_id,
                title=item.get("summary", ""),
                description=item.get("description", ""),
                severity=severity,
                cvss_v3=cvss_score,
                vendor=vendor,
                product=product,
                affected_versions=affected_versions,
                fixed_versions=fixed_versions,
                published=item.get("published_at", ""),
                updated=item.get("updated_at", ""),
                references=references,
                source="github_advisory",
                confidence=0.85,
                raw=item,
            )
        )
    return entries


_FEED_PARSERS: dict[FeedType, Callable[[bytes], list[FeedEntry]]] = {
    FeedType.NVD: _parse_nvd_response,
    FeedType.CISA_KEV: _parse_cisa_kev,
    FeedType.EPSS: _parse_epss_csv,
    FeedType.OSV: _parse_osv_response,
    FeedType.GITHUB_ADVISORY: _parse_github_advisory,
}


# ---------------------------------------------------------------------------
#  FeedUpdater
# ---------------------------------------------------------------------------


class FeedUpdater:
    """Fetches a single feed source with rate limiting, retry, and caching."""

    def __init__(self, cache: FeedCache, source: FeedSource) -> None:
        self._cache = cache
        self._source = source
        self._logger = logging.getLogger(f"{__name__}.updater.{source.name}")

    def update(self, force: bool = False) -> UpdateResult:
        result = UpdateResult(feed_type=self._source.feed_type.value)
        start = time.perf_counter()

        if not self._source.enabled:
            result.status = UpdateStatus.SKIPPED
            result.error = "feed disabled"
            return result

        # Check cache validity
        if not force:
            cached = self._cache.get_source(self._source.name)
            if cached and cached.get("last_fetch"):
                try:
                    last = datetime.fromisoformat(cached["last_fetch"])
                    age_hours = (datetime.now(UTC) - last).total_seconds() / 3600
                    if age_hours < self._source.cache_ttl_hours:
                        result.status = UpdateStatus.NO_UPDATE
                        result.total_entries = cached.get("entry_count", 0)
                        return result
                except (ValueError, TypeError):
                    pass

        # Fetch with retry
        etag = self._source.etag
        last_modified = self._source.last_modified
        last_error: Exception | None = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                if attempt > 1:
                    sleep_time = _exponential_backoff(attempt - 1)
                    self._logger.debug("Retry %d/%d after %.1fs", attempt, MAX_RETRIES, sleep_time)
                    time.sleep(sleep_time)

                request = _make_request(
                    self._source.url,
                    etag=etag,
                    last_modified=last_modified,
                    api_key=self._source.api_key,
                    _timeout=self._source.timeout,
                )
                body, new_etag, new_last_modified, status = _fetch_url(
                    request, timeout=self._source.timeout, max_bytes=self._source.max_response_bytes
                )

                if status == 304:
                    # Not modified - update last_fetch timestamp
                    cached = self._cache.get_source(self._source.name)
                    entry_count = cached.get("entry_count", 0) if cached else 0
                    self._cache.upsert_source(
                        name=self._source.name,
                        feed_type=self._source.feed_type.value,
                        etag=new_etag or etag,
                        last_modified=new_last_modified or last_modified,
                        entry_count=entry_count,
                    )
                    result.status = UpdateStatus.NO_UPDATE
                    result.total_entries = entry_count
                    result.new_etag = new_etag or etag
                    result.new_last_modified = new_last_modified or last_modified
                    return result

                # Rate limit
                if self._source.rate_limit_sleep > 0:
                    time.sleep(self._source.rate_limit_sleep)

                # Parse
                parser = _FEED_PARSERS.get(self._source.feed_type)
                if not parser:
                    result.status = UpdateStatus.FAILED
                    result.error = f"no parser for {self._source.feed_type}"
                    return result

                entries = parser(body)

                # Clear old entries for this source, then batch insert
                self._cache.count_entries(self._source.name)
                self._cache.delete_source_entries(self._source.name)
                batch = [(e.cve, self._source.name, e.to_vulnerability()) for e in entries if e.cve]
                added, updated = self._cache.batch_upsert(batch)

                checksum = _compute_checksum(body)
                self._cache.upsert_source(
                    name=self._source.name,
                    feed_type=self._source.feed_type.value,
                    etag=new_etag or etag,
                    last_modified=new_last_modified or last_modified,
                    entry_count=len(batch),
                    checksum=checksum,
                )

                result.status = UpdateStatus.SUCCESS
                result.entries_added = len(batch)
                result.entries_updated = 0
                result.total_entries = len(batch)
                result.new_etag = new_etag or etag
                result.new_last_modified = new_last_modified or last_modified

                # Update metadata timestamps
                self._cache.set_metadata(f"feed_{self._source.feed_type.value}_updated", _now_iso())
                self._cache.set_metadata(f"feed_{self._source.feed_type.value}_count", str(len(batch)))

                self._logger.info(
                    "Feed '%s': %d entries (%d new, %d replaced) in %.1fs",
                    self._source.name,
                    len(batch),
                    added,
                    updated,
                    time.perf_counter() - start,
                )
                return result

            except (HTTPError, URLError, ConnectionError, OSError, ValueError) as exc:
                last_error = exc
                self._logger.warning("Attempt %d/%d for '%s' failed: %s", attempt, MAX_RETRIES, self._source.name, exc)
                continue

        # All retries exhausted
        result.status = UpdateStatus.FAILED
        result.error = str(last_error) if last_error else "max retries exceeded"
        self._logger.error("Feed '%s' failed after %d attempts: %s", self._source.name, MAX_RETRIES, result.error)
        return result


# ---------------------------------------------------------------------------
#  FeedScheduler
# ---------------------------------------------------------------------------


class FeedScheduler:
    """Orchestrates updates across multiple feed sources.

    Supports dependency ordering (e.g., EPSS may depend on NVD for CVE list)
    and parallel execution of independent feeds.
    """

    def __init__(self, cache: FeedCache, sources: list[FeedSource]) -> None:
        self._cache = cache
        self._sources = {s.name: s for s in sources}

    def update_all(self, force: bool = False) -> dict[str, UpdateResult]:
        """Update all feed sources. Returns mapping of source name to result."""
        results: dict[str, UpdateResult] = {}
        # Order: NVD first (base CVE data), then others
        order = [FeedType.NVD, FeedType.CISA_KEV, FeedType.EPSS, FeedType.OSV, FeedType.GITHUB_ADVISORY]
        ordered_sources = []
        for ft in order:
            for s in self._sources.values():
                if s.feed_type == ft:
                    ordered_sources.append(s)

        for source in ordered_sources:
            updater = FeedUpdater(self._cache, source)
            result = updater.update(force=force)
            results[source.name] = result

        # Update aggregate metadata
        total = self._cache.count_entries()
        checksum = self._cache.compute_checksum()
        self._cache.set_metadata("total_entries", str(total))
        self._cache.set_metadata("checksum", checksum)
        self._cache.set_metadata("last_updated", _now_iso())
        self._cache.set_metadata("is_offline", "false")

        feed_versions = {}
        for ft in FeedType:
            ts = self._cache.get_metadata(f"feed_{ft.value}_updated")
            if ts:
                feed_versions[ft.value] = ts
        self._cache.set_metadata("feed_versions", json.dumps(feed_versions))

        return results

    def update_single(self, source_name: str, force: bool = False) -> UpdateResult | None:
        source = self._sources.get(source_name)
        if not source:
            return None
        updater = FeedUpdater(self._cache, source)
        result = updater.update(force=force)

        # Update aggregate metadata
        total = self._cache.count_entries()
        self._cache.set_metadata("total_entries", str(total))
        self._cache.set_metadata("checksum", self._cache.compute_checksum())
        return result


# ---------------------------------------------------------------------------
#  FeedManager
# ---------------------------------------------------------------------------

_DEFAULT_SOURCES: list[FeedSource] = [
    FeedSource(name="nvd", feed_type=FeedType.NVD, url=NVD_FEED_URL, cache_ttl_hours=6, rate_limit_sleep=6.0),
    FeedSource(
        name="cisa_kev", feed_type=FeedType.CISA_KEV, url=CISA_KEV_URL, cache_ttl_hours=12, rate_limit_sleep=1.0
    ),
    FeedSource(name="epss", feed_type=FeedType.EPSS, url=EPSS_URL, cache_ttl_hours=24, rate_limit_sleep=1.0),
    FeedSource(name="osv", feed_type=FeedType.OSV, url=OSV_URL, cache_ttl_hours=6, rate_limit_sleep=1.0),
    FeedSource(
        name="github_advisory",
        feed_type=FeedType.GITHUB_ADVISORY,
        url=GITHUB_ADVISORY_URL,
        cache_ttl_hours=6,
        rate_limit_sleep=1.0,
    ),
]


class FeedManager:
    """Top-level API for vulnerability feed management.

    Integrates with :class:`VulnerabilityEngine` to provide live feed data,
    offline mode, and cache validation.
    """

    def __init__(self, feed_dir: Path | None = None, sources: list[FeedSource] | None = None) -> None:
        self._cache = FeedCache(cache_dir=feed_dir)
        self._sources = sources or list(_DEFAULT_SOURCES)
        self._scheduler = FeedScheduler(self._cache, self._sources)
        self._lock = Lock()

    # -- Public API --

    def update(self, force: bool = False) -> dict[str, UpdateResult]:
        """Update all feeds. Returns per-source results."""
        return self._scheduler.update_all(force=force)

    def update_feed(self, feed_name: str, force: bool = False) -> UpdateResult | None:
        """Update a single feed by name."""
        return self._scheduler.update_single(feed_name, force=force)

    def get_metadata(self) -> FeedMetadata:
        """Get the current feed database metadata."""
        raw = self._cache.get_all_metadata()
        metadata = FeedMetadata(
            last_updated=raw.get("last_updated", ""),
            last_update_attempt=_now_iso(),
            is_offline=raw.get("is_offline", "true") == "true",
            total_entries=int(raw.get("total_entries", "0")),
            checksum=raw.get("checksum", ""),
        )
        # Load feed-level metadata
        for ft in FeedType:
            ts = raw.get(f"feed_{ft.value}_updated", "")
            if ts:
                metadata.feed_last_updated[ft.value] = ts
            count_str = raw.get(f"feed_{ft.value}_count", "")
            if count_str:
                with contextlib.suppress(ValueError, TypeError):
                    metadata.feed_entry_counts[ft.value] = int(count_str)
        feed_versions_raw = raw.get("feed_versions", "{}")
        with contextlib.suppress(json.JSONDecodeError, TypeError):
            metadata.feed_versions = json.loads(feed_versions_raw)
        return metadata

    def get_vulnerabilities(self) -> list[dict[str, Any]]:
        """Get all cached vulnerability entries as a unified list."""
        return self._cache.get_all_entries()

    def get_vulnerabilities_by_source(self, source: str) -> list[dict[str, Any]]:
        """Get cached vulnerability entries for a specific feed source."""
        return self._cache.get_entries_for_source(source)

    def export_to_json(self, output_path: Path) -> Path:
        """Export all cached vulnerabilities to a JSON file."""
        entries = self.get_vulnerabilities()
        output_path.write_text(
            json.dumps({"vulnerabilities": entries, "metadata": self.get_metadata().to_dict()}, indent=2, default=str),
            encoding="utf-8",
        )
        return output_path

    @property
    def is_offline(self) -> bool:
        try:
            meta = self._cache.get_metadata("is_offline")
            return meta != "false"
        except Exception:
            return True

    @property
    def cache(self) -> FeedCache:
        return self._cache

    @property
    def cache_size_bytes(self) -> int:
        return self._cache.size_bytes

    @property
    def total_entries(self) -> int:
        return self._cache.count_entries()

    def verify_integrity(self) -> bool:
        return self._cache.verify_integrity()

    def clear_cache(self) -> None:
        self._cache.clear()

    def rebuild_from_feeds(self) -> dict[str, UpdateResult]:
        """Force-refresh all feeds and rebuild the local cache."""
        return self.update(force=True)

    def get_feed_sources(self) -> list[FeedSource]:
        return list(self._sources)

    # -- Compatibility with VulnerabilityDatabase --

    def build_vulnerability_database(self) -> list[dict[str, Any]]:
        """Build a list of vulnerability dicts suitable for VulnerabilityDatabase.load()."""
        return self.get_vulnerabilities()


# ---------------------------------------------------------------------------
#  Singleton and convenience
# ---------------------------------------------------------------------------

_default_manager: FeedManager | None = None
_default_manager_lock = Lock()


def get_default_manager(feed_dir: Path | None = None) -> FeedManager:
    """Get or create the default singleton FeedManager."""
    global _default_manager
    if _default_manager is not None:
        return _default_manager
    with _default_manager_lock:
        if _default_manager is not None:
            return _default_manager
        _default_manager = FeedManager(feed_dir=feed_dir)
    return _default_manager


def update_feeds(force: bool = False) -> dict[str, UpdateResult]:
    """Convenience: update all feeds using the default manager."""
    return get_default_manager().update(force=force)


def get_feed_status() -> FeedMetadata:
    """Convenience: get feed metadata from the default manager."""
    return get_default_manager().get_metadata()


# ---------------------------------------------------------------------------
#  Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "DEFAULT_CACHE_TTL_HOURS",
    "DEFAULT_FEED_DIR",
    "FeedCache",
    "FeedEntry",
    "FeedManager",
    "FeedMetadata",
    "FeedScheduler",
    "FeedSource",
    "FeedType",
    "FeedUpdater",
    "UpdateResult",
    "UpdateStatus",
    "get_default_manager",
    "get_feed_status",
    "update_feeds",
]
