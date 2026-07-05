"""Vulnerability Intelligence Engine for VINA.

Matches installed software components against a local CVE database,
supports semantic version comparison, Debian version strings, range
matching, risk scoring, and external feed provider interfaces.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Protocol

from ..models.findings import Finding, make_finding

# ---------------------------------------------------------------------------
#  Models
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SoftwareComponent:
    """A software component discovered on the target system."""
    name: str
    version: str = ""
    vendor: str = ""
    architecture: str = ""
    package_manager: str = ""
    source_stage: str = ""


@dataclass(slots=True)
class Vulnerability:
    """A security vulnerability entry."""
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
    source: str = "local"


@dataclass(slots=True)
class VulnerabilityMatch:
    """A matched vulnerability for a specific software component."""
    vulnerability: Vulnerability
    component: SoftwareComponent
    matching_version: str = ""
    affected_range: str = ""
    fixed_version: str = ""
    risk_score: float = 0.0

    def to_finding(self) -> Finding:
        sev = self.vulnerability.severity
        title = f"{self.vulnerability.cve} - {self.vulnerability.title or self.vulnerability.product}"
        desc = self.vulnerability.description or f"{self.vulnerability.cve} affects {self.component.name} {self.component.version}"
        evidence = (
            f"cve={self.vulnerability.cve} "
            f"component={self.component.name} "
            f"installed={self.component.version} "
            f"fixed={self.fixed_version or 'N/A'}"
        )
        refs = list(self.vulnerability.references)
        tags = ["cve", "vulnerability"]
        if self.vulnerability.kev:
            tags.append("kev")
        if self.vulnerability.exploit_available:
            tags.append("exploit-available")
        if self.vulnerability.cvss_v3 >= 9.0:
            tags.append("critical-cvss")

        mitigation = (
            f"Upgrade {self.component.name} from {self.component.version} "
            f"to {self.fixed_version or 'the latest patched version'}"
        )
        if self.vulnerability.references:
            mitigation += f". See: {', '.join(self.vulnerability.references[:3])}"

        return make_finding(
            title=title,
            description=desc,
            severity=sev,
            category="vulnerability",
            source_stage=f"vuln_intel/{self.vulnerability.source}",
            target=self.component.name,
            evidence=evidence,
            recommendation=mitigation,
            references=refs,
            tags=tags,
            confidence=min(self.vulnerability.confidence, 1.0),
        )


# ---------------------------------------------------------------------------
#  Version parsing and comparison
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-\.].*)?$")
_DEBIAN_VERSION_RE = re.compile(r"^(?:(\d+):)?(.+?)(?:-([^-]+))?$")


def _parse_semver(version: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of integer components for comparison.

    Handles semver-like strings, stripping non-numeric suffixes.
    Returns ``()`` for unparseable versions (will compare as empty = equal).
    """
    m = _SEMVER_RE.match(version.strip())
    if m:
        parts = []
        for g in m.groups():
            if g is not None:
                try:
                    parts.append(int(g))
                except ValueError:
                    break
            else:
                break
        return tuple(parts)
    return ()


def _parse_debian_version(version: str) -> tuple[int, list[int | str], list[int | str]]:
    """Parse a Debian version string into a sortable tuple.

    Returns ``(epoch, upstream_parts, debian_parts)`` where each part is a
    list of alternating ``int`` and ``str`` for alphanumeric comparison.
    """
    m = _DEBIAN_VERSION_RE.match(version.strip())
    if not m:
        return (0, [0], [])

    epoch_str, upstream, debian = m.groups()
    epoch = int(epoch_str) if epoch_str else 0
    upstream_parts = _split_version_str(upstream or "0")
    debian_parts = _split_version_str(debian) if debian else []
    return (epoch, upstream_parts, debian_parts)


def _split_version_str(s: str) -> list[int | str]:
    """Split a version component string into alternating int/str parts.

    ``"1.2.3a"`` → ``[1, ".", 2, ".", 3, "a"]`` but smarter — merges
    contiguous digits into ints and contiguous non-digits into strings.
    """
    parts: list[int | str] = []
    buf = ""
    for ch in s:
        if ch.isdigit():
            if buf and not buf[-1].isdigit():
                parts.append(buf)
                buf = ""
            buf += ch
        else:
            if buf and buf[-1].isdigit():
                parts.append(int(buf))
                buf = ""
            buf += ch
    if buf:
        if buf[-1].isdigit():
            parts.append(int(buf))
        else:
            parts.append(buf)
    if not parts:
        parts.append(0)
    return parts


def _normalize_for_cmp(parts: list[int | str]) -> list[int | str]:
    """Remove trailing zero-value parts for fair comparison.

    ``[1, ".", 0, ".", 0]`` → ``[1, ".", 0]`` (strip trailing ``[".", 0]``).
    """
    while len(parts) >= 2 and parts[-1] == 0 and not isinstance(parts[-2], int):
        parts = parts[:-2]
    return parts


def compare_versions(a: str, b: str) -> int:
    """Compare two version strings.

    Tries Debian comparison first, falls back to semver comparison.

    Returns -1 if ``a < b``, 0 if ``a == b``, 1 if ``a > b``.
    """
    # Try Debian comparison
    epoch_a, up_a, deb_a = _parse_debian_version(a)
    epoch_b, up_b, deb_b = _parse_debian_version(b)

    if epoch_a != epoch_b:
        return -1 if epoch_a < epoch_b else 1

    up_a = _normalize_for_cmp(up_a)
    up_b = _normalize_for_cmp(up_b)

    cmp_val = _compare_version_parts(up_a, up_b)
    if cmp_val != 0:
        return cmp_val

    deb_a = _normalize_for_cmp(deb_a)
    deb_b = _normalize_for_cmp(deb_b)
    return _compare_version_parts(deb_a, deb_b)


def _compare_version_parts(a: list[int | str], b: list[int | str]) -> int:
    """Compare two parsed version component lists."""
    max_len = max(len(a), len(b))
    for i in range(max_len):
        part_a = a[i] if i < len(a) else None
        part_b = b[i] if i < len(b) else None
        if part_a is None and part_b is None:
            return 0
        if part_a is None:
            # Treat missing as 0 for int, "" for str
            if isinstance(part_b, int):
                if 0 < part_b:
                    return -1
                if 0 > part_b:
                    return 1
            else:
                if part_b:
                    return -1
            continue
        if part_b is None:
            if isinstance(part_a, int):
                if part_a > 0:
                    return 1
                if part_a < 0:
                    return -1
            else:
                if part_a:
                    return 1
            continue
        if isinstance(part_a, int) and isinstance(part_b, int):
            if part_a < part_b:
                return -1
            if part_a > part_b:
                return 1
        else:
            str_a = str(part_a)
            str_b = str(part_b)
            if str_a < str_b:
                return -1
            if str_a > str_b:
                return 1
    return 0


# ---------------------------------------------------------------------------
#  Version pattern matching
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class VersionPattern:
    operator: str = ""
    version: str = ""
    end_version: str = ""


def parse_version_pattern(pattern: str) -> list[VersionPattern]:
    """Parse a version constraint string into a list of patterns.

    Examples::
        "<2.4.58"         → [VersionPattern("<", "2.4.58")]
        ">=9.0,<9.3"      → [VersionPattern(">=", "9.0"), VersionPattern("<", "9.3")]
        "1.18.0 - 1.18.9" → [VersionPattern(">=", "1.18.0"), VersionPattern("<=", "1.18.9")]
        "=6.1.0"          → [VersionPattern("=", "6.1.0")]
        "6.1.*"           → [VersionPattern(">=", "6.1.0"), VersionPattern("<", "6.2.0")]
        "5.15.x"          → [VersionPattern(">=", "5.15.0"), VersionPattern("<", "5.16.0")]
    """
    pattern = pattern.strip()
    if not pattern:
        return []

    # Range: "X - Y"
    range_match = re.match(r"^([\d\.\*x]+)\s*-\s*([\d\.\*x]+)$", pattern)
    if range_match:
        start, end = range_match.groups()
        return [VersionPattern(">=", _wildcard_to_base(start)), VersionPattern("<=", _wildcard_to_base(end))]

    # Wildcard: "6.1.*" or "5.15.x"
    if "*" in pattern or pattern.endswith(".x"):
        base = _wildcard_to_base(pattern)
        orig_clean = pattern.replace("*", "").replace("x", "").rstrip(".").rstrip("0").rstrip(".") or "0"
        orig_parts = orig_clean.split(".")
        base_parts = base.split(".")
        idx = len(orig_parts) - 1
        if 0 <= idx < len(base_parts):
            base_parts[idx] = str(int(base_parts[idx]) + 1)
        upper = ".".join(base_parts)
        return [VersionPattern(">=", base), VersionPattern("<", upper)]

    # Comma-separated: ">=9.0,<9.3"
    if "," in pattern:
        results = []
        for part in pattern.split(","):
            results.extend(parse_version_pattern(part.strip()))
        return results

    # Operator-prefixed: "<2.4.58", ">=9.0", "=1.0"
    op_match = re.match(r"^(<=|>=|<|>|!=|=)\s*(.+)$", pattern)
    if op_match:
        return [VersionPattern(op_match.group(1), op_match.group(2).strip())]

    # Bare version: exact match
    return [VersionPattern("=", pattern.strip())]


def _wildcard_to_base(pattern: str) -> str:
    """Convert a wildcard pattern to a base version.

    ``"6.1.*"`` → ``"6.1.0"``, ``"5.15.x"`` → ``"5.15.0"``
    """
    return pattern.replace("*", "0").replace("x", "0")


def _increment_last(version: str) -> str:
    """Increment the last numeric component of a version.

    ``"6.1.0"`` → ``"6.2.0"``, ``"5.15"`` → ``"5.16"``
    """
    parts = version.split(".")
    for i in range(len(parts) - 1, -1, -1):
        if parts[i].isdigit():
            parts[i] = str(int(parts[i]) + 1)
            break
    return ".".join(parts)


def version_matches(installed: str, pattern: str) -> bool:
    """Check if an installed version matches a version constraint pattern.

    Args:
        installed: The installed version string.
        pattern: A version constraint (``"<2.4.58"``, ``">=9.0,<9.3"``, etc.).

    Returns:
        ``True`` if the installed version satisfies the constraint.
    """
    patterns = parse_version_pattern(pattern)
    if not patterns:
        return True  # unparseable pattern matches everything

    for p in patterns:
        cmp_val = compare_versions(installed, p.version)
        if p.operator == "<" and not (cmp_val < 0):
            return False
        elif p.operator == "<=" and not (cmp_val <= 0):
            return False
        elif p.operator == ">" and not (cmp_val > 0):
            return False
        elif p.operator == ">=" and not (cmp_val >= 0):
            return False
        elif p.operator == "=" and not (cmp_val == 0):
            return False
        elif p.operator == "!=" and not (cmp_val != 0):
            return False
    return True


# ---------------------------------------------------------------------------
#  Vulnerability Database
# ---------------------------------------------------------------------------


class VulnerabilityDatabase:
    """Local vulnerability database with indexed lookups.

    Loads CVE entries from JSON files and indexes them by vendor+product
    for fast matching.
    """

    def __init__(self, paths: list[Path] | None = None) -> None:
        self._entries: list[Vulnerability] = []
        # vendor -> product -> list[Vulnerability]
        self._vendor_index: dict[str, dict[str, list[Vulnerability]]] = {}
        # product -> list[Vulnerability]  (fallback)
        self._product_index: dict[str, list[Vulnerability]] = {}
        self._lock = Lock()
        self._loaded = False
        if paths:
            self.load(paths)

    def load(self, paths: list[Path]) -> None:
        """Load vulnerability entries from JSON files."""
        with self._lock:
            for path in paths:
                if not path.exists():
                    continue
                raw = json.loads(path.read_text(encoding="utf-8"))
                entries = raw if isinstance(raw, list) else raw.get("vulnerabilities", [])
                for item in entries:
                    vuln = self._parse_entry(item)
                    if vuln.cve:
                        self._entries.append(vuln)
            self._build_index()

    def _parse_entry(self, item: dict[str, Any]) -> Vulnerability:
        return Vulnerability(
            cve=item.get("cve", ""),
            title=item.get("title", ""),
            description=item.get("description", ""),
            severity=item.get("severity", "medium"),
            cvss_v3=float(item.get("cvss_v3", 0)),
            cvss_v4=float(item.get("cvss_v4", 0)),
            epss=float(item.get("epss", 0)),
            kev=bool(item.get("kev", False)),
            exploited=bool(item.get("exploited", False)),
            vendor=item.get("vendor", "").lower(),
            product=item.get("product", "").lower(),
            affected_versions=list(item.get("affected_versions", [])),
            fixed_versions=list(item.get("fixed_versions", [])),
            published=item.get("published", ""),
            updated=item.get("updated", ""),
            references=list(item.get("references", [])),
            cwe=item.get("cwe", ""),
            mitre_attack=list(item.get("mitre_attack", [])),
            exploit_available=bool(item.get("exploit_available", False)),
            exploit_sources=list(item.get("exploit_sources", [])),
            confidence=float(item.get("confidence", 0.8)),
            source=item.get("source", "local"),
        )

    def _build_index(self) -> None:
        self._vendor_index.clear()
        self._product_index.clear()
        for vuln in self._entries:
            v = vuln.vendor or "_unknown"
            p = vuln.product or "_unknown"
            if v not in self._vendor_index:
                self._vendor_index[v] = {}
            if p not in self._vendor_index[v]:
                self._vendor_index[v][p] = []
            self._vendor_index[v][p].append(vuln)

            if p not in self._product_index:
                self._product_index[p] = []
            self._product_index[p].append(vuln)

    def lookup(self, component: SoftwareComponent) -> list[Vulnerability]:
        """Look up vulnerabilities for a software component.

        Matches by vendor+product first, falls back to product-only.
        """
        results: list[Vulnerability] = []
        seen: set[str] = set()
        name = component.name.lower()
        vendor = component.vendor.lower() if component.vendor else ""

        # Try vendor+product
        if vendor in self._vendor_index and name in self._vendor_index[vendor]:
            for v in self._vendor_index[vendor][name]:
                if v.cve not in seen:
                    seen.add(v.cve)
                    results.append(v)

        # Try product-only
        if name in self._product_index:
            for v in self._product_index[name]:
                if v.cve not in seen:
                    seen.add(v.cve)
                    results.append(v)

        return results

    @property
    def count(self) -> int:
        return len(self._entries)


_DEFAULT_DB: VulnerabilityDatabase | None = None
_DEFAULT_DB_LOCK = Lock()


def get_default_db() -> VulnerabilityDatabase:
    """Get or create the default singleton vulnerability database."""
    global _DEFAULT_DB
    if _DEFAULT_DB is not None:
        return _DEFAULT_DB
    with _DEFAULT_DB_LOCK:
        if _DEFAULT_DB is not None:
            return _DEFAULT_DB
        db_paths = _find_db_files()
        _DEFAULT_DB = VulnerabilityDatabase(paths=db_paths)
    return _DEFAULT_DB


def _find_db_files() -> list[Path]:
    """Find all CVE database JSON files in the data directory."""
    base = Path(__file__).resolve().parent.parent / "data"
    if not base.exists():
        return []
    return sorted(base.glob("*.json"))


def reload_db() -> None:
    """Force reload of the default database."""
    global _DEFAULT_DB
    with _DEFAULT_DB_LOCK:
        _DEFAULT_DB = None
    get_default_db()


# ---------------------------------------------------------------------------
#  Vulnerability Engine
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class VulnEngineConfig:
    enable_kev_filter: bool = False
    min_cvss: float = 0.0
    max_results: int = 0
    exploit_only: bool = False
    offline: bool = True


class VulnerabilityEngine:
    """Orchestrates vulnerability matching for software components.

    Usage::

        engine = VulnerabilityEngine()
        matches = engine.run(components)
        findings = [m.to_finding() for m in matches]

    If a ``feed_manager`` is provided, feed data is loaded into the
    database on first access, and the ``offline`` config flag is
    automatically set from the feed manager's status.
    """

    def __init__(
        self,
        database: VulnerabilityDatabase | None = None,
        config: VulnEngineConfig | None = None,
        feed_manager: Any = None,
    ) -> None:
        self._config = config or VulnEngineConfig()
        self._feed_manager = feed_manager
        self._database = database

        if self._database is None:
            # If feed manager is available, try to load its data
            if self._feed_manager is not None:
                self._database = self._build_db_from_feeds()
                self._config.offline = self._feed_manager.is_offline
            else:
                self._database = get_default_db()

    def _build_db_from_feeds(self) -> VulnerabilityDatabase:
        """Build a VulnerabilityDatabase from FeedManager cache data."""
        feed_data = self._feed_manager.build_vulnerability_database()
        if feed_data:
            db = VulnerabilityDatabase()
            # Load directly into the database
            import json
            from pathlib import Path
            import tempfile
            tmp = Path(tempfile.mktemp(suffix=".json"))
            try:
                tmp.write_text(json.dumps(feed_data, default=str), encoding="utf-8")
                db.load([tmp])
            finally:
                try:
                    tmp.unlink()
                except OSError:
                    pass
            return db
        return get_default_db()

    def run(self, components: list[SoftwareComponent]) -> list[VulnerabilityMatch]:
        """Match all components against the vulnerability database.

        Returns a deduplicated list of matches sorted by risk score
        (highest first).
        """
        matches: list[VulnerabilityMatch] = []
        seen: set[tuple[str, str, str]] = set()  # (cve, component_name, version)

        for comp in components:
            if not comp.version:
                continue
            vulns = self._database.lookup(comp)
            for vuln in vulns:
                key = (vuln.cve, comp.name, comp.version)
                if key in seen:
                    continue
                seen.add(key)

                matched = self._match_version(comp.version, vuln)
                if not matched:
                    continue

                risk = self._compute_risk(vuln, comp)
                fixed = vuln.fixed_versions[0] if vuln.fixed_versions else ""

                matches.append(VulnerabilityMatch(
                    vulnerability=vuln,
                    component=comp,
                    matching_version=comp.version,
                    affected_range=vuln.affected_versions[0] if vuln.affected_versions else "",
                    fixed_version=fixed,
                    risk_score=risk,
                ))

        matches.sort(key=lambda m: m.risk_score, reverse=True)

        if self._config.max_results > 0:
            matches = matches[:self._config.max_results]

        return matches

    def _match_version(self, version: str, vuln: Vulnerability) -> bool:
        """Check if a version is affected by a vulnerability.

        Returns ``True`` if the version matches any affected version
        pattern AND does not match any fixed version pattern.
        """
        # Check affected patterns
        if vuln.affected_versions:
            affected = any(
                version_matches(version, pat)
                for pat in vuln.affected_versions
            )
            if not affected:
                return False

        # Check if fixed version includes this version
        if vuln.fixed_versions:
            for fpat in vuln.fixed_versions:
                if version_matches(version, fpat):
                    return False

        return True

    def _compute_risk(self, vuln: Vulnerability, component: SoftwareComponent) -> float:
        """Compute a 0-100 risk score for a matched vulnerability.

        Factors: CVSS (0-60), EPSS (0-15), KEV (0-10),
        Exploit available (0-10), Confidence (0-5).
        """
        score = 0.0

        # CVSS contribution (max 60)
        cvss = vuln.cvss_v3 or vuln.cvss_v4
        if cvss > 0:
            score += (cvss / 10.0) * 60

        # EPSS contribution (max 15)
        if vuln.epss > 0:
            score += vuln.epss * 15

        # KEV contribution (10)
        if vuln.kev:
            score += 10

        # Exploit available (10)
        if vuln.exploit_available:
            score += 10

        # Confidence (max 5)
        score += vuln.confidence * 5

        return min(max(score, 0), 100)

    @property
    def database(self) -> VulnerabilityDatabase:
        return self._database


# ---------------------------------------------------------------------------
#  External feed provider interfaces
# ---------------------------------------------------------------------------


class VulnFeedProvider(Protocol):
    """Protocol for external vulnerability feed providers."""

    def fetch(self) -> list[Vulnerability]: ...

    @property
    def name(self) -> str: ...


class FeedCache:
    """Simple file-based cache for external vulnerability feeds."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._cache_dir = cache_dir or Path("/tmp/vina_vuln_cache")
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    def get(self, key: str) -> list[dict[str, Any]] | None:
        path = self._cache_dir / f"{key}.json"
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return None
        return None

    def set(self, key: str, data: list[dict[str, Any]]) -> None:
        path = self._cache_dir / f"{key}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        tmp.rename(path)

    def clear(self) -> None:
        for p in self._cache_dir.glob("*.json"):
            p.unlink()


class NVDProvider:
    """NVD (National Vulnerability Database) feed provider."""

    def __init__(self, cache: FeedCache | None = None, api_key: str = "") -> None:
        self._cache = cache or FeedCache()
        self.api_key = api_key
        self.name = "nvd"

    def fetch(self) -> list[Vulnerability]:
        cached = self._cache.get("nvd")
        if cached is not None:
            return [self._to_vuln(item) for item in cached]
        # In production, would call NVD API here
        return []

    @staticmethod
    def _to_vuln(item: dict[str, Any]) -> Vulnerability:
        return Vulnerability(
            cve=item.get("id", ""),
            title=item.get("descriptions", [{}])[0].get("value", "") if isinstance(item.get("descriptions"), list) else item.get("description", ""),
            description=item.get("descriptions", [{}])[0].get("value", "") if isinstance(item.get("descriptions"), list) else item.get("description", ""),
            severity=item.get("severity", "medium"),
            cvss_v3=float(item.get("cvss_v3", 0)),
            vendor=item.get("vendor", ""),
            product=item.get("product", ""),
            references=item.get("references", []),
            source="nvd",
        )


class OSVProvider:
    """OSV (Open Source Vulnerabilities) feed provider."""

    def __init__(self, cache: FeedCache | None = None) -> None:
        self._cache = cache or FeedCache()
        self.name = "osv"

    def fetch(self) -> list[Vulnerability]:
        cached = self._cache.get("osv")
        if cached is not None:
            return [self._to_vuln(item) for item in cached]
        return []

    @staticmethod
    def _to_vuln(item: dict[str, Any]) -> Vulnerability:
        return Vulnerability(
            cve=item.get("id", ""),
            title=item.get("summary", ""),
            description=item.get("details", ""),
            severity=item.get("severity", "medium"),
            references=item.get("references", []),
            source="osv",
        )


# ---------------------------------------------------------------------------
#  Convenience
# ---------------------------------------------------------------------------

_default_engine = VulnerabilityEngine()


def scan_components(components: list[SoftwareComponent]) -> list[VulnerabilityMatch]:
    """Quick convenience to run vulnerability matching with the default engine."""
    return _default_engine.run(components)


def component_from_finding(finding: Finding) -> SoftwareComponent | None:
    """Extract a SoftwareComponent from a scanner finding if possible.

    Looks for structured evidence strings like ``"openssl=1.1.1f arch=amd64"``
    or ``"kernel=6.8.0-35-generic"`` in finding evidence or title.
    """
    name = ""
    version = ""

    # Try evidence string
    ev = finding.evidence or ""
    for part in ev.split():
        if "=" in part:
            key, _, val = part.partition("=")
            if key == "kernel":
                name = "linux-kernel"
                version = val
            elif key in ("package", "name") and not name:
                name = val

    # Try title patterns
    title = finding.title or ""
    if not name:
        for prefix in ("Kernel: ", "Installed: "):
            if title.startswith(prefix):
                rest = title[len(prefix):]
                if " (" in rest:
                    name = rest.split(" (")[0]
                elif "=" in rest:
                    name = rest.split("=")[0]
                else:
                    name = rest.split()[0] if rest else rest

    if not name:
        return None

    # Try to find version in title
    if not version:
        for token in title.split():
            if "=" in token:
                _, _, val = token.partition("=")
                if val and not version:
                    version = val
                    break

    # Extract from Installed: name (version) or name=version patterns
    if not version and title:
        m = re.match(r".*\(([^)]+)\)", title)
        if m:
            version = m.group(1)
        elif "=" in title:
            parts = title.split("=", 1)
            if len(parts) > 1:
                version = parts[1].strip()

    return SoftwareComponent(
        name=name or "unknown",
        version=version,
        source_stage=finding.source_stage,
    )


def build_software_inventory(findings: list[Finding]) -> list[SoftwareComponent]:
    """Build a software inventory from scanner findings.

    Extracts ``SoftwareComponent`` objects from package, kernel, and other
    scanner findings that carry version information.
    """
    components: list[SoftwareComponent] = []
    seen: set[tuple[str, str]] = set()

    for f in findings:
        comp = component_from_finding(f)
        if comp is None:
            continue
        key = (comp.name.lower(), comp.version)
        if key in seen:
            continue
        seen.add(key)
        components.append(comp)

    return components


# ---------------------------------------------------------------------------
#  Risk scoring for overall vulnerability posture
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class VulnStats:
    total_vulnerabilities: int = 0
    by_severity: dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    })
    total_components: int = 0
    critical_cves: int = 0
    kev_count: int = 0
    public_exploits: int = 0
    overall_score: float = 0.0
    top_cves: list[dict[str, Any]] = field(default_factory=list)
    db_version: int = 1
    feed_age_hours: float = -1.0
    last_updated: str = ""
    is_offline: bool = True


def compute_vuln_stats(
    matches: list[VulnerabilityMatch],
    components_count: int = 0,
    feed_metadata: Any = None,
) -> VulnStats:
    """Compute aggregate vulnerability statistics from a list of matches."""
    if not matches:
        return VulnStats(total_components=components_count)

    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    critical = 0
    kev = 0
    exploits = 0
    total_risk = 0.0
    top: list[dict[str, Any]] = []

    for m in matches:
        sev = m.vulnerability.severity.lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        total_risk += m.risk_score
        if sev == "critical":
            critical += 1
        if m.vulnerability.kev:
            kev += 1
        if m.vulnerability.exploit_available:
            exploits += 1

    # Top 5 by risk score
    sorted_matches = sorted(matches, key=lambda m: m.risk_score, reverse=True)
    for m in sorted_matches[:5]:
        top.append({
            "cve": m.vulnerability.cve,
            "severity": m.vulnerability.severity,
            "cvss_v3": m.vulnerability.cvss_v3,
            "risk_score": m.risk_score,
            "component": m.component.name,
            "installed": m.component.version,
        })

    avg_risk = total_risk / len(matches) if matches else 0
    penalty = min((len(matches) * 2), 30)
    overall = min(avg_risk + penalty, 100)

    # Populate feed metadata if available
    db_version = 1
    feed_age = -1.0
    last_updated = ""
    is_offline = True
    if feed_metadata is not None:
        db_version = getattr(feed_metadata, "db_version", 1)
        feed_age = getattr(feed_metadata, "feed_age_hours", -1.0)
        last_updated = getattr(feed_metadata, "last_updated", "")
        is_offline = getattr(feed_metadata, "is_offline", True)

    return VulnStats(
        total_vulnerabilities=len(matches),
        by_severity=by_severity,
        total_components=components_count,
        critical_cves=critical,
        kev_count=kev,
        public_exploits=exploits,
        overall_score=round(overall, 1),
        top_cves=top,
        db_version=db_version,
        feed_age_hours=feed_age,
        last_updated=last_updated,
        is_offline=is_offline,
    )


# ---------------------------------------------------------------------------
#  Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "SoftwareComponent",
    "Vulnerability",
    "VulnerabilityMatch",
    "VulnerabilityDatabase",
    "VulnerabilityEngine",
    "VulnEngineConfig",
    "VulnStats",
    "VersionPattern",
    "compare_versions",
    "parse_version_pattern",
    "version_matches",
    "compute_vuln_stats",
    "scan_components",
    "component_from_finding",
    "build_software_inventory",
    "get_default_db",
    "reload_db",
    "FeedCache",
    "NVDProvider",
    "OSVProvider",
    "VulnFeedProvider",
]
