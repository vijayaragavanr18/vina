"""Shared dataclasses for VINA outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlparse


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class TargetInput:
    raw: str
    normalized: str
    hostname: str | None
    scheme: str | None
    port: int | None
    root_domain: str | None

    @classmethod
    def from_raw(cls, raw: str) -> "TargetInput":
        normalized = raw.strip().rstrip("/")
        candidate = normalized if "://" in normalized else f"//{normalized}"
        parsed = urlparse(candidate)
        hostname = parsed.hostname or normalized.split("/")[0]
        scheme = parsed.scheme or None
        port = parsed.port
        root_domain = _root_domain(hostname) if hostname else None
        return cls(raw=raw, normalized=normalized, hostname=hostname, scheme=scheme, port=port, root_domain=root_domain)


def _root_domain(hostname: str) -> str:
    labels = hostname.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return hostname


@dataclass(slots=True)
class Asset:
    value: str
    source: str


@dataclass(slots=True)
class AliveHost:
    url: str
    source: str
    status_code: int | None = None
    title: str | None = None
    technologies: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PortEntry:
    host: str
    port: int
    protocol: str = "tcp"
    service: str | None = None
    banner: str | None = None
    source: str = "naabu"


@dataclass(slots=True)
class TechnologyEntry:
    host: str
    name: str
    version: str | None = None
    confidence: float | None = None
    source: str = "whatweb"


@dataclass(slots=True)
class CrawlEntry:
    source_url: str
    discovered_url: str
    depth: int | None = None
    source: str = "katana"


@dataclass(slots=True)
class HistoricalUrlEntry:
    url: str
    source: str


@dataclass(slots=True)
class ParameterCandidate:
    url: str
    parameter: str
    source: str


@dataclass(slots=True)
class Finding:
    tool: str
    target: str
    title: str
    severity: str
    evidence: str | None = None
    category: str | None = None
    confidence: float | None = None
    raw: str | None = None


@dataclass(slots=True)
class AnalysisItem:
    finding_title: str
    score: int
    rationale: str
    manual_verification: list[str] = field(default_factory=list)
    burp_request: str | None = None
    payload_ideas: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReportArtifact:
    markdown_path: str
    html_path: str


@dataclass(slots=True)
class ModuleOutput:
    created_at: datetime = field(default_factory=utc_now)


def extract_query_parameters(url: str) -> list[str]:
    parsed = urlparse(url)
    return [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]


__all__ = [
    "AliveHost",
    "AnalysisItem",
    "Asset",
    "CrawlEntry",
    "Finding",
    "HistoricalUrlEntry",
    "ModuleOutput",
    "ParameterCandidate",
    "PortEntry",
    "ReportArtifact",
    "TargetInput",
    "TechnologyEntry",
    "extract_query_parameters",
]
