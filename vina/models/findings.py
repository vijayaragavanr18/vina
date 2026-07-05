"""Unified finding and severity models for VINA."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


def severity_key(s: str | Severity) -> int:
    if isinstance(s, str):
        try:
            s = Severity(s.lower())
        except ValueError:
            return 0
    return SEVERITY_ORDER.get(s, 0)


class FindingCategory(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    SUBDOMAIN = "subdomain"
    ALIVE_HOST = "alive_host"
    OPEN_PORT = "open_port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    ENDPOINT = "endpoint"
    HISTORICAL_URL = "historical_url"
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    INFORMATION = "information"
    PARAMETER = "parameter"
    OTHER = "other"


@dataclass(slots=True)
class Finding:
    id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "info"
    category: str = "other"
    source_stage: str = ""
    target: str = ""
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    timestamp: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)
    host: str = ""
    port: int | None = None
    protocol: str = ""
    url: str = ""
    confidence: float | None = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "source_stage": self.source_stage,
            "target": self.target,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "references": self.references,
            "timestamp": self.timestamp,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "url": self.url,
            "confidence": self.confidence,
            "tags": self.tags,
        }


def _utc_now_str() -> str:
    return datetime.now(UTC).isoformat()


def make_finding(
    *,
    title: str,
    description: str = "",
    severity: str = "info",
    category: str = "other",
    source_stage: str = "",
    target: str = "",
    evidence: str = "",
    recommendation: str = "",
    references: list[str] | None = None,
    host: str = "",
    port: int | None = None,
    protocol: str = "",
    url: str = "",
    confidence: float | None = None,
    tags: list[str] | None = None,
) -> Finding:
    return Finding(
        id=f"{source_stage}/{target}/{title}" if source_stage and target and title else "",
        title=title,
        description=description,
        severity=severity,
        category=category,
        source_stage=source_stage,
        target=target,
        evidence=evidence,
        recommendation=recommendation,
        references=references or [],
        timestamp=_utc_now_str(),
        host=host,
        port=port,
        protocol=protocol,
        url=url,
        confidence=confidence,
        tags=tags or [],
    )


__all__ = [
    "SEVERITY_LABELS",
    "SEVERITY_ORDER",
    "Finding",
    "FindingCategory",
    "Severity",
    "make_finding",
    "severity_key",
]
