"""Structured data models used across VINA."""

from .common import (
    AliveHost,
    AnalysisItem,
    Asset,
    CrawlEntry,
    HistoricalUrlEntry,
    ModuleOutput,
    ParameterCandidate,
    PortEntry,
    ReportArtifact,
    TargetInput,
    TechnologyEntry,
    extract_query_parameters,
)
from .findings import (
    SEVERITY_LABELS,
    SEVERITY_ORDER,
    Finding,
    FindingCategory,
    Severity,
    make_finding,
    severity_key,
)

__all__ = [
    "SEVERITY_LABELS",
    "SEVERITY_ORDER",
    "AliveHost",
    "AnalysisItem",
    "Asset",
    "CrawlEntry",
    "Finding",
    "FindingCategory",
    "HistoricalUrlEntry",
    "ModuleOutput",
    "ParameterCandidate",
    "PortEntry",
    "ReportArtifact",
    "Severity",
    "TargetInput",
    "TechnologyEntry",
    "extract_query_parameters",
    "make_finding",
    "severity_key",
]
