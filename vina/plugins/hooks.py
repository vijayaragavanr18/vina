"""Hook system for the VINA Plugin SDK."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger("vina.plugins.hooks")


class HookPoint(StrEnum):
    """Well-known hook points in the VINA pipeline."""

    BEFORE_PIPELINE = "before_pipeline"
    AFTER_PIPELINE = "after_pipeline"
    BEFORE_STAGE = "before_stage"
    AFTER_STAGE = "after_stage"
    BEFORE_REPORT = "before_report"
    AFTER_REPORT = "after_report"
    BEFORE_FINDING = "before_finding"
    AFTER_FINDING = "after_finding"
    BEFORE_CORRELATION = "before_correlation"
    AFTER_CORRELATION = "after_correlation"
    BEFORE_EXPLOITABILITY = "before_exploitability"
    AFTER_EXPLOITABILITY = "after_exploitability"
    BEFORE_VULNERABILITY_LOOKUP = "before_vulnerability_lookup"
    AFTER_VULNERABILITY_LOOKUP = "after_vulnerability_lookup"


@dataclass(slots=True)
class HookEvent:
    """Data passed to hook handlers.

    ``data`` is a mutable dictionary that handlers can read and modify.
    ``results`` accumulates return values from handlers.
    """

    hook_point: str
    data: dict[str, Any] = field(default_factory=dict)
    cancelled: bool = False
    results: list[Any] = field(default_factory=list)
    errors: list[tuple[str, Exception]] = field(default_factory=list)


HookHandler = Callable[..., Any]


@dataclass(slots=True)
class HookRegistration:
    """A registered hook handler with priority."""

    handler: HookHandler
    priority: int = 0
    plugin_id: str = ""


_ALL_HOOK_POINTS: set[str] = {hp.value for hp in HookPoint}


def is_valid_hook_point(name: str) -> bool:
    """Check if *name* is a recognised hook point."""
    return name in _ALL_HOOK_POINTS


def get_all_hook_points() -> list[str]:
    return sorted(_ALL_HOOK_POINTS)


__all__ = ["HookEvent", "HookHandler", "HookPoint", "HookRegistration", "get_all_hook_points", "is_valid_hook_point"]
