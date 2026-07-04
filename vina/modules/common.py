"""Module plumbing and shared helpers."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.runner import AsyncCommandRunner, CommandResult
from ..core.storage import JsonStore


@dataclass(slots=True)
class StageEnvelope:
    stage: str
    command_results: list[CommandResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ModuleContext:
    def __init__(self, runner: AsyncCommandRunner, store: JsonStore, timeout_seconds: int) -> None:
        self.runner = runner
        self.store = store
        self.timeout_seconds = timeout_seconds
