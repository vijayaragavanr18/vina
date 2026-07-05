"""Historical URL collection stage."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.config import AppConfig
from ..core.runner import CommandResult
from ..models.common import HistoricalUrlEntry, TargetInput
from ..parsers.tool_outputs import lines, unique_lines
from .common import ModuleContext


@dataclass(slots=True)
class HistoricalUrlResult:
    urls: list[HistoricalUrlEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    command_results: list[CommandResult] = field(default_factory=list)


class HistoricalUrlModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> HistoricalUrlResult:
        domain = target.root_domain or target.hostname or target.normalized
        gau = await self.context.runner.run(
            self.config.tool_bin("gau", "gau"), [domain], timeout_seconds=self.context.timeout_seconds
        )
        wayback = await self.context.runner.run(
            self.config.tool_bin("waybackurls", "waybackurls"), [domain], timeout_seconds=self.context.timeout_seconds
        )
        collected = unique_lines(f"{gau.stdout}\n{wayback.stdout}")
        urls = [
            HistoricalUrlEntry(url=value, source=gau.command if value in lines(gau.stdout) else wayback.command)
            for value in collected
        ]
        warnings = [result.stderr for result in (gau, wayback) if result.stderr and not result.succeeded]
        return HistoricalUrlResult(urls=urls, warnings=warnings, command_results=[gau, wayback])
