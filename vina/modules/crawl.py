"""Crawler stage."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.config import AppConfig
from ..core.runner import CommandResult
from ..models.common import AliveHost, CrawlEntry
from ..parsers.tool_outputs import parse_katana
from .common import ModuleContext


@dataclass(slots=True)
class CrawlResult:
    entries: list[CrawlEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    command_results: list[CommandResult] = field(default_factory=list)


class CrawlModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, hosts: list[AliveHost]) -> CrawlResult:
        if not hosts:
            return CrawlResult()
        command = await self.context.runner.run(
            self.config.tool_bin("katana", "katana"),
            ["-silent", "-json"],
            timeout_seconds=self.context.timeout_seconds,
            input_text="\n".join(host.url for host in hosts) + "\n",
        )
        entries: list[CrawlEntry] = []
        for item in parse_katana(command.stdout):
            url = str(item.get("url"))
            entries.append(CrawlEntry(source_url=hosts[0].url, discovered_url=url, source=command.command))
        warnings = [command.stderr] if command.stderr and not command.succeeded else []
        return CrawlResult(entries=entries, warnings=warnings, command_results=[command])
