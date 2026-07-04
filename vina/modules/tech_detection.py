"""Technology detection stage."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.config import AppConfig
from ..core.runner import CommandResult
from ..models.common import AliveHost, TechnologyEntry
from ..parsers.tool_outputs import parse_whatweb
from .common import ModuleContext


@dataclass(slots=True)
class TechnologyDetectionResult:
    technologies: list[TechnologyEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    command_results: list[CommandResult] = field(default_factory=list)


class TechnologyDetectionModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, hosts: list[AliveHost]) -> TechnologyDetectionResult:
        if not hosts:
            return TechnologyDetectionResult()
        command = await self.context.runner.run(
            self.config.tool_bin("whatweb", "WhatWeb"),
            ["--log-json=-", "--no-errors"] + [host.url for host in hosts],
            timeout_seconds=self.context.timeout_seconds,
        )
        technologies: list[TechnologyEntry] = []
        for item in parse_whatweb(command.stdout):
            host = str(item.get("target") or item.get("url") or hosts[0].url)
            plugins = item.get("plugins")
            if isinstance(plugins, dict):
                for name, details in plugins.items():
                    version = None
                    if isinstance(details, dict):
                        version_value = details.get("version")
                        if isinstance(version_value, str):
                            version = version_value
                    technologies.append(TechnologyEntry(host=host, name=str(name), version=version, source=command.command))
        warnings = [command.stderr] if command.stderr and not command.succeeded else []
        return TechnologyDetectionResult(technologies=technologies, warnings=warnings, command_results=[command])
