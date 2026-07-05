"""Alive host discovery stage."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.config import AppConfig
from ..core.runner import CommandResult
from ..models.common import AliveHost, Asset
from ..parsers.tool_outputs import parse_httpx
from .common import ModuleContext


@dataclass(slots=True)
class HostDiscoveryResult:
    hosts: list[AliveHost] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    command_results: list[CommandResult] = field(default_factory=list)


class HostDiscoveryModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, assets: list[Asset]) -> HostDiscoveryResult:
        values = [asset.value for asset in assets]
        if not values:
            return HostDiscoveryResult()
        result = await self.context.runner.run(
            self.config.tool_bin("httpx", "httpx"),
            ["-silent", "-json", "-title", "-tech-detect"],
            timeout_seconds=self.context.timeout_seconds,
            input_text="\n".join(values) + "\n",
        )
        hosts: list[AliveHost] = []
        for item in parse_httpx(result.stdout):
            url = str(item.get("url") or item.get("input") or item.get("host"))
            status_code_val = item.get("status-code")
            title_val = item.get("title")
            tech_val = item.get("tech")
            hosts.append(
                AliveHost(
                    url=url,
                    source=result.command,
                    status_code=status_code_val if isinstance(status_code_val, int) else None,
                    title=title_val if isinstance(title_val, str) else None,
                    technologies=[
                        str(tech) for tech in (tech_val if isinstance(tech_val, list) else []) if isinstance(tech, str)
                    ],
                )
            )
        warnings = [result.stderr] if result.stderr and not result.succeeded else []
        return HostDiscoveryResult(hosts=hosts, warnings=warnings, command_results=[result])
