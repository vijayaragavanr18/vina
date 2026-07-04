"""Port scanning stage."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.config import AppConfig
from ..core.runner import CommandResult
from ..models.common import AliveHost, PortEntry
from ..parsers.tool_outputs import parse_naabu, parse_nmap_grepable
from .common import ModuleContext


@dataclass(slots=True)
class PortScanResult:
    ports: list[PortEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    command_results: list[CommandResult] = field(default_factory=list)


class PortScanModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, hosts: list[AliveHost]) -> PortScanResult:
        urls = [host.url for host in hosts]
        if not urls:
            return PortScanResult()
        naabu_result = await self.context.runner.run(
            self.config.tool_bin("naabu", "naabu"),
            ["-json", "-silent"],
            timeout_seconds=self.context.timeout_seconds,
            input_text="\n".join(urls) + "\n",
        )
        ports: list[PortEntry] = []
        for item in parse_naabu(naabu_result.stdout):
            host = str(item.get("host"))
            port = int(item.get("port"))
            ports.append(
                PortEntry(
                    host=host,
                    port=port,
                    protocol=str(item.get("protocol") or "tcp"),
                    service=str(item.get("service") or "") or None,
                    source=naabu_result.command,
                )
            )

        nmap_result = await self._run_nmap(hosts)
        for item in parse_nmap_grepable(nmap_result.stdout):
            port = item.get("port")
            if isinstance(port, int):
                ports.append(
                    PortEntry(
                        host=urls[0],
                        port=port,
                        protocol=str(item.get("protocol") or "tcp"),
                        service=item.get("service") if isinstance(item.get("service"), str) else None,
                        source=nmap_result.command,
                    )
                )

        warnings = [result.stderr for result in (naabu_result, nmap_result) if result.stderr and not result.succeeded]
        return PortScanResult(ports=self._dedupe_ports(ports), warnings=warnings, command_results=[naabu_result, nmap_result])

    async def _run_nmap(self, hosts: list[AliveHost]):
        host = hosts[0].url
        ports = ",".join(str(port) for port in self.config.common_ports)
        return await self.context.runner.run(
            self.config.tool_bin("nmap", "nmap"),
            ["-Pn", "-sV", "-p", ports, "-oG", "-", host],
            timeout_seconds=self.context.timeout_seconds,
        )

    @staticmethod
    def _dedupe_ports(ports: list[PortEntry]) -> list[PortEntry]:
        seen: set[tuple[str, int, str]] = set()
        deduped: list[PortEntry] = []
        for port in ports:
            key = (port.host, port.port, port.protocol)
            if key not in seen:
                seen.add(key)
                deduped.append(port)
        return deduped
