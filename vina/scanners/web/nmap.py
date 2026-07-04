"""Web service-detection stage powered by Nmap."""

from __future__ import annotations

import logging
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NmapService:
    """Single service entry discovered by Nmap."""

    hostname: str
    ip: str | None = None
    port: int = 0
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    state: str = "open"
    extra_info: str | None = None


@dataclass(slots=True)
class NmapHost:
    """Host-level Nmap scan result with its services."""

    hostname: str
    ip: str | None = None
    services: list[NmapService] = field(default_factory=list)


@dataclass(slots=True)
class NmapResult:
    """Structured result for the Nmap service detection stage."""

    target: TargetInput
    command_result: CommandResult
    hosts: list[NmapHost] = field(default_factory=list)
    services: list[NmapService] = field(default_factory=list)
    host_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class NmapModule:
    """Scan open ports with Nmap and detect running services."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(
        self,
        open_ports: list[str],
        target: TargetInput,
    ) -> NmapResult:
        """Execute Nmap against open ports and return detected services.

        Parameters
        ----------
        open_ports:
            Port strings from the previous naabu stage
            (e.g. ``example.com:80/tcp``).
        target:
            Target metadata attached to the result.
        """
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        executable = self.config.tool_bin("nmap", "nmap")

        host_ports = self._parse_open_ports(open_ports)
        host_count = len(host_ports)

        if not host_ports:
            warnings.append("No open ports were provided")
            command_result = self._empty_command_result(executable)
            hosts: list[NmapHost] = []
            services: list[NmapService] = []
        else:
            args = self._build_nmap_args(host_ports)
            command_result = await self.context.runner.run(
                executable,
                args,
                timeout_seconds=self.context.timeout_seconds,
            )
            hosts, services = self._parse_xml_output(
                command_result.stdout, warnings
            )

        if command_result.missing_executable:
            warnings.append(f"Missing executable: {executable}")
        if command_result.timed_out:
            warnings.append(
                f"Nmap timed out after {self.context.timeout_seconds} seconds"
            )
        if (
            command_result.returncode not in (0, None)
            and not command_result.timed_out
            and not command_result.missing_executable
        ):
            warnings.append(
                f"Nmap failed with exit code {command_result.returncode}"
            )
        if (
            host_ports
            and not services
            and command_result.stdout.strip()
            and not command_result.timed_out
        ):
            warnings.append("No valid XML records were produced")
        if not services:
            warnings.append("No services discovered")

        services = self._deduplicate(services)

        result = NmapResult(
            target=target_input,
            command_result=command_result,
            hosts=hosts,
            services=services,
            host_count=host_count,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    @staticmethod
    def _parse_open_ports(open_ports: list[str]) -> dict[str, set[tuple[int, str]]]:
        """Parse ``host:port/protocol`` strings grouped by host."""
        host_ports: dict[str, set[tuple[int, str]]] = {}
        for entry in open_ports:
            if "/" not in entry or ":" not in entry:
                continue
            host_part, rest = entry.rsplit(":", 1)
            port_str, protocol = rest.split("/", 1)
            host = host_part.strip().lower()
            try:
                port = int(port_str)
            except ValueError:
                continue
            if host not in host_ports:
                host_ports[host] = set()
            host_ports[host].add((port, protocol))
        return host_ports

    @staticmethod
    def _build_nmap_args(
        host_ports: dict[str, set[tuple[int, str]]],
    ) -> list[str]:
        """Build nmap arguments from parsed host-port mapping."""
        all_ports: set[int] = set()
        hostnames = list(host_ports.keys())
        for ports in host_ports.values():
            for port, _ in ports:
                all_ports.add(port)
        port_str = ",".join(str(p) for p in sorted(all_ports))
        return ["-Pn", "-sV", "-oX", "-", "-p", port_str] + hostnames

    def _parse_xml_output(
        self,
        xml_text: str,
        warnings: list[str],
    ) -> tuple[list[NmapHost], list[NmapService]]:
        """Parse Nmap XML output into typed records."""
        hosts: list[NmapHost] = []
        services: list[NmapService] = []

        if not xml_text.strip():
            return hosts, services

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            msg = f"Malformed XML: {exc}"
            logger.warning(msg)
            warnings.append(msg)
            return hosts, services

        for host_elem in root.findall("host"):
            hostname = self._extract_hostname(host_elem)
            if not hostname:
                continue
            ip = self._extract_ip(host_elem)

            host_services: list[NmapService] = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    svc = self._parse_port(hostname, ip, port_elem)
                    if svc is not None:
                        host_services.append(svc)

            hosts.append(
                NmapHost(hostname=hostname, ip=ip, services=host_services)
            )
            services.extend(host_services)

        return hosts, services

    @staticmethod
    def _extract_hostname(host_elem: ET.Element) -> str | None:
        """Extract the primary hostname from a host element."""
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None:
                name = hn.get("name")
                if name:
                    return name.strip().lower()
        return None

    @staticmethod
    def _extract_ip(host_elem: ET.Element) -> str | None:
        """Extract the IP address from a host element."""
        addr = host_elem.find("address")
        if addr is not None:
            ip = addr.get("addr")
            if ip:
                return ip.strip()
        return None

    @staticmethod
    def _parse_port(
        hostname: str,
        ip: str | None,
        port_elem: ET.Element,
    ) -> NmapService | None:
        """Parse a single port element into an NmapService."""
        protocol = port_elem.get("protocol", "tcp")
        port_str = port_elem.get("portid")
        if not port_str:
            return None
        try:
            port = int(port_str)
        except ValueError:
            return None

        state_elem = port_elem.find("state")
        state = "open"
        if state_elem is not None:
            state = state_elem.get("state", "open")

        service_elem = port_elem.find("service")
        service: str | None = None
        product: str | None = None
        version: str | None = None
        extra_info: str | None = None
        if service_elem is not None:
            service = NmapModule._normalize_text(
                service_elem.get("name")
            )
            product = NmapModule._normalize_text(
                service_elem.get("product")
            )
            version = NmapModule._normalize_text(
                service_elem.get("version")
            )
            extra_info = NmapModule._normalize_text(
                service_elem.get("extrainfo")
            )

        return NmapService(
            hostname=hostname,
            ip=ip,
            port=port,
            protocol=protocol,
            service=service,
            product=product,
            version=version,
            state=state,
            extra_info=extra_info,
        )

    @staticmethod
    def _deduplicate(
        services: list[NmapService],
    ) -> list[NmapService]:
        """Deduplicate services by (hostname, port, protocol)."""
        seen: set[tuple[str, int, str]] = set()
        deduped: list[NmapService] = []
        for svc in services:
            key = (svc.hostname, svc.port, svc.protocol)
            if key not in seen:
                seen.add(key)
                deduped.append(svc)
        return deduped

    def _save_results(self, result: NmapResult) -> Path:
        """Persist Nmap results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "hosts": [asdict(host) for host in result.hosts],
            "services": [asdict(svc) for svc in result.services],
            "host_count": result.host_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("web/services.json", payload)

    def _print_summary(self, result: NmapResult) -> None:
        """Print a concise summary of Nmap results."""
        print("----------------------------------------")
        print("Nmap")
        print("----------------------------------------")
        print(f"Hosts Scanned : {result.host_count}")
        print(f"Open Services : {len(result.services)}")

    @staticmethod
    def _empty_command_result(command: str) -> CommandResult:
        """Build a no-op CommandResult for the empty-input case."""
        return CommandResult(
            command=command,
            args=("-Pn", "-sV", "-oX", "-"),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command=command,
        )

    @staticmethod
    def _normalize_text(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        text = value.strip()
        return text or None


__all__ = ["NmapModule", "NmapHost", "NmapResult", "NmapService"]
