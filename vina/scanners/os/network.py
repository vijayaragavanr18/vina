"""OS-level network-discovery stage.

Collects network interfaces, listening ports, and routing tables
using ip/ifconfig, ss/netstat, and ip route/route through
AsyncCommandRunner.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
import re

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NetworkInterface:
    """A single network interface entry."""

    name: str
    state: str | None = None
    mac_address: str | None = None
    ipv4_addresses: list[str] = field(default_factory=list)
    ipv6_addresses: list[str] = field(default_factory=list)
    mtu: int | None = None
    source_command: str | None = None


@dataclass(slots=True)
class ListeningPort:
    """A single listening port entry."""

    protocol: str
    local_address: str
    port: int
    process: str | None = None
    pid: int | None = None
    source_command: str | None = None


@dataclass(slots=True)
class RouteEntry:
    """A single routing table entry."""

    destination: str
    gateway: str | None = None
    interface: str | None = None
    source_command: str | None = None


@dataclass(slots=True)
class NetworkResult:
    """Structured result for the network-discovery stage."""

    target: TargetInput
    command_result: CommandResult
    interfaces: list[NetworkInterface] = field(default_factory=list)
    listening_ports: list[ListeningPort] = field(default_factory=list)
    routes: list[RouteEntry] = field(default_factory=list)
    interface_count: int = 0
    listening_port_count: int = 0
    route_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class NetworkModule:
    """Collect network information using ip/ifconfig, ss/netstat, and route."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(
        self,
        target: TargetInput,
    ) -> NetworkResult:
        """Execute system commands and return discovered network data.

        Parameters
        ----------
        target:
            Target metadata attached to the result.
        """
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            (
                "ip_addr",
                self.config.tool_bin("ip", "ip"),
                ["addr"],
            ),
            (
                "ifconfig",
                self.config.tool_bin("ifconfig", "ifconfig"),
                [],
            ),
            (
                "ip_route",
                self.config.tool_bin("ip", "ip"),
                ["route"],
            ),
            (
                "route_n",
                self.config.tool_bin("route", "route"),
                ["-n"],
            ),
            (
                "ss",
                self.config.tool_bin("ss", "ss"),
                ["-tulpen"],
            ),
            (
                "netstat",
                self.config.tool_bin("netstat", "netstat"),
                ["-tulpen"],
            ),
        ]

        results: dict[str, CommandResult] = {}
        for name, executable, args in commands:
            cr = await self.context.runner.run(
                executable,
                args,
                timeout_seconds=self.context.timeout_seconds,
            )
            results[name] = cr
            if cr.missing_executable:
                warnings.append(f"Missing executable: {executable}")
            if cr.timed_out:
                warnings.append(
                    f"{name} timed out after {self.context.timeout_seconds}s"
                )
            if cr.returncode not in (0, None) and not cr.timed_out and not cr.missing_executable:
                stderr_snippet = cr.stderr.strip()[:120] if cr.stderr.strip() else ""
                msg = f"{name} exited with code {cr.returncode}"
                if stderr_snippet:
                    msg += f": {stderr_snippet}"
                warnings.append(msg)

        interfaces = self._parse_interfaces(results, warnings)
        listening_ports = self._parse_listening_ports(results, warnings)
        routes = self._parse_routes(results, warnings)

        if not interfaces:
            warnings.append("No network interfaces could be discovered")
        if not listening_ports:
            warnings.append("No listening ports could be discovered")
        if not routes:
            warnings.append("No routes could be discovered")

        primary = (
            results.get("ip_addr")
            or results.get("ifconfig")
            or results.get("ip_route")
            or results.get("route_n")
            or results.get("ss")
            or results.get("netstat")
            or self._empty_command_result()
        )

        result = NetworkResult(
            target=target_input,
            command_result=primary,
            interfaces=interfaces,
            listening_ports=listening_ports,
            routes=routes,
            interface_count=len(interfaces),
            listening_port_count=len(listening_ports),
            route_count=len(routes),
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    # ------------------------------------------------------------------
    # Interface parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_interfaces(
        results: dict[str, CommandResult],
        warnings: list[str],
    ) -> list[NetworkInterface]:
        """Parse interface data from ``ip addr`` or fallback ``ifconfig``."""
        cr = results.get("ip_addr")
        if cr and cr.succeeded and cr.stdout.strip():
            return NetworkModule._parse_ip_addr(cr.stdout, warnings)
        cr = results.get("ifconfig")
        if cr and cr.succeeded and cr.stdout.strip():
            return NetworkModule._parse_ifconfig(cr.stdout, warnings)
        return []

    @staticmethod
    def _parse_ip_addr(stdout: str, warnings: list[str]) -> list[NetworkInterface]:
        """Parse ``ip addr`` output into NetworkInterface objects."""
        interfaces: list[NetworkInterface] = []
        current: NetworkInterface | None = None

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^(\d+):\s+(\S+):", line)
            if m:
                if current is not None:
                    interfaces.append(current)
                name = m.group(2)
                mtu_m = re.search(r"mtu\s+(\d+)", line)
                mtu = int(mtu_m.group(1)) if mtu_m else None
                state_m = re.search(r"state\s+(\S+)", line)
                state = state_m.group(1) if state_m else None
                current = NetworkInterface(
                    name=name,
                    state=state,
                    mtu=mtu,
                    source_command="ip addr",
                )
                continue
            if current is None:
                continue
            if line.startswith("link/ether"):
                parts = line.split()
                if len(parts) >= 2:
                    current.mac_address = parts[1]
            elif line.startswith("inet "):
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[1]
                    current.ipv4_addresses.append(addr)
            elif line.startswith("inet6 "):
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[1]
                    current.ipv6_addresses.append(addr)

        if current is not None:
            interfaces.append(current)

        return interfaces

    @staticmethod
    def _parse_ifconfig(stdout: str, warnings: list[str]) -> list[NetworkInterface]:
        """Parse ``ifconfig`` output into NetworkInterface objects."""
        interfaces: list[NetworkInterface] = []
        current: NetworkInterface | None = None

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current is not None:
                    interfaces.append(current)
                    current = None
                continue
            m = re.match(r"^(\S+?):\s+flags=", line)
            if m:
                if current is not None:
                    interfaces.append(current)
                name = m.group(1)
                mtu_m = re.search(r"mtu\s+(\d+)", line)
                mtu = int(mtu_m.group(1)) if mtu_m else None
                flags_raw = line.split("flags=", 1)[1] if "flags=" in line else ""
                inner = flags_raw.split("<", 1)[1].split(">", 1)[0] if "<" in flags_raw else ""
                state = "UP" if "UP" in inner else "UNKNOWN"
                current = NetworkInterface(
                    name=name,
                    state=state,
                    mtu=mtu,
                    source_command="ifconfig",
                )
                continue
            if current is None:
                continue
            if line.startswith("inet "):
                parts = line.split()
                if len(parts) >= 2:
                    current.ipv4_addresses.append(parts[1])
            elif line.startswith("inet6 "):
                parts = line.split()
                if len(parts) >= 2:
                    current.ipv6_addresses.append(parts[1])
            elif line.startswith("ether "):
                parts = line.split()
                if len(parts) >= 2:
                    current.mac_address = parts[1]

        if current is not None:
            interfaces.append(current)

        return interfaces

    # ------------------------------------------------------------------
    # Listening port parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_listening_ports(
        results: dict[str, CommandResult],
        warnings: list[str],
    ) -> list[ListeningPort]:
        """Parse port data from ``ss -tulpen`` or fallback ``netstat -tulpen``."""
        cr = results.get("ss")
        if cr and cr.succeeded and cr.stdout.strip():
            return NetworkModule._parse_ss(cr.stdout, warnings)
        cr = results.get("netstat")
        if cr and cr.succeeded and cr.stdout.strip():
            return NetworkModule._parse_netstat(cr.stdout, warnings)
        return []

    @staticmethod
    def _parse_ss(stdout: str, warnings: list[str]) -> list[ListeningPort]:
        """Parse ``ss -tulpen`` output into ListeningPort objects."""
        ports: list[ListeningPort] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("Netid") or line.startswith("State"):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            try:
                netid = parts[0]
                local = parts[4]
                local = local.strip("[]")
                if ":" not in local:
                    continue
                addr_part, port_str = local.rsplit(":", 1)
                if not port_str.isdigit():
                    continue
                port = int(port_str)
                local_address = f"{addr_part}:{port}"

                process: str | None = None
                pid: int | None = None
                proc_part = " ".join(parts[5:]) if len(parts) > 5 else ""
                pm = re.search(r'users:\(\(["\'](.+?)["\'],pid=(\d+),', proc_part)
                if pm:
                    process = pm.group(1)
                    pid = int(pm.group(2))

                ports.append(
                    ListeningPort(
                        protocol=netid,
                        local_address=local_address,
                        port=port,
                        process=process,
                        pid=pid,
                        source_command="ss",
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse ss line: {line}")
        return ports

    @staticmethod
    def _parse_netstat(stdout: str, warnings: list[str]) -> list[ListeningPort]:
        """Parse ``netstat -tulpen`` output into ListeningPort objects."""
        ports: list[ListeningPort] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("Proto") or line.startswith("Active"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                proto = parts[0]
                local = parts[3]
                local = local.strip("[]")
                if ":" not in local:
                    continue
                addr_part, port_str = local.rsplit(":", 1)
                if not port_str.isdigit():
                    continue
                port = int(port_str)
                local_address = f"{addr_part}:{port}"

                process: str | None = None
                pid: int | None = None
                pid_field = parts[-1] if len(parts) >= 7 else ""
                pm = re.match(r"(\d+)/(.+)", pid_field)
                if pm:
                    pid = int(pm.group(1))
                    process = pm.group(2)

                ports.append(
                    ListeningPort(
                        protocol=proto,
                        local_address=local_address,
                        port=port,
                        process=process,
                        pid=pid,
                        source_command="netstat",
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse netstat line: {line}")
        return ports

    # ------------------------------------------------------------------
    # Route parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_routes(
        results: dict[str, CommandResult],
        warnings: list[str],
    ) -> list[RouteEntry]:
        """Parse route data from ``ip route`` or fallback ``route -n``."""
        cr = results.get("ip_route")
        if cr and cr.succeeded and cr.stdout.strip():
            return NetworkModule._parse_ip_route(cr.stdout, warnings)
        cr = results.get("route_n")
        if cr and cr.succeeded and cr.stdout.strip():
            return NetworkModule._parse_route_n(cr.stdout, warnings)
        return []

    @staticmethod
    def _parse_ip_route(stdout: str, warnings: list[str]) -> list[RouteEntry]:
        """Parse ``ip route`` output into RouteEntry objects.

        Format: <destination> [via <gateway>] dev <interface> ...
        """
        routes: list[RouteEntry] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                dest = line.split()[0] if line.split() else ""
                gateway: str | None = None
                interface: str | None = None
                via_m = re.search(r"via\s+(\S+)", line)
                if via_m:
                    gateway = via_m.group(1)
                dev_m = re.search(r"dev\s+(\S+)", line)
                if dev_m:
                    interface = dev_m.group(1)
                if not dest:
                    continue
                routes.append(
                    RouteEntry(
                        destination=dest,
                        gateway=gateway,
                        interface=interface,
                        source_command="ip route",
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse ip route line: {line}")
        return routes

    @staticmethod
    def _parse_route_n(stdout: str, warnings: list[str]) -> list[RouteEntry]:
        """Parse ``route -n`` output into RouteEntry objects.

        Format: Destination  Gateway  Genmask  Flags  Metric  Ref  Use  Iface
        """
        routes: list[RouteEntry] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Kernel") or line.startswith("Destination") or line.startswith("Iface"):
                continue
            parts = line.split()
            if len(parts) < 8:
                continue
            try:
                dest = parts[0]
                gateway = parts[1]
                mask = parts[2]
                iface = parts[7]
                if mask and mask != "0.0.0.0" and dest != "0.0.0.0":
                    dest = f"{dest}/{mask}"
                elif mask == "0.0.0.0" and dest == "0.0.0.0":
                    dest = "default"
                routes.append(
                    RouteEntry(
                        destination=dest,
                        gateway=gateway if gateway != "0.0.0.0" else None,
                        interface=iface,
                        source_command="route -n",
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse route -n line: {line}")
        return routes

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate_interfaces(
        interfaces: list[NetworkInterface],
    ) -> list[NetworkInterface]:
        """Deduplicate interfaces by name."""
        seen: dict[str, NetworkInterface] = {}
        for iface in interfaces:
            if iface.name not in seen:
                seen[iface.name] = iface
        return list(seen.values())

    @staticmethod
    def _deduplicate_ports(
        ports: list[ListeningPort],
    ) -> list[ListeningPort]:
        """Deduplicate listening ports by (protocol, local_address, port)."""
        seen: set[tuple[str, str, int]] = set()
        deduped: list[ListeningPort] = []
        for p in ports:
            key = (p.protocol, p.local_address, p.port)
            if key not in seen:
                seen.add(key)
                deduped.append(p)
        return deduped

    @staticmethod
    def _deduplicate_routes(
        routes: list[RouteEntry],
    ) -> list[RouteEntry]:
        """Deduplicate routes by (destination, gateway, interface)."""
        seen: set[tuple[str, str | None, str | None]] = set()
        deduped: list[RouteEntry] = []
        for r in routes:
            key = (r.destination, r.gateway, r.interface)
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        return deduped

    # ------------------------------------------------------------------
    # Save / Print / Helpers
    # ------------------------------------------------------------------

    def _save_results(self, result: NetworkResult) -> Path:
        """Persist network results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "interfaces": [asdict(i) for i in result.interfaces],
            "listening_ports": [asdict(p) for p in result.listening_ports],
            "routes": [asdict(r) for r in result.routes],
            "interface_count": result.interface_count,
            "listening_port_count": result.listening_port_count,
            "route_count": result.route_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("os/network.json", payload)

    def _print_summary(self, result: NetworkResult) -> None:
        """Print a concise summary of discovered network data."""
        print("----------------------------------------")
        print("Network")
        print("----------------------------------------")
        print(f"Interfaces      : {result.interface_count}")
        print(f"Listening Ports : {result.listening_port_count}")
        print(f"Routes          : {result.route_count}")
        if result.warnings:
            print(f"Warnings        : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        """Build a no-op CommandResult for the no-data case."""
        return CommandResult(
            command="network",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="network",
        )


__all__ = ["NetworkModule", "NetworkInterface", "ListeningPort", "RouteEntry", "NetworkResult"]
