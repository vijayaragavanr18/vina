"""Listening services and exposed ports audits.

Checks listening ports, wildcard binds, privileged ports, remote services,
web services, mail services, and databases on IPv4 and IPv6.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding, make_finding
from ....modules.common import ModuleContext

logger = logging.getLogger(__name__)

DB_PORTS = {3306: "MySQL", 33060: "MySQL X", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}

REMOTE_PORTS = {
    22: "SSH",
    21: "FTP Control",
    20: "FTP Data",
    23: "Telnet",
    139: "NetBIOS",
    445: "SMB",
    2049: "NFS",
    111: "RPCBind",
    3389: "RDP",
}

VNC_PORT_RE = re.compile(r"^590\d$")

WEB_PORTS = {80: "HTTP", 443: "HTTPS", 8080: "HTTP Alternative", 8443: "HTTPS Alternative"}

MAIL_PORTS = {25: "SMTP", 465: "SMTPS", 587: "SMTP Submission", 110: "POP3", 995: "POP3S", 143: "IMAP", 993: "IMAPS"}


@dataclass(slots=True)
class PortInfo:
    protocol: str
    address: str
    port: int
    process: str = "unknown"
    pid: int | None = None
    is_wildcard: bool = False
    is_ipv6: bool = False


@dataclass(slots=True)
class ListeningServicesResult:
    target: TargetInput
    command_result: CommandResult
    listening_ports: list[PortInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class ListeningServicesModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> ListeningServicesResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []
        listening_ports: list[PortInfo] = []

        ss_cmd = self.config.tool_bin("ss", "ss")
        cr = await self.context.runner.run(ss_cmd, ["-tulpen"], timeout_seconds=5)

        if cr.succeeded and cr.stdout.strip():
            for line in cr.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("Netid") or line.startswith("State"):
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

                    is_wildcard = addr_part in ("0.0.0.0", "::", "*")  # nosec: B104
                    is_ipv6 = ":" in addr_part and addr_part != "0.0.0.0"  # nosec: B104

                    process = "unknown"
                    pid = None
                    proc_part = " ".join(parts[5:]) if len(parts) > 5 else ""
                    pm = re.search(r'users:\(\(["\'](.+?)["\'],pid=(\d+),', proc_part)
                    if pm:
                        process = pm.group(1)
                        pid = int(pm.group(2))

                    listening_ports.append(
                        PortInfo(
                            protocol=netid,
                            address=addr_part,
                            port=port,
                            process=process,
                            pid=pid,
                            is_wildcard=is_wildcard,
                            is_ipv6=is_ipv6,
                        )
                    )
                except (IndexError, ValueError):
                    pass

        target_str = target.normalized

        for p in listening_ports:
            if p.port < 1024:
                findings.append(
                    make_finding(
                        title=f"Privileged port listening: {p.port} ({p.process})",
                        description=f"Port {p.port} (protocol: {p.protocol}) is a privileged port used by process '{p.process}'. Privileged ports (< 1024) require root permissions to bind.",
                        severity="info",
                        category="information",
                        source_stage="network_security",
                        target=target_str,
                        evidence=f"Port: {p.port}, Process: {p.process}",
                        confidence=0.9,
                    )
                )

            if p.port in DB_PORTS:
                db_name = DB_PORTS[p.port]
                sev = "high" if p.is_wildcard else "low"
                findings.append(
                    make_finding(
                        title=f"Exposed database service: {db_name} (port {p.port})",
                        description=f"The database service '{db_name}' is listening on port {p.port} (process: {p.process})."
                        + (
                            " It is bound to all interfaces (wildcard bind), exposing it to the network."
                            if p.is_wildcard
                            else " It is bound to local interface."
                        ),
                        severity=sev,
                        category="vulnerability" if p.is_wildcard else "security_control",
                        source_stage="network_security",
                        target=target_str,
                        evidence=f"Database: {db_name}, Port: {p.port}, Wildcard: {p.is_wildcard}",
                        recommendation="Restrict database access to localhost or secure VPN subnet. Avoid wildcard binds in production.",
                        confidence=0.9,
                    )
                )

            if p.port in REMOTE_PORTS or VNC_PORT_RE.match(str(p.port)):
                svc_name = REMOTE_PORTS.get(p.port, "VNC")
                sev = "medium"
                if p.port in (23, 21):
                    sev = "high"
                if p.is_wildcard:
                    sev = "critical" if sev == "high" else "high"

                findings.append(
                    make_finding(
                        title=f"Exposed remote service: {svc_name} (port {p.port})",
                        description=f"The remote access service '{svc_name}' is active on port {p.port}."
                        + (
                            " It is exposed to the wildcard address, allowing network connections."
                            if p.is_wildcard
                            else " It is bound locally."
                        ),
                        severity=sev,
                        category="vulnerability" if p.is_wildcard else "security_control",
                        source_stage="network_security",
                        target=target_str,
                        evidence=f"Service: {svc_name}, Port: {p.port}, Wildcard: {p.is_wildcard}",
                        recommendation="Disable insecure services (Telnet/FTP) and restrict SSH/RDP to trusted IPs only.",
                        confidence=0.9,
                    )
                )

            if p.port in WEB_PORTS:
                web_name = WEB_PORTS[p.port]
                findings.append(
                    make_finding(
                        title=f"Active Web service: {web_name} (port {p.port})",
                        description=f"Web server '{p.process}' is active on port {p.port}.",
                        severity="info",
                        category="information",
                        source_stage="network_security",
                        target=target_str,
                        evidence=f"Web server: {p.process}, Port: {p.port}",
                        confidence=0.85,
                    )
                )

            if p.port in MAIL_PORTS:
                mail_name = MAIL_PORTS[p.port]
                findings.append(
                    make_finding(
                        title=f"Active Mail service: {mail_name} (port {p.port})",
                        description=f"Mail handler '{p.process}' is active on port {p.port}.",
                        severity="info",
                        category="information",
                        source_stage="network_security",
                        target=target_str,
                        evidence=f"Mail process: {p.process}, Port: {p.port}",
                        confidence=0.85,
                    )
                )

        primary = cr or self._empty_command_result()

        result = ListeningServicesResult(
            target=target,
            command_result=primary,
            listening_ports=listening_ports,
            warnings=warnings,
            findings=findings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        return result

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="listening_services",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="listening_services",
        )
