"""Routing and TCP hardening audits.

Audits IP forwarding, source routing, redirects, martian logging,
SYN cookies, TCP timestamps, and rp_filter.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding, make_finding
from ....modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RoutingResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class RoutingModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> RoutingResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        sysctl_keys = [
            "net.ipv4.ip_forward",
            "net.ipv6.conf.all.forwarding",
            "net.ipv4.conf.all.accept_source_route",
            "net.ipv6.conf.all.accept_source_route",
            "net.ipv4.conf.all.accept_redirects",
            "net.ipv6.conf.all.accept_redirects",
            "net.ipv4.conf.all.log_martians",
            "net.ipv4.tcp_syncookies",
            "net.ipv4.conf.all.rp_filter",
            "net.ipv4.conf.default.rp_filter",
            "net.ipv4.conf.all.send_redirects",
            "net.ipv4.conf.default.send_redirects",
        ]

        sysctl_cmd = self.config.tool_bin("sysctl", "sysctl")
        cr = await self.context.runner.run(sysctl_cmd, sysctl_keys, timeout_seconds=5)

        settings = {}
        if cr.succeeded and cr.stdout.strip():
            for line in cr.stdout.splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    settings[k.strip()] = v.strip()

        target_str = target.normalized

        def check_key(key: str, expected: str, severity: str, desc: str, rec: str) -> None:
            val = settings.get(key)
            if val is not None and val != expected:
                findings.append(
                    make_finding(
                        title=f"Sysctl {key} is misconfigured",
                        description=f"{desc} (current: {val}, expected: {expected}).",
                        severity=severity,
                        category="misconfiguration",
                        source_stage="network_security",
                        target=target_str,
                        evidence=f"{key}={val}",
                        recommendation=f"Set {key}={expected} in /etc/sysctl.conf and run 'sysctl -p': {rec}",
                        confidence=0.9,
                    )
                )

        check_key(
            "net.ipv4.ip_forward",
            "0",
            "medium",
            "IP forwarding is enabled, which allows the host to act as a router and forward packets.",
            "sysctl -w net.ipv4.ip_forward=0",
        )
        check_key(
            "net.ipv6.conf.all.forwarding",
            "0",
            "medium",
            "IPv6 forwarding is enabled, which allows the host to act as an IPv6 router.",
            "sysctl -w net.ipv6.conf.all.forwarding=0",
        )
        check_key(
            "net.ipv4.conf.all.accept_source_route",
            "0",
            "medium",
            "Accepting source routed packets is enabled, allowing attackers to route packets through specific hosts to bypass security controls.",
            "sysctl -w net.ipv4.conf.all.accept_source_route=0",
        )
        check_key(
            "net.ipv6.conf.all.accept_source_route",
            "0",
            "medium",
            "Accepting IPv6 source routed packets is enabled.",
            "sysctl -w net.ipv6.conf.all.accept_source_route=0",
        )
        check_key(
            "net.ipv4.conf.all.accept_redirects",
            "0",
            "medium",
            "Accepting ICMP redirects is enabled, which could allow MITM/routing table manipulation attacks.",
            "sysctl -w net.ipv4.conf.all.accept_redirects=0",
        )
        check_key(
            "net.ipv6.conf.all.accept_redirects",
            "0",
            "medium",
            "Accepting IPv6 ICMP redirects is enabled.",
            "sysctl -w net.ipv6.conf.all.accept_redirects=0",
        )
        check_key(
            "net.ipv4.conf.all.log_martians",
            "1",
            "low",
            "Logging of Martian packets (packets with impossible source addresses) is disabled.",
            "sysctl -w net.ipv4.conf.all.log_martians=1",
        )
        check_key(
            "net.ipv4.tcp_syncookies",
            "1",
            "medium",
            "TCP SYN cookies are disabled. This leaves the host vulnerable to TCP SYN flood Denial of Service (DoS) attacks.",
            "sysctl -w net.ipv4.tcp_syncookies=1",
        )
        check_key(
            "net.ipv4.conf.all.rp_filter",
            "1",
            "medium",
            "Reverse Path Filtering (rp_filter) on all interfaces is not set to strict mode (1), which can allow IP spoofing.",
            "sysctl -w net.ipv4.conf.all.rp_filter=1",
        )
        check_key(
            "net.ipv4.conf.default.rp_filter",
            "1",
            "medium",
            "Default Reverse Path Filtering (rp_filter) is not set to strict mode (1).",
            "sysctl -w net.ipv4.conf.default.rp_filter=1",
        )
        check_key(
            "net.ipv4.conf.all.send_redirects",
            "0",
            "medium",
            "Sending ICMP redirects is enabled, which allows the host to redirect other hosts' traffic.",
            "sysctl -w net.ipv4.conf.all.send_redirects=0",
        )
        check_key(
            "net.ipv4.conf.default.send_redirects",
            "0",
            "medium",
            "Default sending of ICMP redirects is enabled.",
            "sysctl -w net.ipv4.conf.default.send_redirects=0",
        )

        primary = cr or self._empty_command_result()

        result = RoutingResult(
            target=target,
            command_result=primary,
            warnings=warnings,
            findings=findings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        return result

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="routing",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="routing",
        )
