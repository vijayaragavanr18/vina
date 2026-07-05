"""DNS resolver security configuration audits.

Audits /etc/resolv.conf, insecure resolvers, and DNSSEC resolver options.
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
class DnsResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class DnsModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> DnsResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        cat_cmd = self.config.tool_bin("cat", "cat")
        cr = await self.context.runner.run(cat_cmd, ["/etc/resolv.conf"], timeout_seconds=5)

        nameservers = []
        options = []
        if cr.succeeded and cr.stdout.strip():
            for line in cr.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    if parts[0] == "nameserver":
                        nameservers.append(parts[1])
                    elif parts[0] == "options":
                        options.extend(parts[1:])

        target_str = target.normalized

        if not nameservers:
            findings.append(
                make_finding(
                    title="No DNS nameservers configured",
                    description="/etc/resolv.conf does not define any active nameservers.",
                    severity="low",
                    category="misconfiguration",
                    source_stage="network_security",
                    target=target_str,
                    evidence="No nameserver entries found in /etc/resolv.conf.",
                    recommendation="Configure valid DNS nameservers in network interface settings or /etc/resolv.conf.",
                    confidence=0.9,
                )
            )
        else:
            insecure_public = []
            for ns in nameservers:
                if ns in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"):
                    insecure_public.append(ns)
            if insecure_public:
                findings.append(
                    make_finding(
                        title="Insecure public DNS resolvers configured",
                        description=f"System resolves DNS queries through unencrypted public servers: {', '.join(insecure_public)}.",
                        severity="low",
                        category="misconfiguration",
                        source_stage="network_security",
                        target=target_str,
                        evidence=f"Nameservers: {', '.join(insecure_public)}",
                        recommendation="Configure a local DNS stub resolver (e.g. systemd-resolved) with DNS-over-TLS (DoT) enabled.",
                        confidence=0.8,
                    )
                )

        has_edns = any("edns" in opt for opt in options)
        if not has_edns and nameservers:
            findings.append(
                make_finding(
                    title="DNSSEC validation or EDNS0 options not enforced in resolv.conf",
                    description="The options in /etc/resolv.conf do not specify edns0 or trust-ad options, which are required for DNSSEC authentication validation.",
                    severity="low",
                    category="misconfiguration",
                    source_stage="network_security",
                    target=target_str,
                    evidence=f"Options: {', '.join(options) if options else 'None'}",
                    recommendation="Add 'options edns0' or configure DNSSEC validation in /etc/resolved.conf or resolver configuration.",
                    confidence=0.75,
                )
            )

        primary = cr or self._empty_command_result()

        result = DnsResult(
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
            command="dns",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="dns",
        )
