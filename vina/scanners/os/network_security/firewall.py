"""Firewall status and rules audits.

Audits ufw, firewalld, iptables, and nftables.
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
class FirewallResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class FirewallModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> FirewallResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        ufw_cmd = self.config.tool_bin("ufw", "ufw")
        firewall_cmd = self.config.tool_bin("firewall-cmd", "firewall-cmd")
        iptables_cmd = self.config.tool_bin("iptables", "iptables")
        nft_cmd = self.config.tool_bin("nft", "nft")

        cr_ufw = await self.context.runner.run(ufw_cmd, ["status"], timeout_seconds=5)
        ufw_active = False
        if cr_ufw.succeeded and "active" in cr_ufw.stdout.lower() and "inactive" not in cr_ufw.stdout.lower():
            ufw_active = True

        cr_fwd = await self.context.runner.run(firewall_cmd, ["--state"], timeout_seconds=5)
        fwd_active = False
        if cr_fwd.succeeded and "running" in cr_fwd.stdout.lower():
            fwd_active = True

        cr_ipt = await self.context.runner.run(iptables_cmd, ["-L", "-n"], timeout_seconds=5)
        ipt_active = False
        if cr_ipt.succeeded and cr_ipt.stdout.strip():
            lines = cr_ipt.stdout.splitlines()
            rule_count = sum(
                1 for line in lines if line.strip() and not line.startswith("Chain") and not line.startswith("target")
            )
            if rule_count > 0:
                ipt_active = True

        cr_nft = await self.context.runner.run(nft_cmd, ["list", "ruleset"], timeout_seconds=5)
        nft_active = False
        if cr_nft.succeeded and cr_nft.stdout.strip():
            nft_active = True

        if not (ufw_active or fwd_active or ipt_active or nft_active):
            findings.append(
                make_finding(
                    title="Firewall is disabled or has no rules",
                    description="No active firewall configuration (UFW, Firewalld, iptables, or nftables) was detected on the host.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="network_security",
                    target=target.normalized,
                    evidence="No active firewall rules detected in UFW, Firewalld, iptables, or nftables.",
                    recommendation="Enable a firewall service (e.g. 'ufw enable' or 'systemctl enable --now firewalld') and configure inbound/outbound rules.",
                    confidence=0.9,
                )
            )
        else:
            evidence_parts = []
            if ufw_active:
                evidence_parts.append("UFW (active)")
            if fwd_active:
                evidence_parts.append("Firewalld (active)")
            if ipt_active:
                evidence_parts.append("iptables (active rules)")
            if nft_active:
                evidence_parts.append("nftables (active rules)")
            findings.append(
                make_finding(
                    title="Firewall is enabled",
                    description=f"Active firewall configuration detected: {', '.join(evidence_parts)}.",
                    severity="info",
                    category="security_control",
                    source_stage="network_security",
                    target=target.normalized,
                    evidence=f"Active firewalls: {', '.join(evidence_parts)}",
                    confidence=0.9,
                )
            )

        primary = cr_ufw or cr_fwd or cr_ipt or cr_nft or self._empty_command_result()

        result = FirewallResult(
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
            command="firewall",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="firewall",
        )
