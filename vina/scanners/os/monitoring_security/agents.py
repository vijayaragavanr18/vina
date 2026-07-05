"""Security monitoring agents status auditing.

Checks for active Host Intrusion Detection Systems (HIDS) and log monitors like fail2ban, OSSEC, and Wazuh.
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
class AgentsResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class AgentsModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> AgentsResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        pgrep_cmd = self.config.tool_bin("pgrep", "pgrep")
        cr_f2b = await self.context.runner.run(pgrep_cmd, ["-x", "fail2ban-server"], timeout_seconds=5)
        cr_wz = await self.context.runner.run(pgrep_cmd, ["-f", "wazuh-agent"], timeout_seconds=5)
        cr_ossec = await self.context.runner.run(pgrep_cmd, ["-f", "ossec"], timeout_seconds=5)

        has_hids = cr_wz.succeeded or cr_ossec.succeeded

        if not cr_f2b.succeeded:
            findings.append(make_finding(
                title="fail2ban brute-force protection is not running",
                description="The fail2ban logging monitor daemon is not active. The host lacks automated firewall blocking against persistent ssh or web service brute-force attacks.",
                severity="medium",
                category="vulnerability",
                source_stage="monitoring_security",
                target=target_str,
                evidence="fail2ban-server process not running",
                recommendation="Install and enable fail2ban: 'apt-get install fail2ban && systemctl enable --now fail2ban'.",
                confidence=0.9,
            ))

        if not has_hids:
            findings.append(make_finding(
                title="No active Host Intrusion Detection System (HIDS) resolved",
                description="No active Wazuh or OSSEC agent processes were discovered. System events, files modifications, and security logs are not being monitored or reported in real time.",
                severity="medium",
                category="vulnerability",
                source_stage="monitoring_security",
                target=target_str,
                evidence="No Wazuh or OSSEC process active",
                recommendation="Install and register a central SIEM/HIDS agent (e.g. Wazuh agent).",
                confidence=0.85,
            ))

        primary = cr_f2b or cr_wz or self._empty_command_result()

        result = AgentsResult(
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
            command="agents",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="agents",
        )
