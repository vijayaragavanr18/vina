"""Auditd and journald logging security audits.

Checks if auditd is active, parses loaded audit rules, and checks journald configuration.
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
class AuditingResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class AuditingModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> AuditingResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        pgrep_cmd = self.config.tool_bin("pgrep", "pgrep")
        cr_auditd = await self.context.runner.run(pgrep_cmd, ["-x", "auditd"], timeout_seconds=5)

        if not cr_auditd.succeeded:
            findings.append(make_finding(
                title="auditd auditing daemon is not running",
                description="The auditd daemon is not active. The system cannot perform kernel-level auditing of file access, privilege execution, or user actions.",
                severity="high",
                category="vulnerability",
                source_stage="monitoring_security",
                target=target_str,
                evidence="auditd process not running",
                recommendation="Enable and start auditd: 'systemctl enable --now auditd'.",
                confidence=0.9,
            ))
        else:
            auditctl_cmd = self.config.tool_bin("auditctl", "auditctl")
            cr_rules = await self.context.runner.run(auditctl_cmd, ["-l"], timeout_seconds=5)

            rules_str = ""
            if cr_rules.succeeded and cr_rules.stdout.strip():
                rules_str = cr_rules.stdout

            if "-a always,exit" not in rules_str or "execve" not in rules_str:
                findings.append(make_finding(
                    title="Audit rules do not track process execution (execve)",
                    description="No audit rules were found for auditing the execve system call. This prevents tracking what commands users or attackers run on the host.",
                    severity="medium",
                    category="misconfiguration",
                    source_stage="monitoring_security",
                    target=target_str,
                    evidence="Missing execve audit rules in loaded config",
                    recommendation="Add '-a always,exit -F arch=b64 -S execve' to /etc/audit/rules.d/audit.rules.",
                    confidence=0.85,
                ))

        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_j = await self.context.runner.run(cat_cmd, ["/etc/systemd/journald.conf"], timeout_seconds=5)

        if cr_j.succeeded and cr_j.stdout.strip():
            content = cr_j.stdout
            storage_persistent = False
            for line in content.splitlines():
                line = line.strip().replace(" ", "")
                if line.startswith("Storage="):
                    val = line.partition("=")[2]
                    if val.lower() == "persistent":
                        storage_persistent = True

            if not storage_persistent:
                findings.append(make_finding(
                    title="Systemd journald storage is not persistent",
                    description="Journald is configured to use volatile storage (in-memory) or auto storage. Logs will be lost on system reboot, hindering post-incident forensics.",
                    severity="medium",
                    category="misconfiguration",
                    source_stage="monitoring_security",
                    target=target_str,
                    evidence="Storage is not set to persistent in journald.conf",
                    recommendation="Configure 'Storage=persistent' in /etc/systemd/journald.conf.",
                    confidence=0.9,
                ))

        primary = cr_auditd or cr_j or self._empty_command_result()

        result = AuditingResult(
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
            command="auditing",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="auditing",
        )
