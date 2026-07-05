"""Syslog remote forwarding and log rotation security auditing.

Audits rsyslog/syslog-ng configurations for remote forwarding, and logrotate configuration for log retention/compression.
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
class SyslogResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class SyslogModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> SyslogResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_rsys = await self.context.runner.run(cat_cmd, ["/etc/rsyslog.conf"], timeout_seconds=5)

        has_forwarding = False
        if cr_rsys.succeeded and cr_rsys.stdout.strip():
            content = cr_rsys.stdout
            for line in content.splitlines():
                line_stripped = line.strip()
                if line_stripped and not line_stripped.startswith("#") and (" @" in line_stripped or " @@" in line_stripped):
                    has_forwarding = True

        if not has_forwarding:
            findings.append(make_finding(
                title="Syslog remote log forwarding is not configured",
                description="Syslog logs are stored only locally. If the host is compromised, attackers can clear or tamper with local logs to erase tracks. Forwarding logs to a centralized collector (SIEM) prevents this.",
                severity="medium",
                category="vulnerability",
                source_stage="monitoring_security",
                target=target_str,
                evidence="No active '@' or '@@' target forwarding resolved in /etc/rsyslog.conf",
                recommendation="Configure log forwarding by adding '*.* @@<siem-ip>:514' to rsyslog settings.",
                confidence=0.9,
            ))

        cr_rotate = await self.context.runner.run(cat_cmd, ["/etc/logrotate.conf"], timeout_seconds=5)
        has_compress = False
        if cr_rotate.succeeded and cr_rotate.stdout.strip():
            content = cr_rotate.stdout
            for line in content.splitlines():
                if line.strip() == "compress":
                    has_compress = True

        if not has_compress:
            findings.append(make_finding(
                title="Logrotate compression is disabled",
                description="Global logrotate config does not enforce 'compress'. Log archives remain uncompressed, risking disk space exhaustion.",
                severity="low",
                category="misconfiguration",
                source_stage="monitoring_security",
                target=target_str,
                evidence="compress directive is commented out or missing from logrotate.conf",
                recommendation="Add or uncomment the 'compress' directive in /etc/logrotate.conf.",
                confidence=0.9,
            ))

        primary = cr_rsys or cr_rotate or self._empty_command_result()

        result = SyslogResult(
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
            command="syslog",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="syslog",
        )
