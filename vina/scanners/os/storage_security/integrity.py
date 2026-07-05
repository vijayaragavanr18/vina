"""Filesystem integrity and immutability security auditing.

Audits presence of file integrity monitoring tools (AIDE/Tripwire) and checks for immutable files.
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
class IntegrityResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class IntegrityModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> IntegrityResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        which_cmd = self.config.tool_bin("which", "which")
        cr_aide = await self.context.runner.run(which_cmd, ["aide"], timeout_seconds=5)
        cr_trip = await self.context.runner.run(which_cmd, ["tripwire"], timeout_seconds=5)

        has_fim = cr_aide.succeeded or cr_trip.succeeded

        if not has_fim:
            findings.append(
                make_finding(
                    title="File Integrity Monitoring (FIM) not configured",
                    description="No file integrity monitoring tool (e.g. AIDE, Tripwire) was found in PATH. FIM is essential for detecting unauthorized changes, system binaries tampering, or rootkits.",
                    severity="medium",
                    category="vulnerability",
                    source_stage="storage_security",
                    target=target_str,
                    evidence="aide and tripwire executables not resolved in PATH",
                    recommendation="Install and configure AIDE (Advanced Intrusion Detection Environment) to monitor critical directories (e.g. /bin, /sbin, /etc).",
                    confidence=0.9,
                )
            )

        lsattr_cmd = self.config.tool_bin("lsattr", "lsattr")
        cr_attr = await self.context.runner.run(
            lsattr_cmd, ["-d", "/etc/passwd", "/etc/shadow", "/etc/sudoers"], timeout_seconds=5
        )

        immutable_files = []
        if cr_attr.succeeded and cr_attr.stdout.strip():
            for line in cr_attr.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    attrs = parts[0]
                    filepath = parts[1]
                    if "i" in attrs:
                        immutable_files.append(filepath)

        if immutable_files:
            findings.append(
                make_finding(
                    title="Immutable system configuration files detected",
                    description="One or more critical system configuration files have the immutable ('i') attribute set, preventing modification even by the root user. While sometimes used as hardening, it can prevent standard password updates or package operations.",
                    severity="info",
                    category="information",
                    source_stage="storage_security",
                    target=target_str,
                    evidence=f"Immutable files: {', '.join(immutable_files)}",
                    recommendation="Ensure this is intentional and not left by a security incident or malformed deployment.",
                    confidence=0.85,
                )
            )

        primary = cr_aide or cr_attr or self._empty_command_result()

        result = IntegrityResult(
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
            command="integrity",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="integrity",
        )
