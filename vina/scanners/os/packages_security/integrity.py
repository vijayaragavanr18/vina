"""Package integrity and verification audits.

Audits installed package integrity, including: modified packages, missing signatures,
verification failures, orphaned packages, held packages, and partially installed packages.
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

        apt_mark = self.config.tool_bin("apt-mark", "apt-mark")
        cr_held = await self.context.runner.run(apt_mark, ["showhold"], timeout_seconds=5)
        if cr_held.succeeded and cr_held.stdout.strip():
            held_pkgs = [line.strip() for line in cr_held.stdout.splitlines() if line.strip()]
            if held_pkgs:
                findings.append(make_finding(
                    title=f"Held packages detected ({len(held_pkgs)} found)",
                    description="Held packages are prevented from being upgraded automatically, which can leave security vulnerabilities unpatched.",
                    severity="low",
                    category="misconfiguration",
                    source_stage="packages_security",
                    target=target.normalized,
                    evidence=f"Held packages: {', '.join(held_pkgs[:10])}",
                    recommendation="Review held packages and unhold them if not strictly necessary: apt-mark unhold <package>.",
                    confidence=0.85,
                ))

        dpkg_cmd = self.config.tool_bin("dpkg", "dpkg")
        cr_audit = await self.context.runner.run(dpkg_cmd, ["--audit"], timeout_seconds=5)
        if cr_audit.succeeded and cr_audit.stdout.strip():
            findings.append(make_finding(
                title="Broken or partially installed packages detected",
                description="dpkg --audit reported broken or half-installed packages on the system.",
                severity="medium",
                category="misconfiguration",
                source_stage="packages_security",
                target=target.normalized,
                evidence=cr_audit.stdout.strip()[:300],
                recommendation="Fix broken packages: apt-get install -f or dpkg --configure -a.",
                confidence=0.9,
            ))

        debsums_cmd = self.config.tool_bin("debsums", "debsums")
        cr_debsums = await self.context.runner.run(debsums_cmd, ["-c"], timeout_seconds=10)
        if cr_debsums.stdout.strip():
            modified_files = [line.strip() for line in cr_debsums.stdout.splitlines() if line.strip()]
            if modified_files:
                findings.append(make_finding(
                    title=f"Modified package files detected ({len(modified_files)} files)",
                    description="Installed package files have been modified. This could indicate local edits or unauthorized modification/tampering by malware.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="packages_security",
                    target=target.normalized,
                    evidence="Modified files:\n" + "\n".join(modified_files[:10]),
                    recommendation="Reinstall modified packages to restore integrity: apt-get install --reinstall <package>.",
                    confidence=0.8,
                ))

        deborphan_cmd = self.config.tool_bin("deborphan", "deborphan")
        cr_orphan = await self.context.runner.run(deborphan_cmd, [], timeout_seconds=5)
        if cr_orphan.succeeded and cr_orphan.stdout.strip():
            orphans = [line.strip() for line in cr_orphan.stdout.splitlines() if line.strip()]
            if orphans:
                findings.append(make_finding(
                    title=f"Orphaned packages detected ({len(orphans)} found)",
                    description="Orphaned packages are no longer supported by any active repository and will not receive security updates.",
                    severity="low",
                    category="misconfiguration",
                    source_stage="packages_security",
                    target=target.normalized,
                    evidence=f"Orphaned: {', '.join(orphans[:10])}",
                    recommendation="Remove orphaned packages: apt-get purge $(deborphan).",
                    confidence=0.75,
                ))

        rpm_cmd = self.config.tool_bin("rpm", "rpm")
        cr_rpm = await self.context.runner.run(rpm_cmd, ["-qa", "--qf", "%{NAME} %{SIGGPG:pgpsig}\n"], timeout_seconds=10)
        if cr_rpm.succeeded and cr_rpm.stdout.strip():
            unsigned = []
            for line in cr_rpm.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) == 1 or (len(parts) > 1 and "none" in parts[1].lower()):
                    unsigned.append(parts[0])
            if unsigned:
                findings.append(make_finding(
                    title=f"Unsigned RPM packages detected ({len(unsigned)} found)",
                    description="Installed RPM packages lack GPG signatures. Packages without GPG signatures cannot be verified for authenticity.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="packages_security",
                    target=target.normalized,
                    evidence=f"Unsigned: {', '.join(unsigned[:10])}",
                    recommendation="Remove unsigned packages or replace them with signed equivalents from official repositories.",
                    confidence=0.85,
                ))

        primary = cr_held or cr_audit or cr_debsums or cr_orphan or cr_rpm or self._empty_command_result()

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
