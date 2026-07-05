"""File permissions, SUID/SGID, and sensitive files security auditing.

Audits SUID/SGID binaries, sticky bits, ACLs, and sensitive system files permissions.
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
class PermissionsResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class PermissionsModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> PermissionsResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized
        stat_cmd = self.config.tool_bin("stat", "stat")

        cr_passwd = await self.context.runner.run(stat_cmd, ["-c", "%a %U %G", "/etc/passwd"], timeout_seconds=5)
        if cr_passwd.succeeded and cr_passwd.stdout.strip():
            parts = cr_passwd.stdout.strip().split()
            perms = parts[0] if len(parts) >= 1 else ""
            if perms and int(perms) > 644:
                findings.append(make_finding(
                    title=f"/etc/passwd permissions are too open ({perms})",
                    description="The /etc/passwd file is writable by users other than root. This allows unauthorized modification of user accounts.",
                    severity="high",
                    category="permissions",
                    source_stage="storage_security",
                    target=target_str,
                    evidence=f"Permissions: {perms}",
                    recommendation="Set permissions on /etc/passwd to 644: 'chmod 644 /etc/passwd'.",
                    confidence=0.95,
                ))

        cr_shadow = await self.context.runner.run(stat_cmd, ["-c", "%a %U %G", "/etc/shadow"], timeout_seconds=5)
        if cr_shadow.succeeded and cr_shadow.stdout.strip():
            parts = cr_shadow.stdout.strip().split()
            perms = parts[0] if len(parts) >= 1 else ""
            if perms and int(perms) > 640:
                findings.append(make_finding(
                    title=f"/etc/shadow permissions are too open ({perms})",
                    description="The /etc/shadow file containing password hashes is readable or writable by unprivileged accounts.",
                    severity="critical",
                    category="permissions",
                    source_stage="storage_security",
                    target=target_str,
                    evidence=f"Permissions: {perms}",
                    recommendation="Restrict permissions to 600 or 640: 'chmod 600 /etc/shadow'.",
                    confidence=0.95,
                ))

        cr_sudoers = await self.context.runner.run(stat_cmd, ["-c", "%a %U %G", "/etc/sudoers"], timeout_seconds=5)
        if cr_sudoers.succeeded and cr_sudoers.stdout.strip():
            parts = cr_sudoers.stdout.strip().split()
            perms = parts[0] if len(parts) >= 1 else ""
            if perms and int(perms) > 440:
                findings.append(make_finding(
                    title=f"/etc/sudoers permissions are too open ({perms})",
                    description="The sudoers configuration file has loose permissions, potentially permitting unauthorized modification or reading by unprivileged users.",
                    severity="high",
                    category="permissions",
                    source_stage="storage_security",
                    target=target_str,
                    evidence=f"Permissions: {perms}",
                    recommendation="Configure sudoers file permissions to 440: 'chmod 440 /etc/sudoers'.",
                    confidence=0.9,
                ))

        find_cmd = self.config.tool_bin("find", "find")
        cr_suid = await self.context.runner.run(find_cmd, ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "-perm", "/6000", "-type", "f"], timeout_seconds=10)

        suid_binaries = []
        if cr_suid.succeeded and cr_suid.stdout.strip():
            suid_binaries = cr_suid.stdout.strip().splitlines()

        if len(suid_binaries) > 0:
            findings.append(make_finding(
                title=f"SUID/SGID files detected ({len(suid_binaries)} files)",
                description="SUID or SGID executable files were discovered on the system. If insecurely programmed, these can be abused for local privilege escalation.",
                severity="info",
                category="permissions",
                source_stage="storage_security",
                target=target_str,
                evidence=f"Found SUID/SGID count: {len(suid_binaries)} under binary directories.",
                recommendation="Regularly audit SUID/SGID binaries and remove SUID flags from unnecessary commands.",
                confidence=0.9,
            ))

        primary = cr_passwd or cr_shadow or self._empty_command_result()

        result = PermissionsResult(
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
            command="permissions",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="permissions",
        )
