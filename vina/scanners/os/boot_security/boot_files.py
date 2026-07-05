"""Bootloader and initramfs files security auditing.

Audits file ownership, permissions, and checks for tampering in /boot directory.
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
class BootFilesResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class BootFilesModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> BootFilesResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        find_cmd = self.config.tool_bin("find", "find")

        cr_owners = await self.context.runner.run(find_cmd, ["/boot", "-maxdepth", "2", "!", "-user", "root", "-printf", "%p %u\\n"], timeout_seconds=10)
        if cr_owners.succeeded and cr_owners.stdout.strip():
            non_root_files = cr_owners.stdout.strip().splitlines()
            findings.append(make_finding(
                title="Boot files not owned by root",
                description="One or more files under /boot are not owned by the root user, which is a significant privilege exposure.",
                severity="high",
                category="permissions",
                source_stage="boot_security",
                target=target_str,
                evidence="\n".join(non_root_files[:10]) + (f"\n... total {len(non_root_files)} files" if len(non_root_files) > 10 else ""),
                recommendation="Run 'chown -R root:root /boot' to restore proper ownership.",
                confidence=0.9,
            ))

        cr_writable = await self.context.runner.run(find_cmd, ["/boot", "-maxdepth", "2", "-perm", "-002", "-type", "f"], timeout_seconds=10)
        if cr_writable.succeeded and cr_writable.stdout.strip():
            writable_files = cr_writable.stdout.strip().splitlines()
            findings.append(make_finding(
                title="World-writable files detected in /boot",
                description="World-writable files were discovered in the boot directory. Any local user can overwrite them to manipulate boot configuration or execute payloads.",
                severity="critical",
                category="permissions",
                source_stage="boot_security",
                target=target_str,
                evidence="\n".join(writable_files[:10]) + (f"\n... total {len(writable_files)} files" if len(writable_files) > 10 else ""),
                recommendation="Remove world-write permissions from boot files: 'chmod o-w /boot/file'.",
                confidence=0.95,
            ))

        cr_initrd = await self.context.runner.run(find_cmd, ["/boot", "-maxdepth", "2", "-name", "initrd.img*", "-o", "-name", "initramfs*", "-printf", "%p %a\\n"], timeout_seconds=10)
        if cr_initrd.succeeded and cr_initrd.stdout.strip():
            initrd_lines = cr_initrd.stdout.strip().splitlines()
            overly_open = []
            for line in initrd_lines:
                parts = line.split()
                if len(parts) >= 2:
                    path = parts[0]
                    stat_cmd = self.config.tool_bin("stat", "stat")
                    cr_s = await self.context.runner.run(stat_cmd, ["-c", "%a", path], timeout_seconds=5)
                    if cr_s.succeeded and cr_s.stdout.strip():
                        val = int(cr_s.stdout.strip())
                        if val > 600:
                            overly_open.append(f"{path} ({val})")

            if overly_open:
                findings.append(make_finding(
                    title="Initramfs image permissions are too permissive",
                    description="Initramfs files contain system secrets, private keys, and config parameters. They should be protected with 600 permissions to prevent unprivileged local users from reading or extracting their contents.",
                    severity="medium",
                    category="permissions",
                    source_stage="boot_security",
                    target=target_str,
                    evidence="\n".join(overly_open),
                    recommendation="Set permissions on initramfs files to 600: chmod 600 /boot/initrd.img-*",
                    confidence=0.9,
                ))

        primary = cr_owners or cr_writable or self._empty_command_result()

        result = BootFilesResult(
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
            command="boot_files",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="boot_files",
        )
