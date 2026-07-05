"""GRUB bootloader security auditing.

Audits password configuration, unrestricted boot entries, and config permissions.
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
class GrubResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class GrubModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> GrubResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        grub_paths = [
            "/boot/grub/grub.cfg",
            "/boot/grub2/grub.cfg",
            "/boot/efi/EFI/ubuntu/grub.cfg",
            "/boot/efi/EFI/debian/grub.cfg",
            "/boot/efi/EFI/redhat/grub.cfg",
            "/boot/efi/EFI/centos/grub.cfg",
        ]

        stat_cmd = self.config.tool_bin("stat", "stat")
        cat_cmd = self.config.tool_bin("cat", "cat")

        grub_file = None
        cr_stat = None
        for path in grub_paths:
            cr_stat = await self.context.runner.run(stat_cmd, ["-c", "%a %U %G", path], timeout_seconds=5)
            if cr_stat.succeeded and cr_stat.stdout.strip():
                grub_file = path
                break

        target_str = target.normalized

        if not grub_file:
            findings.append(
                make_finding(
                    title="GRUB configuration file not found",
                    description="Unable to locate active GRUB configuration file under standard paths.",
                    severity="low",
                    category="information",
                    source_stage="boot_security",
                    target=target_str,
                    evidence="Checked paths: " + ", ".join(grub_paths),
                    confidence=0.8,
                )
            )
            primary = cr_stat or self._empty_command_result()
        else:
            assert cr_stat is not None
            parts = cr_stat.stdout.strip().split()
            perms = parts[0] if len(parts) >= 1 else ""
            owner = parts[1] if len(parts) >= 2 else ""
            group = parts[2] if len(parts) >= 3 else ""

            if perms and int(perms) > 600:
                findings.append(
                    make_finding(
                        title=f"GRUB configuration file permissions are too open: {grub_file} ({perms})",
                        description=f"The GRUB configuration file '{grub_file}' has permissions '{perms}'. It should be set to 600 or 400 to prevent local users from reading boot configurations, which may contain password hashes.",
                        severity="medium",
                        category="permissions",
                        source_stage="boot_security",
                        target=target_str,
                        evidence=f"Path: {grub_file}, Perms: {perms}, Owner: {owner}:{group}",
                        recommendation=f"Run 'chmod 600 {grub_file}' and 'chown root:root {grub_file}' to secure the configuration.",
                        confidence=0.9,
                    )
                )

            if owner != "root":
                findings.append(
                    make_finding(
                        title=f"GRUB configuration file is not owned by root: {grub_file}",
                        description=f"The GRUB configuration file '{grub_file}' is owned by '{owner}'. It must be owned by root.",
                        severity="medium",
                        category="permissions",
                        source_stage="boot_security",
                        target=target_str,
                        evidence=f"Owner: {owner}",
                        recommendation=f"Run 'chown root:root {grub_file}'.",
                        confidence=0.9,
                    )
                )

            cr_cat = await self.context.runner.run(cat_cmd, [grub_file], timeout_seconds=10)
            has_password = False
            unrestricted_entries = []
            total_entries = 0

            if cr_cat.succeeded and cr_cat.stdout.strip():
                content = cr_cat.stdout
                if "password" in content or "password_pbkdf2" in content:
                    has_password = True

                for line in content.splitlines():
                    if "menuentry " in line:
                        total_entries += 1
                        if "--unrestricted" in line:
                            m = line.split("menuentry ")[1].split("{")[0].strip()
                            unrestricted_entries.append(m)

            if not has_password:
                findings.append(
                    make_finding(
                        title="GRUB bootloader is not password protected",
                        description="No password configuration (password or password_pbkdf2) was found in the GRUB configuration. Any user with physical or console access can modify boot options and boot into single-user mode.",
                        severity="high",
                        category="misconfiguration",
                        source_stage="boot_security",
                        target=target_str,
                        evidence=f"File: {grub_file}, Password configured: False",
                        recommendation="Configure a bootloader password using grub-mkpasswd-pbkdf2 and add it to GRUB configuration.",
                        confidence=0.9,
                    )
                )
            elif unrestricted_entries and len(unrestricted_entries) == total_entries:
                findings.append(
                    make_finding(
                        title="All GRUB boot entries are unrestricted",
                        description="GRUB has a password set, but all boot menu entries are marked as '--unrestricted'. This allows anyone to boot them without authentication, reducing the benefit of the password protection.",
                        severity="medium",
                        category="misconfiguration",
                        source_stage="boot_security",
                        target=target_str,
                        evidence=f"Total entries: {total_entries}, Unrestricted: {len(unrestricted_entries)}",
                        recommendation="Remove the '--unrestricted' flag from sensitive boot entries (like recovery or rescue entries) so they require the GRUB password to boot.",
                        confidence=0.85,
                    )
                )

            primary = cr_cat

        result = GrubResult(
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
            command="grub",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="grub",
        )
