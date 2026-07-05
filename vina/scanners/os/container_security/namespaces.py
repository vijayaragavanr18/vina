"""Linux namespaces, capabilities, and LSM (AppArmor, SELinux) security auditing.

Checks for LSM (AppArmor, SELinux) active configurations and kernel namespaces parameters.
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
class NamespacesResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class NamespacesModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> NamespacesResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_aa = await self.context.runner.run(cat_cmd, ["/sys/module/apparmor/parameters/enabled"], timeout_seconds=5)

        apparmor_active = False
        if cr_aa.succeeded and cr_aa.stdout.strip():
            val = cr_aa.stdout.strip()
            if val.lower() == "y":
                apparmor_active = True

        sestatus_cmd = self.config.tool_bin("sestatus", "sestatus")
        cr_se = await self.context.runner.run(sestatus_cmd, [], timeout_seconds=5)

        selinux_active = False
        if cr_se.succeeded and cr_se.stdout.strip():
            content = cr_se.stdout
            if "SELinux status:                 enabled" in content or "SELinux status: enabled" in content:
                selinux_active = True

        if not apparmor_active and not selinux_active:
            findings.append(
                make_finding(
                    title="No active Linux Security Module (LSM) resolved",
                    description="Neither AppArmor nor SELinux is active on this host. Without an active LSM, containers lack kernel-level access control restriction enforcement, leaving them vulnerable to escape.",
                    severity="high",
                    category="vulnerability",
                    source_stage="container_security",
                    target=target_str,
                    evidence="AppArmor parameters set to disabled, sestatus reports disabled or command missing",
                    recommendation="Enable SELinux or AppArmor via grub configurations.",
                    confidence=0.9,
                )
            )

        cr_sec = await self.context.runner.run(cat_cmd, ["/proc/sys/kernel/seccomp/actions_avail"], timeout_seconds=5)
        if not cr_sec.succeeded:
            findings.append(
                make_finding(
                    title="Kernel lacks seccomp system call filtering support",
                    description="The kernel does not expose seccomp interfaces under /proc/sys/kernel/seccomp/. Container runtimes cannot restrict dangerous system calls, heightening privilege escalation risks.",
                    severity="medium",
                    category="vulnerability",
                    source_stage="container_security",
                    target=target_str,
                    evidence="/proc/sys/kernel/seccomp/actions_avail not found or unreadable",
                    recommendation="Rebuild kernel with CONFIG_SECCOMP enabled.",
                    confidence=0.85,
                )
            )

        primary = cr_aa or cr_se or cr_sec or self._empty_command_result()

        result = NamespacesResult(
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
            command="namespaces",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="namespaces",
        )
