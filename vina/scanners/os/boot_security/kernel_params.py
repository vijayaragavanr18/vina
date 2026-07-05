"""Kernel boot parameters and recovery mode security auditing.

Audits /proc/cmdline, mitigation configurations, MAC settings, and recovery/emergency shell authentication.
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
class KernelParamsResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class KernelParamsModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> KernelParamsResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_cmd = await self.context.runner.run(cat_cmd, ["/proc/cmdline"], timeout_seconds=5)

        cmdline = ""
        if cr_cmd.succeeded and cr_cmd.stdout.strip():
            cmdline = cr_cmd.stdout.strip()

        target_str = target.normalized

        if cmdline:
            params = cmdline.split()

            for param in params:
                if param.startswith("init="):
                    val = param.partition("=")[2]
                    if val in ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh"):
                        findings.append(make_finding(
                            title=f"Vulnerable kernel boot parameter: {param}",
                            description=f"Kernel is configured to boot directly into an unauthenticated shell: {param}. This bypasses standard systemd/sysvinit login controls.",
                            severity="critical",
                            category="vulnerability",
                            source_stage="boot_security",
                            target=target_str,
                            evidence=f"Kernel cmdline: {cmdline}",
                            recommendation="Remove the custom init parameter from GRUB configuration /etc/default/grub.",
                            confidence=0.95,
                        ))

            if "mitigations=off" in cmdline:
                findings.append(make_finding(
                    title="Kernel speculative execution mitigations are disabled",
                    description="Kernel is booted with 'mitigations=off', disabling protections against CPU side-channel attacks (Meltdown, Spectre, MDS, L1TF).",
                    severity="high",
                    category="vulnerability",
                    source_stage="boot_security",
                    target=target_str,
                    evidence=f"Kernel cmdline: {cmdline}",
                    recommendation="Remove 'mitigations=off' from kernel boot arguments in /etc/default/grub.",
                    confidence=0.9,
                ))

            if "selinux=0" in cmdline:
                findings.append(make_finding(
                    title="SELinux disabled in kernel boot parameters",
                    description="SELinux is explicitly disabled via boot parameter 'selinux=0'.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="boot_security",
                    target=target_str,
                    evidence=f"Kernel cmdline: {cmdline}",
                    recommendation="Enable SELinux in boot configuration.",
                    confidence=0.9,
                ))
            if "apparmor=0" in cmdline:
                findings.append(make_finding(
                    title="AppArmor disabled in kernel boot parameters",
                    description="AppArmor is explicitly disabled via boot parameter 'apparmor=0'.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="boot_security",
                    target=target_str,
                    evidence=f"Kernel cmdline: {cmdline}",
                    recommendation="Enable AppArmor in boot configuration.",
                    confidence=0.9,
                ))

        grep_cmd = self.config.tool_bin("grep", "grep")
        cr_emerg = await self.context.runner.run(grep_cmd, ["-r", "sulogin", "/lib/systemd/system/emergency.service", "/lib/systemd/system/rescue.service"], timeout_seconds=5)

        cr_files = await self.context.runner.run(cat_cmd, ["/lib/systemd/system/emergency.service", "/lib/systemd/system/rescue.service"], timeout_seconds=5)

        if cr_files.succeeded and cr_files.stdout.strip():
            content = cr_files.stdout
            if "ExecStart=-/bin/bash" in content or "ExecStart=-/bin/sh" in content:
                findings.append(make_finding(
                    title="Root shell spawned on systemd emergency/rescue mode without password",
                    description="Emergency or rescue systemd unit files are configured to spawn a shell directly without requiring the root password via sulogin.",
                    severity="critical",
                    category="vulnerability",
                    source_stage="boot_security",
                    target=target_str,
                    evidence="ExecStart directive runs shell directly without sulogin wrapper.",
                    recommendation="Modify systemd emergency/rescue service files to enforce sulogin root authentication.",
                    confidence=0.85,
                ))

        primary = cr_cmd or cr_emerg or self._empty_command_result()

        result = KernelParamsResult(
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
            command="kernel_params",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="kernel_params",
        )
