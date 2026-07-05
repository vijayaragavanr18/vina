"""Virtualization and hypervisor host modules security auditing.

Checks for loaded virtualization modules (KVM, QEMU, VirtualBox, VMware).
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
class VirtualizationResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class VirtualizationModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> VirtualizationResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        lsmod_cmd = self.config.tool_bin("lsmod", "lsmod")
        cr_mod = await self.context.runner.run(lsmod_cmd, [], timeout_seconds=5)

        detected_hypervisors = []
        if cr_mod.succeeded and cr_mod.stdout.strip():
            content = cr_mod.stdout
            if "kvm" in content:
                detected_hypervisors.append("Kernel-based Virtual Machine (KVM)")
            if "vboxdrv" in content:
                detected_hypervisors.append("VirtualBox (vboxdrv)")
            if "vmw_" in content or "vmci" in content:
                detected_hypervisors.append("VMware Virtualization Drivers")

        if detected_hypervisors:
            findings.append(
                make_finding(
                    title=f"Virtualization hypervisor modules active: {', '.join(detected_hypervisors)}",
                    description="Hypervisor/Virtualization kernel drivers are active on the host. Ensure the virtual machines are monitored and hypervisor patches are up to date to prevent hypervisor escape.",
                    severity="info",
                    category="information",
                    source_stage="container_security",
                    target=target_str,
                    evidence=f"Loaded modules: {', '.join(detected_hypervisors)}",
                    recommendation="Audit active virtual machines. Unused virtualization modules should be disabled or blacklisted.",
                    confidence=0.9,
                )
            )

        primary = cr_mod or self._empty_command_result()

        result = VirtualizationResult(
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
            command="virtualization",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="virtualization",
        )
