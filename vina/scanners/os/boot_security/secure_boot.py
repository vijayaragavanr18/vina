"""UEFI Secure Boot and EFI security auditing.

Audits Secure Boot state, custom keys, efivars, and boot entries.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding, make_finding
from ....modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SecureBootResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class SecureBootModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> SecureBootResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        efi_dir = Path("/sys/firmware/efi")
        booted_efi = efi_dir.exists()

        if not booted_efi:
            findings.append(
                make_finding(
                    title="System booted in Legacy BIOS mode (no Secure Boot)",
                    description="The system firmware is configured for Legacy BIOS mode instead of UEFI. Secure Boot cannot be enforced or validated in this mode.",
                    severity="medium",
                    category="misconfiguration",
                    source_stage="boot_security",
                    target=target_str,
                    evidence="Directory /sys/firmware/efi does not exist",
                    recommendation="Reboot the system, enable UEFI boot mode in firmware settings, and configure Secure Boot.",
                    confidence=0.9,
                )
            )
            return SecureBootResult(
                target=target,
                command_result=self._empty_command_result(),
                warnings=warnings,
                findings=findings,
                execution_time_seconds=time.perf_counter() - started_at,
            )

        mokutil_cmd = self.config.tool_bin("mokutil", "mokutil")
        cr_sb = await self.context.runner.run(mokutil_cmd, ["--sb-state"], timeout_seconds=5)

        sb_enabled = False
        if cr_sb.succeeded and cr_sb.stdout.strip():
            if "SecureBoot enabled" in cr_sb.stdout:
                sb_enabled = True
        else:
            bootctl_cmd = self.config.tool_bin("bootctl", "bootctl")
            cr_bc = await self.context.runner.run(bootctl_cmd, ["status"], timeout_seconds=5)
            if cr_bc.succeeded and "Secure Boot: enabled" in cr_bc.stdout:
                sb_enabled = True

        if not sb_enabled:
            findings.append(
                make_finding(
                    title="UEFI Secure Boot is disabled",
                    description="UEFI Secure Boot is disabled. This allows the system to load unsigned boot loaders, kernels, and kernel modules, exposing the OS to bootkit/rootkit tampering.",
                    severity="high",
                    category="vulnerability",
                    source_stage="boot_security",
                    target=target_str,
                    evidence="Secure Boot state: disabled",
                    recommendation="Enable UEFI Secure Boot in the system UEFI firmware settings.",
                    confidence=0.9,
                )
            )
        else:
            findings.append(
                make_finding(
                    title="UEFI Secure Boot is enabled",
                    description="UEFI Secure Boot is active, preventing the execution of unsigned bootloaders or kernels.",
                    severity="info",
                    category="security_control",
                    source_stage="boot_security",
                    target=target_str,
                    evidence="Secure Boot state: enabled",
                    confidence=0.9,
                )
            )

        efibootmgr_cmd = self.config.tool_bin("efibootmgr", "efibootmgr")
        cr_eb = await self.context.runner.run(efibootmgr_cmd, [], timeout_seconds=5)

        boot_entries = []
        if cr_eb.succeeded and cr_eb.stdout.strip():
            for line in cr_eb.stdout.splitlines():
                if line.startswith("Boot"):
                    boot_entries.append(line.strip())

        if not boot_entries:
            warnings.append("Unable to parse EFI boot entries via efibootmgr")

        cr_pk = await self.context.runner.run(mokutil_cmd, ["--pk"], timeout_seconds=5)
        custom_keys = False
        if cr_pk.succeeded and cr_pk.stdout.strip() and "No PK is defined" not in cr_pk.stdout and "PK" in cr_pk.stdout:
            custom_keys = True

        if custom_keys:
            findings.append(
                make_finding(
                    title="Custom UEFI Secure Boot keys configured",
                    description="The system uses custom platform keys (PK) or enrollment keys rather than the default factory certificates.",
                    severity="info",
                    category="information",
                    source_stage="boot_security",
                    target=target_str,
                    evidence="Platform Key (PK) certificates are registered",
                    confidence=0.8,
                )
            )

        primary = cr_sb or cr_eb or self._empty_command_result()

        result = SecureBootResult(
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
            command="secure_boot",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="secure_boot",
        )
