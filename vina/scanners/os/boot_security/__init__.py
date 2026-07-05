"""Boot Process, GRUB, and Secure Boot Security Stage for VINA.

PS-05: Audits bootloader configurations, Secure Boot, EFI, kernel boot parameters,
initramfs settings, bootloader files, and recovery configurations.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding
from ....modules.common import ModuleContext
from .boot_files import BootFilesModule, BootFilesResult
from .grub import GrubModule, GrubResult
from .kernel_params import KernelParamsModule, KernelParamsResult
from .secure_boot import SecureBootModule, SecureBootResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class BootSecurityResult:
    """Aggregate result from all boot security sub-scanners."""

    target: TargetInput
    command_result: CommandResult
    grub: GrubResult | None = None
    secure_boot: SecureBootResult | None = None
    kernel_params: KernelParamsResult | None = None
    boot_files: BootFilesResult | None = None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class BootSecurityModule:
    """Orchestrate all boot process security audits."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> BootSecurityResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        grub_mod = GrubModule(self.config, self.context)
        grub_res = await grub_mod.run(target_input)
        findings.extend(grub_res.findings)
        warnings.extend(grub_res.warnings)

        sb_mod = SecureBootModule(self.config, self.context)
        sb_res = await sb_mod.run(target_input)
        findings.extend(sb_res.findings)
        warnings.extend(sb_res.warnings)

        kp_mod = KernelParamsModule(self.config, self.context)
        kp_res = await kp_mod.run(target_input)
        findings.extend(kp_res.findings)
        warnings.extend(kp_res.warnings)

        bf_mod = BootFilesModule(self.config, self.context)
        bf_res = await bf_mod.run(target_input)
        findings.extend(bf_res.findings)
        warnings.extend(bf_res.warnings)

        primary = (
            grub_res.command_result
            or sb_res.command_result
            or kp_res.command_result
            or bf_res.command_result
            or self._empty_command_result()
        )

        result = BootSecurityResult(
            target=target_input,
            command_result=primary,
            grub=grub_res,
            secure_boot=sb_res,
            kernel_params=kp_res,
            boot_files=bf_res,
            findings=findings,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _save_results(self, result: BootSecurityResult) -> Path:
        payload: dict[str, Any] = {
            "target": result.target.normalized,
            "duration_seconds": result.execution_time_seconds,
            "findings": [f.to_dict() for f in result.findings],
            "warnings": result.warnings,
        }
        return self.context.store.save("os/boot_security.json", payload)

    def _print_summary(self, result: BootSecurityResult) -> None:
        print("----------------------------------------")
        print("Boot Security")
        print("----------------------------------------")
        print(f"Findings       : {len(result.findings)}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="boot_security",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="boot_security",
        )


__all__ = [
    "BootSecurityModule",
    "BootSecurityResult",
]
