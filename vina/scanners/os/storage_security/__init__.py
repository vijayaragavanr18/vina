"""File System, Permissions, and Storage Security Stage for VINA.

PS-07: Audits filesystems, SUID/SGID permissions, sensitive files access control,
mount configurations, LUKS/dm-crypt, swap encryption, FIM status, and immutability attributes.
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
from .encryption import EncryptionModule, EncryptionResult
from .integrity import IntegrityModule, IntegrityResult
from .mounts import MountsModule, MountsResult
from .permissions import PermissionsModule, PermissionsResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class StorageSecurityResult:
    """Aggregate result from all storage/filesystem security sub-scanners."""

    target: TargetInput
    command_result: CommandResult
    permissions: PermissionsResult | None = None
    mounts: MountsResult | None = None
    encryption: EncryptionResult | None = None
    integrity: IntegrityResult | None = None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class StorageSecurityModule:
    """Orchestrate all storage and filesystem security audits."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> StorageSecurityResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        perm_mod = PermissionsModule(self.config, self.context)
        perm_res = await perm_mod.run(target_input)
        findings.extend(perm_res.findings)
        warnings.extend(perm_res.warnings)

        mount_mod = MountsModule(self.config, self.context)
        mount_res = await mount_mod.run(target_input)
        findings.extend(mount_res.findings)
        warnings.extend(mount_res.warnings)

        crypt_mod = EncryptionModule(self.config, self.context)
        crypt_res = await crypt_mod.run(target_input)
        findings.extend(crypt_res.findings)
        warnings.extend(crypt_res.warnings)

        int_mod = IntegrityModule(self.config, self.context)
        int_res = await int_mod.run(target_input)
        findings.extend(int_res.findings)
        warnings.extend(int_res.warnings)

        primary = (
            perm_res.command_result
            or mount_res.command_result
            or crypt_res.command_result
            or int_res.command_result
            or self._empty_command_result()
        )

        result = StorageSecurityResult(
            target=target_input,
            command_result=primary,
            permissions=perm_res,
            mounts=mount_res,
            encryption=crypt_res,
            integrity=int_res,
            findings=findings,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _save_results(self, result: StorageSecurityResult) -> Path:
        payload: dict[str, Any] = {
            "target": result.target.normalized,
            "duration_seconds": result.execution_time_seconds,
            "findings": [f.to_dict() for f in result.findings],
            "warnings": result.warnings,
        }
        return self.context.store.save("os/storage_security.json", payload)

    def _print_summary(self, result: StorageSecurityResult) -> None:
        print("----------------------------------------")
        print("Storage Security")
        print("----------------------------------------")
        print(f"Findings       : {len(result.findings)}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="storage_security",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="storage_security",
        )


__all__ = [
    "StorageSecurityModule",
    "StorageSecurityResult",
]
