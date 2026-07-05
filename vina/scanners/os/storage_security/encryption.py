"""Storage encryption, LUKS, and Swap security auditing.

Audits LUKS full-disk encryption status and checks if swap space is encrypted.
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
class EncryptionResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class EncryptionModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> EncryptionResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        lsblk_cmd = self.config.tool_bin("lsblk", "lsblk")
        cr_lsblk = await self.context.runner.run(lsblk_cmd, ["-o", "NAME,TYPE,FSTYPE"], timeout_seconds=5)

        has_encryption = False
        if cr_lsblk.succeeded and cr_lsblk.stdout.strip():
            content = cr_lsblk.stdout
            if "crypt" in content or "LUKS" in content:
                has_encryption = True

        if not has_encryption:
            findings.append(
                make_finding(
                    title="System lacks full-disk encryption (LUKS)",
                    description="No encrypted partitions (LUKS/dm-crypt) were resolved. If physical disks are lost or stolen, all system and user data can be retrieved by third parties.",
                    severity="medium",
                    category="vulnerability",
                    source_stage="storage_security",
                    target=target_str,
                    evidence="lsblk shows no crypt/LUKS partitions",
                    recommendation="Enforce LUKS full-disk encryption on root and home partition mappings.",
                    confidence=0.9,
                )
            )

        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_swaps = await self.context.runner.run(cat_cmd, ["/proc/swaps"], timeout_seconds=5)

        has_swap = False
        swap_path = ""
        if cr_swaps.succeeded and cr_swaps.stdout.strip():
            lines = cr_swaps.stdout.strip().splitlines()
            if len(lines) > 1:
                has_swap = True
                parts = lines[1].split()
                if len(parts) >= 1:
                    swap_path = parts[0]

        if has_swap and swap_path:
            cr_crypttab = await self.context.runner.run(cat_cmd, ["/etc/crypttab"], timeout_seconds=5)
            swap_encrypted = False

            if (
                "dm-" in swap_path
                or "crypt" in swap_path.lower()
                or (cr_crypttab.succeeded and cr_crypttab.stdout.strip() and "swap" in cr_crypttab.stdout.lower())
            ):
                swap_encrypted = True

            if not swap_encrypted:
                findings.append(
                    make_finding(
                        title="Unencrypted swap space configured",
                        description="Active swap space is not encrypted. Sensible kernel memory pages containing secrets, password hashes, or TLS keys can be written in plain text to swap disks, enabling offline memory retrieval.",
                        severity="high",
                        category="vulnerability",
                        source_stage="storage_security",
                        target=target_str,
                        evidence=f"Swap path: {swap_path}",
                        recommendation="Enable swap space encryption using dm-crypt or configure a transient swap key in crypttab.",
                        confidence=0.9,
                    )
                )

        primary = cr_lsblk or cr_swaps or self._empty_command_result()

        result = EncryptionResult(
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
            command="encryption",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="encryption",
        )
