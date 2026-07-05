"""Kernel crypto configuration and system entropy security auditing.

Audits FIPS mode configuration and system available entropy levels.
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
class KernelCryptoResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class KernelCryptoModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> KernelCryptoResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_fips = await self.context.runner.run(cat_cmd, ["/proc/sys/crypto/fips_enabled"], timeout_seconds=5)

        fips_enabled = False
        if cr_fips.succeeded and cr_fips.stdout.strip():
            val = cr_fips.stdout.strip()
            if val == "1":
                fips_enabled = True

        if not fips_enabled:
            findings.append(make_finding(
                title="Kernel FIPS mode is disabled",
                description="The kernel cryptographical modules are not operating in FIPS-140 compliance mode. This may violate federal or enterprise compliance regulations.",
                severity="info",
                category="compliance",
                source_stage="crypto_security",
                target=target_str,
                evidence="fips_enabled set to 0 or missing",
                recommendation="Enable FIPS mode in the bootloader kernel parameters ('fips=1').",
                confidence=0.85,
            ))

        cr_ent = await self.context.runner.run(cat_cmd, ["/proc/sys/kernel/random/entropy_avail"], timeout_seconds=5)
        if cr_ent.succeeded and cr_ent.stdout.strip():
            try:
                entropy_val = int(cr_ent.stdout.strip())
                if entropy_val < 1000:
                    findings.append(make_finding(
                        title=f"Low available kernel entropy: {entropy_val}",
                        description="The system available random entropy pool size is less than 1000. Low entropy can lead to blocking or weak cryptographic key generation for SSH, TLS, or system secrets.",
                        severity="medium",
                        category="misconfiguration",
                        source_stage="crypto_security",
                        target=target_str,
                        evidence=f"entropy_avail = {entropy_val}",
                        recommendation="Install haveged or enable virtio-rng to feed the kernel entropy pool.",
                        confidence=0.9,
                    ))
            except ValueError:
                warnings.append(f"Failed to parse available entropy count: {cr_ent.stdout}")

        primary = cr_fips or cr_ent or self._empty_command_result()

        result = KernelCryptoResult(
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
            command="kernel_crypto",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="kernel_crypto",
        )
