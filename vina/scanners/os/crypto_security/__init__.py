"""Cryptographic Implementation and Configuration Security Stage for VINA.

PS-09: Audits SSL/TLS certificates and key permissions, SSH ciphers and MACs,
kernel FIPS configurations, and available entropy pool.
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
from .kernel_crypto import KernelCryptoModule, KernelCryptoResult
from .ssh_ciphers import SshCiphersModule, SshCiphersResult
from .ssl_certs import SslCertsModule, SslCertsResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CryptoSecurityResult:
    """Aggregate result from all cryptographic security sub-scanners."""

    target: TargetInput
    command_result: CommandResult
    ssl_certs: SslCertsResult | None = None
    ssh_ciphers: SshCiphersResult | None = None
    kernel_crypto: KernelCryptoResult | None = None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class CryptoSecurityModule:
    """Orchestrate all cryptographic configuration security audits."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> CryptoSecurityResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        ssl_mod = SslCertsModule(self.config, self.context)
        ssl_res = await ssl_mod.run(target_input)
        findings.extend(ssl_res.findings)
        warnings.extend(ssl_res.warnings)

        ssh_mod = SshCiphersModule(self.config, self.context)
        ssh_res = await ssh_mod.run(target_input)
        findings.extend(ssh_res.findings)
        warnings.extend(ssh_res.warnings)

        kernel_mod = KernelCryptoModule(self.config, self.context)
        kernel_res = await kernel_mod.run(target_input)
        findings.extend(kernel_res.findings)
        warnings.extend(kernel_res.warnings)

        primary = (
            ssl_res.command_result
            or ssh_res.command_result
            or kernel_res.command_result
            or self._empty_command_result()
        )

        result = CryptoSecurityResult(
            target=target_input,
            command_result=primary,
            ssl_certs=ssl_res,
            ssh_ciphers=ssh_res,
            kernel_crypto=kernel_res,
            findings=findings,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _save_results(self, result: CryptoSecurityResult) -> Path:
        payload: dict[str, Any] = {
            "target": result.target.normalized,
            "duration_seconds": result.execution_time_seconds,
            "findings": [f.to_dict() for f in result.findings],
            "warnings": result.warnings,
        }
        return self.context.store.save("os/crypto_security.json", payload)

    def _print_summary(self, result: CryptoSecurityResult) -> None:
        print("----------------------------------------")
        print("Crypto Security")
        print("----------------------------------------")
        print(f"Findings       : {len(result.findings)}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="crypto_security",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="crypto_security",
        )


__all__ = [
    "CryptoSecurityModule",
    "CryptoSecurityResult",
]
