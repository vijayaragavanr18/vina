"""Containerisation, Virtualisation, and Namespace Security Stage for VINA.

PS-10: Audits container engines (Docker, Podman, CRI-O), orchestrators (Kubernetes),
Linux namespaces, capabilities, AppArmor/SELinux LSM state, and loaded virtualization modules.
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
from .namespaces import NamespacesModule, NamespacesResult
from .runtimes import RuntimesModule, RuntimesResult
from .virtualization import VirtualizationModule, VirtualizationResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ContainerSecurityResult:
    """Aggregate result from container, namespaces, and virtualization security audits."""

    target: TargetInput
    command_result: CommandResult
    runtimes: RuntimesResult | None = None
    namespaces: NamespacesResult | None = None
    virtualization: VirtualizationResult | None = None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class ContainerSecurityModule:
    """Orchestrate containerization, namespaces, and virtualization security audits."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> ContainerSecurityResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        runtime_mod = RuntimesModule(self.config, self.context)
        runtime_res = await runtime_mod.run(target_input)
        findings.extend(runtime_res.findings)
        warnings.extend(runtime_res.warnings)

        ns_mod = NamespacesModule(self.config, self.context)
        ns_res = await ns_mod.run(target_input)
        findings.extend(ns_res.findings)
        warnings.extend(ns_res.warnings)

        virt_mod = VirtualizationModule(self.config, self.context)
        virt_res = await virt_mod.run(target_input)
        findings.extend(virt_res.findings)
        warnings.extend(virt_res.warnings)

        primary = (
            runtime_res.command_result
            or ns_res.command_result
            or virt_res.command_result
            or self._empty_command_result()
        )

        result = ContainerSecurityResult(
            target=target_input,
            command_result=primary,
            runtimes=runtime_res,
            namespaces=ns_res,
            virtualization=virt_res,
            findings=findings,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _save_results(self, result: ContainerSecurityResult) -> Path:
        payload: dict[str, Any] = {
            "target": result.target.normalized,
            "duration_seconds": result.execution_time_seconds,
            "findings": [f.to_dict() for f in result.findings],
            "warnings": result.warnings,
        }
        return self.context.store.save("os/container_security.json", payload)

    def _print_summary(self, result: ContainerSecurityResult) -> None:
        print("----------------------------------------")
        print("Container Security")
        print("----------------------------------------")
        print(f"Findings       : {len(result.findings)}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="container_security",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="container_security",
        )


__all__ = ["ContainerSecurityModule", "ContainerSecurityResult"]
