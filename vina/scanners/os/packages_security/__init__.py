"""Package Management and Software Supply Chain Security Stage for VINA.

PS-03: Comprehensive package/supply-chain audit. Orchestrated as a single
stage that delegates to modular sub-scanners.
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
from .integrity import IntegrityModule, IntegrityResult
from .inventory import InventoryModule, InventoryResult
from .managers import PackageManagersModule, PackageManagersResult
from .repositories import RepositoriesModule, RepositoriesResult
from .supply_chain import SupplyChainModule, SupplyChainResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PackagesSecurityResult:
    """Aggregate result from all package-security sub-scanners."""

    target: TargetInput
    command_result: CommandResult
    managers: PackageManagersResult | None = None
    repositories: RepositoriesResult | None = None
    integrity: IntegrityResult | None = None
    supply_chain: SupplyChainResult | None = None
    inventory: InventoryResult | None = None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class PackagesSecurityModule:
    """Orchestrate all sub-scanners and collect their findings."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> PackagesSecurityResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        pm_mod = PackageManagersModule(self.config, self.context)
        pm_res = await pm_mod.run(target_input)
        findings.extend(pm_res.findings)
        warnings.extend(pm_res.warnings)

        repo_mod = RepositoriesModule(self.config, self.context)
        repo_res = await repo_mod.run(target_input)
        findings.extend(repo_res.findings)
        warnings.extend(repo_res.warnings)

        int_mod = IntegrityModule(self.config, self.context)
        int_res = await int_mod.run(target_input)
        findings.extend(int_res.findings)
        warnings.extend(int_res.warnings)

        sc_mod = SupplyChainModule(self.config, self.context)
        sc_res = await sc_mod.run(target_input, pm_res.packages)
        findings.extend(sc_res.findings)
        warnings.extend(sc_res.warnings)

        inv_mod = InventoryModule(self.config, self.context)
        inv_res = await inv_mod.run(target_input, pm_res.packages, repo_res.repositories)
        findings.extend(inv_res.findings)
        warnings.extend(inv_res.warnings)

        primary = (
            pm_res.command_result
            or repo_res.command_result
            or int_res.command_result
            or sc_res.command_result
            or inv_res.command_result
            or self._empty_command_result()
        )

        result = PackagesSecurityResult(
            target=target_input,
            command_result=primary,
            managers=pm_res,
            repositories=repo_res,
            integrity=int_res,
            supply_chain=sc_res,
            inventory=inv_res,
            findings=findings,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _save_results(self, result: PackagesSecurityResult) -> Path:
        payload: dict[str, Any] = {
            "target": result.target.normalized,
            "duration_seconds": result.execution_time_seconds,
            "findings": [f.to_dict() for f in result.findings],
            "warnings": result.warnings,
        }
        return self.context.store.save("os/packages_security.json", payload)

    def _print_summary(self, result: PackagesSecurityResult) -> None:
        print("----------------------------------------")
        print("Package Security")
        print("----------------------------------------")
        print(f"Findings       : {len(result.findings)}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="packages_security",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="packages_security",
        )


__all__ = ["PackagesSecurityModule", "PackagesSecurityResult"]
