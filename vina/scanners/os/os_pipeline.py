"""OS-level scanning pipeline for VINA.

Coordinates host recon and OS-level scanner modules sequentially,
passing structured dataclasses between stages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Literal

from ...core.config import AppConfig
from ...core.runner import AsyncCommandRunner
from ...core.storage import JsonStore
from ...models.common import Asset, TargetInput
from ...modules.common import ModuleContext
from ..recon import ReconModule, ReconResult
from .system_info import SystemInfoModule, SystemInfoResult
from .services import ServicesModule, ServicesResult
from .users import UsersModule, UsersResult
from .filesystem import FilesystemModule, FilesystemResult
from .capabilities import CapabilitiesModule, CapabilitiesResult
from .network import NetworkModule, NetworkResult
from .sudo import SudoModule, SudoResult
from .privilege_escalation import PrivilegeEscalationModule, PrivilegeEscalationResult

StageStatus = Literal["success", "empty", "failed", "skipped"]


@dataclass(slots=True)
class StageStatistics:
    """Execution metadata for one pipeline stage."""

    name: str
    status: StageStatus
    execution_time: float
    warnings: list[str]
    record_count: int


@dataclass(slots=True)
class OSPipelineResult:
    """Aggregate result returned by the OS pipeline."""

    target: TargetInput
    started_at: datetime
    finished_at: datetime
    total_duration: float
    stage_results: list[StageStatistics] = field(default_factory=list)
    summary: str = ""


class OSPipeline:
    """Coordinate the OS-level scanning chain for a target."""

    def __init__(self, config: AppConfig, output_dir: Path | None = None) -> None:
        self.config = config
        self.output_root = output_dir or config.output_dir
        self.store = JsonStore(self.output_root)
        self.runner = AsyncCommandRunner()
        self.context = ModuleContext(
            self.runner, self.store, self.config.timeout_seconds
        )

    async def run(self, target: str) -> OSPipelineResult:
        """Run the OS pipeline and return an OSPipelineResult."""
        target_input = TargetInput.from_raw(target)
        started_at = datetime.now(timezone.utc)
        started_perf = perf_counter()

        stage_results: list[StageStatistics] = []

        # Stage 1: Host Recon --------------------------------------------------
        recon = ReconModule(self.config, self.context)
        recon_started = perf_counter()
        recon_result: ReconResult = await recon.run(target_input)
        recon_elapsed = perf_counter() - recon_started
        assets: list[Asset] = recon_result.assets
        any_succeeded = any(cr.succeeded for cr in recon_result.command_results)
        stage_results.append(
            self._stats(
                "host_recon",
                recon_elapsed,
                recon_result.warnings,
                len(assets),
                self._status(any_succeeded, bool(assets)),
            )
        )

        # Stage 2: SystemInfo --------------------------------------------------
        sysinfo = SystemInfoModule(self.config, self.context)
        sysinfo_result: SystemInfoResult = await sysinfo.run(target_input)
        stage_results.append(
            self._stats(
                "system_info",
                sysinfo_result.execution_time_seconds,
                sysinfo_result.warnings,
                1 if sysinfo_result.system_info is not None else 0,
                self._status(sysinfo_result.command_result.succeeded, sysinfo_result.system_info is not None),
            )
        )

        # Stage 3: Services ----------------------------------------------------
        services = ServicesModule(self.config, self.context)
        services_result: ServicesResult = await services.run(target_input)
        stage_results.append(
            self._stats(
                "services",
                services_result.execution_time_seconds,
                services_result.warnings,
                len(services_result.services),
                self._status(services_result.command_result.succeeded, bool(services_result.services)),
            )
        )

        # Stage 4: Users -------------------------------------------------------
        users = UsersModule(self.config, self.context)
        users_result: UsersResult = await users.run(target_input)
        stage_results.append(
            self._stats(
                "users",
                users_result.execution_time_seconds,
                users_result.warnings,
                len(users_result.users),
                self._status(users_result.command_result.succeeded, bool(users_result.users)),
            )
        )

        # Stage 5: Filesystem --------------------------------------------------
        filesystem = FilesystemModule(self.config, self.context)
        filesystem_result: FilesystemResult = await filesystem.run(target_input)
        stage_results.append(
            self._stats(
                "filesystem",
                filesystem_result.execution_time_seconds,
                filesystem_result.warnings,
                len(filesystem_result.entries),
                self._status(filesystem_result.command_result.succeeded, bool(filesystem_result.entries)),
            )
        )

        # Stage 6: Capabilities ------------------------------------------------
        capabilities = CapabilitiesModule(self.config, self.context)
        capabilities_result: CapabilitiesResult = await capabilities.run(target_input)
        stage_results.append(
            self._stats(
                "capabilities",
                capabilities_result.execution_time_seconds,
                capabilities_result.warnings,
                len(capabilities_result.entries),
                self._status(capabilities_result.command_result.succeeded, bool(capabilities_result.entries)),
            )
        )

        # Stage 7: Network -----------------------------------------------------
        network = NetworkModule(self.config, self.context)
        network_result: NetworkResult = await network.run(target_input)
        stage_results.append(
            self._stats(
                "network",
                network_result.execution_time_seconds,
                network_result.warnings,
                network_result.interface_count,
                self._status(network_result.command_result.succeeded, bool(network_result.interfaces)),
            )
        )

        # Stage 8: Sudo --------------------------------------------------------
        sudo = SudoModule(self.config, self.context)
        sudo_result: SudoResult = await sudo.run(target_input)
        stage_results.append(
            self._stats(
                "sudo",
                sudo_result.execution_time_seconds,
                sudo_result.warnings,
                len(sudo_result.entries),
                self._status(sudo_result.command_result.succeeded, bool(sudo_result.entries)),
            )
        )

        # Stage 9: PrivilegeEscalation -----------------------------------------
        pe = PrivilegeEscalationModule(self.config, self.context)
        pe_result: PrivilegeEscalationResult = await pe.run(target_input)
        stage_results.append(
            self._stats(
                "privilege_escalation",
                pe_result.execution_time_seconds,
                pe_result.warnings,
                len(pe_result.findings),
                self._status(pe_result.command_result.succeeded, bool(pe_result.findings)),
            )
        )

        # Build result ---------------------------------------------------------
        finished_at = datetime.now(timezone.utc)
        total_duration = perf_counter() - started_perf
        summary = self._build_summary(target_input, stage_results, total_duration)
        print(summary)

        return OSPipelineResult(
            target=target_input,
            started_at=started_at,
            finished_at=finished_at,
            total_duration=total_duration,
            stage_results=stage_results,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _status(succeeded: bool, has_records: bool) -> StageStatus:
        if not succeeded:
            return "failed"
        if not has_records:
            return "empty"
        return "success"

    @staticmethod
    def _stats(
        name: str,
        execution_time: float,
        warnings: list[str],
        record_count: int,
        status: StageStatus,
    ) -> StageStatistics:
        return StageStatistics(
            name=name,
            status=status,
            execution_time=execution_time,
            warnings=warnings,
            record_count=record_count,
        )

    @staticmethod
    def _build_summary(
        target_input: TargetInput,
        stage_results: list[StageStatistics],
        total_duration: float,
    ) -> str:
        """Build a concise console summary."""
        target_display = (
            target_input.root_domain
            or target_input.hostname
            or target_input.normalized
        )

        lines = [
            "=" * 41,
            "VINA OS Pipeline",
            "=" * 41,
            f"Target:          {target_display}",
        ]
        for sr in stage_results:
            lines.append(f"  {sr.name:<18} {sr.status:<8} {sr.record_count}")
        lines.append(f"Total Duration:  {total_duration:.2f}s")
        lines.append("=" * 41)
        return "\n".join(lines)


__all__ = [
    "OSPipelineResult",
    "StageStatistics",
    "StageStatus",
    "OSPipeline",
]
