"""OS-level scanning pipeline for VINA.

Coordinates all OS scanner modules using a dependency-aware scheduler
that executes independent stages concurrently, emits unified Finding
objects, and generates structured JSON reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from ...core.aggregator import FindingAggregator
from ...core.config import AppConfig
from ...core.dependency import DependencyChecker
from ...core.runner import AsyncCommandRunner
from ...core.scheduler import PipelineScheduler, RetryConfig, StageDef
from ...core.storage import JsonStore
from ...models.common import TargetInput
from ...models.findings import Finding
from ...models.stages import (
    StageResult,
    StageState,
    build_skipped_stage,
    build_stage_result,
    log_stage_result,
    summary_for_stages,
)
from ...modules.common import ModuleContext
from ...plugins.hooks import HookPoint
from ...plugins.registry import get_registry
from ...reports import generate_reports
from ..recon import ReconModule, ReconResult
from .capabilities import CapabilitiesModule, CapabilitiesResult
from .cron import CronModule, CronResult
from .docker import DockerModule, DockerResult
from .environment import EnvironmentModule, EnvironmentResult
from .filesystem import FilesystemModule, FilesystemResult
from .kernel import KernelModule, KernelResult
from .logs import LogsModule, LogsResult
from .network import NetworkModule, NetworkResult
from .packages import PackagesModule, PackagesResult
from .privilege_escalation import PrivilegeEscalationModule, PrivilegeEscalationResult
from .processes import ProcessesModule, ProcessesResult
from .secrets import SecretsModule, SecretsResult
from .services import ServicesModule, ServicesResult
from .ssh import SshModule, SshResult
from .sudo import SudoModule, SudoResult
from .systemd import SystemdModule, SystemdResult
from .system_info import SystemInfoModule, SystemInfoResult
from .users import UsersModule, UsersResult

# Tools checked before the OS pipeline runs.
_OS_TOOLS: list[str] = [
    "getcap", "ss", "ip", "systemctl", "sudo", "find", "route",
    "ifconfig", "netstat", "service", "cat", "ls", "ps", "dpkg",
    "uname", "stat", "env", "lastb", "last",
]

# Dependency graph. All stages depend on host_recon for target context
# but are otherwise independent of each other.
_STAGE_DEPS: dict[str, list[str]] = {
    "host_recon": [],
    "system_info": ["host_recon"],
    "ssh": ["host_recon"],
    "kernel": ["host_recon"],
    "environment": ["host_recon"],
    "packages": ["host_recon"],
    "services": ["host_recon"],
    "users": ["host_recon"],
    "filesystem": ["host_recon"],
    "network": ["host_recon"],
    "processes": ["host_recon"],
    "cron": ["host_recon"],
    "systemd": ["host_recon"],
    "docker": ["host_recon"],
    "logs": ["host_recon"],
    "secrets": ["host_recon"],
    "capabilities": ["host_recon"],
    "sudo": ["host_recon"],
    "privilege_escalation": ["host_recon"],
}


@dataclass(slots=True)
class OSPipelineResult:
    """Aggregate result returned by the OS pipeline."""

    target: TargetInput
    started_at: datetime
    finished_at: datetime
    total_duration: float
    stage_results: list[StageResult] = field(default_factory=list)
    summary: str = ""

    # Optional scan data for CLI reporting
    findings: list[Finding] = field(default_factory=list)
    enriched_findings: list[Finding] = field(default_factory=list)
    attack_paths: list[Any] = field(default_factory=list)
    aggregator: Any = None
    stats: Any = None
    vuln_matches: list[Any] = field(default_factory=list)
    vuln_stats: Any = None
    exploitability_assessments: list[Any] = field(default_factory=list)
    exploitability_summary: Any = None


class OSPipeline:
    """Coordinate the OS-level scanning chain for a target.

    Stages are scheduled according to the dependency graph defined in
    ``_STAGE_DEPS``.  Independent stages run concurrently up to
    ``_MAX_PARALLEL``.
    """

    _MAX_PARALLEL = 6

    def __init__(self, config: AppConfig, output_dir: Path | None = None) -> None:
        self.config = config
        self.output_root = output_dir or config.output_dir
        self.store = JsonStore(self.output_root)
        self.runner = AsyncCommandRunner()
        self.context = ModuleContext(
            self.runner, self.store, self.config.timeout_seconds
        )
        self._dep_checker = DependencyChecker(config)

    async def run(self, target: str) -> OSPipelineResult:
        """Run the full OS pipeline and return an OSPipelineResult."""
        registry = get_registry()
        registry.run_hook(HookPoint.BEFORE_PIPELINE, target=target)

        # Pre-flight dependency check --------------------------------------
        self._run_dep_check()

        target_input = TargetInput.from_raw(target)
        started_at = datetime.now(timezone.utc)
        started_perf = perf_counter()

        # Shared state for passing data between stages
        _results: dict[str, Any] = {}

        def _ctx(timeout: int | None = None) -> ModuleContext:
            if timeout is None:
                return self.context
            return ModuleContext(self.runner, self.store, timeout)

        # Stage coroutines --------------------------------------------------

        async def _stage_host_recon() -> StageResult:
            recon = ReconModule(self.config, self.context)
            recon_result: ReconResult = await recon.run(target_input)
            _results["host_recon"] = recon_result
            _results["assets"] = recon_result.assets
            return self._record_recon(recon_result)

        async def _stage_system_info() -> StageResult:
            mod = SystemInfoModule(self.config, self.context)
            res: SystemInfoResult = await mod.run(target_input)
            _results["system_info"] = res
            return self._record("system_info", res, 1 if res.system_info is not None else 0)

        async def _stage_services() -> StageResult:
            mod = ServicesModule(self.config, self.context)
            res: ServicesResult = await mod.run(target_input)
            _results["services"] = res
            return self._record("services", res, len(res.services))

        async def _stage_users() -> StageResult:
            mod = UsersModule(self.config, self.context)
            res: UsersResult = await mod.run(target_input)
            _results["users"] = res
            return self._record("users", res, len(res.users))

        async def _stage_filesystem() -> StageResult:
            mod = FilesystemModule(self.config, self.context)
            res: FilesystemResult = await mod.run(target_input)
            _results["filesystem"] = res
            return self._record("filesystem", res, len(res.entries))

        async def _stage_network() -> StageResult:
            mod = NetworkModule(self.config, self.context)
            res: NetworkResult = await mod.run(target_input)
            _results["network"] = res
            return self._record("network", res, res.interface_count)

        async def _stage_capabilities() -> StageResult:
            mod = CapabilitiesModule(self.config, self.context)
            res: CapabilitiesResult = await mod.run(target_input)
            _results["capabilities"] = res
            return self._record("capabilities", res, len(res.entries))

        async def _stage_sudo() -> StageResult:
            mod = SudoModule(self.config, self.context)
            res: SudoResult = await mod.run(target_input)
            _results["sudo"] = res
            return self._record("sudo", res, len(res.entries))

        async def _stage_privilege_escalation() -> StageResult:
            mod = PrivilegeEscalationModule(self.config, self.context)
            res: PrivilegeEscalationResult = await mod.run(target_input)
            _results["privilege_escalation"] = res
            return self._record("privilege_escalation", res, len(res.findings))

        # New stages -------------------------------------------------------

        async def _stage_ssh() -> StageResult:
            mod = SshModule(self.config, self.context)
            res: SshResult = await mod.run(target_input)
            _results["ssh"] = res
            return self._record("ssh", res, len(res.settings))

        async def _stage_cron() -> StageResult:
            mod = CronModule(self.config, self.context)
            res: CronResult = await mod.run(target_input)
            _results["cron"] = res
            return self._record("cron", res, res.total_count)

        async def _stage_systemd() -> StageResult:
            mod = SystemdModule(self.config, self.context)
            res: SystemdResult = await mod.run(target_input)
            _results["systemd"] = res
            return self._record("systemd", res, len(res.services))

        async def _stage_docker() -> StageResult:
            mod = DockerModule(self.config, self.context)
            res: DockerResult = await mod.run(target_input)
            _results["docker"] = res
            return self._record("docker", res, len(res.running_containers))

        async def _stage_kernel() -> StageResult:
            mod = KernelModule(self.config, self.context)
            res: KernelResult = await mod.run(target_input)
            _results["kernel"] = res
            return self._record("kernel", res, len(res.loaded_modules))

        async def _stage_environment() -> StageResult:
            mod = EnvironmentModule(self.config, self.context)
            res: EnvironmentResult = await mod.run(target_input)
            _results["environment"] = res
            return self._record("environment", res, len(res.variables))

        async def _stage_processes() -> StageResult:
            mod = ProcessesModule(self.config, self.context)
            res: ProcessesResult = await mod.run(target_input)
            _results["processes"] = res
            return self._record("processes", res, res.total_count)

        async def _stage_packages() -> StageResult:
            mod = PackagesModule(self.config, self.context)
            res: PackagesResult = await mod.run(target_input)
            _results["packages"] = res
            return self._record("packages", res, res.total_count)

        async def _stage_logs() -> StageResult:
            mod = LogsModule(self.config, self.context)
            res: LogsResult = await mod.run(target_input)
            _results["logs"] = res
            return self._record("logs", res, len(res.entries))

        async def _stage_secrets() -> StageResult:
            mod = SecretsModule(self.config, self.context)
            res: SecretsResult = await mod.run(target_input)
            _results["secrets"] = res
            return self._record("secrets", res, res.total_count)

        # Build stage definitions ------------------------------------------
        stages = [
            StageDef("host_recon", _STAGE_DEPS["host_recon"], _stage_host_recon, RetryConfig()),
            StageDef("system_info", _STAGE_DEPS["system_info"], _stage_system_info, RetryConfig()),
            StageDef("ssh", _STAGE_DEPS["ssh"], _stage_ssh, RetryConfig()),
            StageDef("kernel", _STAGE_DEPS["kernel"], _stage_kernel, RetryConfig()),
            StageDef("environment", _STAGE_DEPS["environment"], _stage_environment, RetryConfig()),
            StageDef("packages", _STAGE_DEPS["packages"], _stage_packages, RetryConfig()),
            StageDef("services", _STAGE_DEPS["services"], _stage_services, RetryConfig()),
            StageDef("users", _STAGE_DEPS["users"], _stage_users, RetryConfig()),
            StageDef("filesystem", _STAGE_DEPS["filesystem"], _stage_filesystem, RetryConfig()),
            StageDef("network", _STAGE_DEPS["network"], _stage_network, RetryConfig()),
            StageDef("processes", _STAGE_DEPS["processes"], _stage_processes, RetryConfig()),
            StageDef("cron", _STAGE_DEPS["cron"], _stage_cron, RetryConfig()),
            StageDef("systemd", _STAGE_DEPS["systemd"], _stage_systemd, RetryConfig()),
            StageDef("docker", _STAGE_DEPS["docker"], _stage_docker, RetryConfig()),
            StageDef("logs", _STAGE_DEPS["logs"], _stage_logs, RetryConfig()),
            StageDef("secrets", _STAGE_DEPS["secrets"], _stage_secrets, RetryConfig()),
            StageDef("capabilities", _STAGE_DEPS["capabilities"], _stage_capabilities, RetryConfig()),
            StageDef("sudo", _STAGE_DEPS["sudo"], _stage_sudo, RetryConfig()),
            StageDef("privilege_escalation", _STAGE_DEPS["privilege_escalation"], _stage_privilege_escalation, RetryConfig()),
        ]

        scheduler = PipelineScheduler(max_parallel=self._MAX_PARALLEL)
        scheduler_result = await scheduler.run(stages)

        # Collect findings from scanner results ----------------------------
        findings: list[Finding] = []
        registry.run_hook(HookPoint.BEFORE_FINDING, findings=findings)
        result_keys = [
            "system_info", "ssh", "kernel", "environment", "packages",
            "services", "users", "filesystem", "network", "processes",
            "cron", "systemd", "docker", "logs", "secrets",
            "capabilities", "sudo", "privilege_escalation",
        ]
        for key in result_keys:
            res = _results.get(key)
            if res is not None:
                sf = getattr(res, "findings", None) or []
                findings.extend(sf)

        # Vulnerability intelligence -----------------------------------------
        registry.run_hook(HookPoint.BEFORE_VULNERABILITY_LOOKUP, findings=findings)
        vuln_matches: list[Any] = []
        vuln_stats: Any = None
        inventory: list[Any] = []
        if findings:
            from ...core.vuln_intel import (
                VulnerabilityEngine, build_software_inventory, compute_vuln_stats,
            )
            inventory = build_software_inventory(findings)
            ve = VulnerabilityEngine()
            vuln_matches = ve.run(inventory)
            vuln_findings = [m.to_finding() for m in vuln_matches]
            findings.extend(vuln_findings)
            feed_meta = None
            try:
                from ...core.feed_manager import get_feed_status
                feed_meta = get_feed_status()
            except Exception:
                pass
            vuln_stats = compute_vuln_stats(vuln_matches, len(inventory), feed_metadata=feed_meta)
        registry.run_hook(HookPoint.AFTER_VULNERABILITY_LOOKUP, findings=findings, vuln_matches=vuln_matches, vuln_stats=vuln_stats)

        # Aggregate, enrich, correlate, exploitability ----------------------
        agg = FindingAggregator()
        agg.add_findings(findings)
        stats = agg.statistics()
        target_display = target_input.root_domain or target_input.hostname or target_input.normalized
        reports_dir = self.output_root / "reports"

        from ...core.correlation import CorrelationEngine, compute_correlation_stats
        from ...core.knowledge import EnrichmentEngine
        from ...core.exploitability import (
            ExploitabilityEngine, compute_exploitability_summary,
        )

        ee = EnrichmentEngine()
        enriched = ee.enrich_all(findings)
        registry.run_hook(HookPoint.BEFORE_CORRELATION, findings=enriched)
        ce = CorrelationEngine()
        paths = ce.run(enriched)
        registry.run_hook(HookPoint.AFTER_CORRELATION, findings=enriched, attack_paths=paths)
        ac_stats = compute_correlation_stats(paths)

        # Exploitability analysis
        registry.run_hook(HookPoint.BEFORE_EXPLOITABILITY, findings=enriched, attack_paths=paths, vuln_matches=vuln_matches)
        exp_engine = ExploitabilityEngine()
        exp_assessments = exp_engine.run(
            findings=findings, enriched=enriched,
            attack_paths=paths, vuln_matches=vuln_matches,
            inventory=inventory,
        )
        exp_summary = compute_exploitability_summary(exp_assessments)

        stats.attack_paths_total = ac_stats.total_paths
        stats.attack_paths_by_severity = ac_stats.by_severity
        stats.highest_attack_severity = ac_stats.highest_severity
        stats.average_attack_confidence = ac_stats.average_confidence
        stats.overall_risk_score = ac_stats.overall_risk_score
        stats.critical_chains = ac_stats.critical_chains
        stats.high_chains = ac_stats.high_chains

        registry.run_hook(HookPoint.AFTER_FINDING, findings=findings, enriched=enriched)

        # Generate reports --------------------------------------------------
        if findings:
            registry.run_hook(HookPoint.BEFORE_REPORT, findings=enriched, attack_paths=paths, vuln_matches=vuln_matches)
            generated = generate_reports(
                target=target_display,
                findings=enriched,
                stage_results=scheduler_result.stage_results,
                stats=stats,
                aggregator=agg,
                output_dir=reports_dir,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc),
                enrich=False,
                correlate_enabled=False,
                attack_paths=paths,
                vuln_matches=vuln_matches,
                vuln_stats=vuln_stats,
                exploitability_assessments=exp_assessments,
                exploitability_summary=exp_summary,
            )
            registry.run_hook(HookPoint.AFTER_REPORT, generated=generated, findings=enriched)
            import logging
            logger = logging.getLogger(__name__)
            for fmt, path in generated.items():
                logger.info("Report generated: %s (%s)", path, fmt)

        registry.run_hook(HookPoint.AFTER_PIPELINE, target=target, findings=findings)
        # Build result -----------------------------------------------------
        finished_at = datetime.now(timezone.utc)
        total_duration = perf_counter() - started_perf
        summary = summary_for_stages(
            "OS Pipeline",
            target_display,
            scheduler_result.stage_results,
            scheduler_result.total_duration,
        )
        print(summary)

        return OSPipelineResult(
            target=target_input,
            started_at=started_at,
            finished_at=finished_at,
            total_duration=total_duration,
            stage_results=scheduler_result.stage_results,
            summary=summary,
            findings=findings,
            enriched_findings=enriched,
            attack_paths=paths,
            aggregator=agg,
            stats=stats,
            vuln_matches=vuln_matches,
            vuln_stats=vuln_stats,
            exploitability_assessments=exp_assessments,
            exploitability_summary=exp_summary,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_dep_check(self) -> None:
        """Check all OS tools and print the pre-flight summary."""
        results = self._dep_checker.check_all(_OS_TOOLS)
        self._dep_checker.print_summary(results)

    @staticmethod
    def _record(name: str, result: Any, record_count: int) -> StageResult:
        """Build and log a :class:`StageResult` from a module result."""
        cr = result.command_result
        stage = build_stage_result(
            name=name,
            command_result=cr,
            record_count=record_count,
            warnings=result.warnings,
            extra_duration=result.execution_time_seconds,
        )
        log_stage_result(stage)
        return stage

    @staticmethod
    def _record_recon(result: ReconResult) -> StageResult:
        """Build a StageResult for the host_recon stage (multiple commands)."""
        any_succeeded = any(cr.succeeded for cr in result.command_results)
        any_missing = any(cr.missing_executable for cr in result.command_results)
        any_timedout = any(cr.timed_out for cr in result.command_results)
        primary = result.command_results[0] if result.command_results else None

        if not result.command_results:
            stage = build_skipped_stage("host_recon")
            log_stage_result(stage)
            return stage

        record_count = len(result.assets)
        if not any_succeeded and record_count > 0:
            status = StageState.SUCCESS
        elif any_missing:
            status = StageState.MISSING_DEPENDENCY
        elif any_timedout and record_count == 0:
            status = StageState.TIMEOUT
        elif record_count > 0:
            status = StageState.SUCCESS
        elif record_count == 0 and any_succeeded:
            status = StageState.EMPTY
        else:
            status = StageState.FAILED

        stage = StageResult(
            name="host_recon",
            status=status,
            command=primary.full_command if primary else "",
            exit_code=primary.returncode if primary else None,
            duration=0.0,
            record_count=record_count,
            warnings=result.warnings,
            timed_out=any_timedout,
            executable_missing=any_missing,
            started_at=primary.started_at if primary else "",
            finished_at=primary.finished_at if primary else "",
        )
        log_stage_result(stage)
        return stage


__all__ = [
    "OSPipelineResult",
    "StageResult",
    "StageState",
    "OSPipeline",
]
