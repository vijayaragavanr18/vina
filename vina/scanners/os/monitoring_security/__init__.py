"""Logging, Auditing, and Monitoring Security Stage for VINA.

PS-08: Audits system audit rules, journald config, remote syslog forwarding,
logrotate settings, time synchronization (NTP/Chrony), and intrusion detection agents.
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
from .agents import AgentsModule, AgentsResult
from .auditing import AuditingModule, AuditingResult
from .syslog import SyslogModule, SyslogResult
from .time_sync import TimeSyncModule, TimeSyncResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class MonitoringSecurityResult:
    """Aggregate result from all monitoring/auditing sub-scanners."""

    target: TargetInput
    command_result: CommandResult
    auditing: AuditingResult | None = None
    syslog: SyslogResult | None = None
    time_sync: TimeSyncResult | None = None
    agents: AgentsResult | None = None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class MonitoringSecurityModule:
    """Orchestrate all log and event monitoring security audits."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> MonitoringSecurityResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        audit_mod = AuditingModule(self.config, self.context)
        audit_res = await audit_mod.run(target_input)
        findings.extend(audit_res.findings)
        warnings.extend(audit_res.warnings)

        syslog_mod = SyslogModule(self.config, self.context)
        syslog_res = await syslog_mod.run(target_input)
        findings.extend(syslog_res.findings)
        warnings.extend(syslog_res.warnings)

        ts_mod = TimeSyncModule(self.config, self.context)
        ts_res = await ts_mod.run(target_input)
        findings.extend(ts_res.findings)
        warnings.extend(ts_res.warnings)

        agents_mod = AgentsModule(self.config, self.context)
        agents_res = await agents_mod.run(target_input)
        findings.extend(agents_res.findings)
        warnings.extend(agents_res.warnings)

        primary = (
            audit_res.command_result
            or syslog_res.command_result
            or ts_res.command_result
            or agents_res.command_result
            or self._empty_command_result()
        )

        result = MonitoringSecurityResult(
            target=target_input,
            command_result=primary,
            auditing=audit_res,
            syslog=syslog_res,
            time_sync=ts_res,
            agents=agents_res,
            findings=findings,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _save_results(self, result: MonitoringSecurityResult) -> Path:
        payload: dict[str, Any] = {
            "target": result.target.normalized,
            "duration_seconds": result.execution_time_seconds,
            "findings": [f.to_dict() for f in result.findings],
            "warnings": result.warnings,
        }
        return self.context.store.save("os/monitoring_security.json", payload)

    def _print_summary(self, result: MonitoringSecurityResult) -> None:
        print("----------------------------------------")
        print("Monitoring Security")
        print("----------------------------------------")
        print(f"Findings       : {len(result.findings)}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="monitoring_security",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="monitoring_security",
        )


__all__ = ["MonitoringSecurityModule", "MonitoringSecurityResult"]
