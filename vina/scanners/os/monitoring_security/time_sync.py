"""Time synchronization status auditing.

Checks if time synchronization (NTP/Chrony/systemd-timesyncd) is active and running.
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
class TimeSyncResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class TimeSyncModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> TimeSyncResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        timedatectl_cmd = self.config.tool_bin("timedatectl", "timedatectl")
        cr_td = await self.context.runner.run(timedatectl_cmd, [], timeout_seconds=5)

        synced = False
        if cr_td.succeeded and cr_td.stdout.strip():
            content = cr_td.stdout
            if "System clock synchronized: yes" in content or "NTP service: active" in content or "NTP synchronized: yes" in content:
                synced = True

        if not synced:
            findings.append(make_finding(
                title="System time synchronization is inactive",
                description="Time synchronization (NTP/Chrony/timesyncd) is disabled or not synchronized. Clock drift can compromise security token validation and prevent accurate event correlation during security incidents.",
                severity="medium",
                category="vulnerability",
                source_stage="monitoring_security",
                target=target_str,
                evidence="timedatectl indicates no active synchronization",
                recommendation="Enable systemd-timesyncd or Chrony: 'systemctl enable --now systemd-timesyncd'.",
                confidence=0.9,
            ))

        result = TimeSyncResult(
            target=target,
            command_result=cr_td,
            warnings=warnings,
            findings=findings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        return result
