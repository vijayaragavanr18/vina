"""OS-level systemd service audit stage.

Inspects enabled services, writable service files,
dangerous ExecStart paths, and timer units.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...models.findings import Finding, make_finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SystemdServiceEntry:
    unit: str
    state: str
    path: str | None = None
    exec_start: str | None = None
    writable: bool = False


@dataclass(slots=True)
class TimerEntry:
    unit: str
    state: str | None = None
    next_trigger: str | None = None


@dataclass(slots=True)
class SystemdResult:
    target: TargetInput
    command_result: CommandResult
    services: list[SystemdServiceEntry] = field(default_factory=list)
    timers: list[TimerEntry] = field(default_factory=list)
    enabled_count: int = 0
    writable_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class SystemdModule:
    """Audit systemd services and timers on the local host."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> SystemdResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("list_units", self.config.tool_bin("systemctl", "systemctl"), ["list-unit-files"]),
            ("list_timers", self.config.tool_bin("systemctl", "systemctl"), ["list-timers", "--all"]),
            ("find_writable", self.config.tool_bin("find", "find"), ["/etc/systemd/system", "-writable", "-type", "f"]),
        ]

        results: dict[str, CommandResult] = {}
        for name, executable, args in commands:
            cr = await self.context.runner.run(executable, args, timeout_seconds=self.context.timeout_seconds)
            results[name] = cr
            if cr.missing_executable:
                warnings.append(f"Missing executable: {executable}")
            if cr.timed_out:
                warnings.append(f"{name} timed out after {self.context.timeout_seconds}s")
            if cr.returncode not in (0, None) and not cr.timed_out and not cr.missing_executable:
                warnings.append(f"{name} exited with code {cr.returncode}")

        findings: list[Finding] = []
        target_str = target_input.normalized

        services = self._parse_services(results, warnings, findings, target_str)
        timers = self._parse_timers(results, warnings)
        writable_files = self._parse_writable(results, warnings)
        writable_count = len(writable_files)

        enabled_count = sum(1 for s in services if s.state == "enabled")

        for wf in writable_files:
            findings.append(
                make_finding(
                    title=f"Writable systemd unit: {wf}",
                    description=f"Systemd unit file {wf} is world-writable",
                    severity="high",
                    category="misconfiguration",
                    source_stage="systemd",
                    target=target_str,
                    evidence=wf,
                    recommendation="Restrict permissions: chmod 644 <file> && chown root:root <file>",
                )
            )

        if not services:
            warnings.append("No systemd services could be enumerated")

        primary = results.get("list_units") or results.get("list_timers") or self._empty_command_result()

        result = SystemdResult(
            target=target_input,
            command_result=primary,
            services=services,
            timers=timers,
            enabled_count=enabled_count,
            writable_count=writable_count,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_services(
        self, results: dict[str, CommandResult], _warnings: list[str], findings: list[Finding], target_str: str
    ) -> list[SystemdServiceEntry]:
        services: list[SystemdServiceEntry] = []
        cr = results.get("list_units")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return services

        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0].endswith(".service"):
                unit = parts[0]
                state = parts[1].lower() if len(parts) > 1 else "unknown"
                services.append(SystemdServiceEntry(unit=unit, state=state))

        # Check for dangerous services
        dangerous_prefixes = ("sshd", "docker", "containerd", "kube", "webmin", "mysql", "postgresql")
        for s in services:
            if s.state == "enabled" and any(s.unit.startswith(p) for p in dangerous_prefixes):
                findings.append(
                    make_finding(
                        title=f"Enabled service: {s.unit}",
                        description=f"Service {s.unit} is enabled and potentially exposes attack surface",
                        severity="info",
                        category="service",
                        source_stage="systemd",
                        target=target_str,
                        evidence=s.unit,
                    )
                )

        # Check for writable-looking services (running from /tmp, /dev/shm, /var/tmp)
        for s in services:
            suspicious_prefixes = ("/tmp", "/dev/shm", "/var/tmp")  # nosec: B108
            if s.exec_start and any(s.exec_start.startswith(p) for p in suspicious_prefixes):
                findings.append(
                    make_finding(
                        title=f"Suspicious ExecStart: {s.exec_start}",
                        description=f"Service {s.unit} runs from a world-writable path: {s.exec_start}",
                        severity="high",
                        category="misconfiguration",
                        source_stage="systemd",
                        target=target_str,
                        evidence=f"{s.unit}: {s.exec_start}",
                        recommendation="Move the binary to a system path and ensure correct ownership",
                    )
                )

        return services

    @staticmethod
    def _parse_timers(results: dict[str, CommandResult], _warnings: list[str]) -> list[TimerEntry]:
        timers: list[TimerEntry] = []
        cr = results.get("list_timers")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return timers
        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("NEXT") or line.startswith("---"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                timers.append(TimerEntry(unit=parts[-1], next_trigger=parts[0]))
        return timers

    @staticmethod
    def _parse_writable(results: dict[str, CommandResult], _warnings: list[str]) -> list[str]:
        cr = results.get("find_writable")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return []
        return [line.strip() for line in cr.stdout.splitlines() if line.strip()]

    def _save_results(self, result: SystemdResult) -> Path:
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "services": [asdict(s) for s in result.services],
            "timers": [asdict(t) for t in result.timers],
            "enabled_count": result.enabled_count,
            "writable_count": result.writable_count,
            "warnings": result.warnings,
            "findings": [f.to_dict() for f in result.findings],
        }
        return self.context.store.save("os/systemd.json", payload)

    def _print_summary(self, result: SystemdResult) -> None:
        print("----------------------------------------")
        print("Systemd Audit")
        print("----------------------------------------")
        print(f"Services       : {len(result.services)}")
        print(f"Enabled        : {result.enabled_count}")
        print(f"Timers         : {len(result.timers)}")
        print(f"Writable Files : {result.writable_count}")
        print(f"Findings       : {len(result.findings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="systemd",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="systemd",
        )


__all__ = ["SystemdModule", "SystemdResult", "SystemdServiceEntry", "TimerEntry"]
