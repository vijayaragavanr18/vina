"""OS-level log audit stage.

Inspects authentication logs, sudo logs, and failed login
attempts for security events.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...models.findings import Finding, make_finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)

_FAILED_LOGIN_PATTERN = re.compile(r"Failed password|authentication failure|FAILED LOGIN")
_SUDO_PATTERN = re.compile(r"sudo:\s+\w+")
_ROOT_LOGIN_PATTERN = re.compile(r"Accepted password for root|Accepted publickey for root")


@dataclass(slots=True)
class LogEntry:
    timestamp: str = ""
    source: str = ""
    message: str = ""
    user: str = ""
    ip: str = ""
    event_type: str = ""


@dataclass(slots=True)
class LogStatistics:
    failed_logins: int = 0
    sudo_events: int = 0
    root_logins: int = 0


@dataclass(slots=True)
class LogsResult:
    target: TargetInput
    command_result: CommandResult
    entries: list[LogEntry] = field(default_factory=list)
    stats: LogStatistics = field(default_factory=LogStatistics)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class LogsModule:
    """Audit system logs for security events."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> LogsResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("auth_log", self.config.tool_bin("cat", "cat"), ["/var/log/auth.log"]),
            ("secure_log", self.config.tool_bin("cat", "cat"), ["/var/log/secure"]),
            ("messages", self.config.tool_bin("cat", "cat"), ["/var/log/messages"]),
            ("syslog", self.config.tool_bin("cat", "cat"), ["/var/log/syslog"]),
            ("lastb", self.config.tool_bin("lastb", "lastb"), []),
            ("last", self.config.tool_bin("last", "last"), []),
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

        entries, stats = self._parse_logs(results, findings, target_str)

        if not entries:
            warnings.append("No log entries could be read. Log files may not exist or require root privileges.")

        primary = results.get("auth_log") or results.get("secure_log") or results.get("last") or self._empty_command_result()

        result = LogsResult(
            target=target_input,
            command_result=primary,
            entries=entries,
            stats=stats,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_logs(self, results: dict[str, CommandResult], findings: list[Finding], target_str: str) -> tuple[list[LogEntry], LogStatistics]:
        entries: list[LogEntry] = []
        stats = LogStatistics()

        for source_name in ("auth_log", "secure_log", "messages", "syslog"):
            cr = results.get(source_name)
            if cr is None or not cr.succeeded or not cr.stdout.strip():
                continue
            for line in cr.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue

                # Extract user
                user = ""
                ip = ""
                event_type = ""

                # Failed login
                if _FAILED_LOGIN_PATTERN.search(line):
                    stats.failed_logins += 1
                    event_type = "failed_login"
                    user_match = re.search(r"for\s+(\w+)", line)
                    if user_match:
                        user = user_match.group(1)
                    ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        ip = ip_match.group(1)

                # Sudo events
                elif _SUDO_PATTERN.search(line):
                    stats.sudo_events += 1
                    event_type = "sudo"

                # Root login
                if _ROOT_LOGIN_PATTERN.search(line):
                    stats.root_logins += 1
                    event_type = "root_login"
                    ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        ip = ip_match.group(1)
                    if not user:
                        user = "root"

                if event_type:
                    ts = line[:19] if len(line) > 19 else ""
                    entries.append(LogEntry(timestamp=ts, source=source_name, message=line[:200], user=user, ip=ip, event_type=event_type))

        # Generate findings based on statistics
        if stats.failed_logins > 0:
            findings.append(make_finding(
                title=f"Failed logins: {stats.failed_logins}",
                description=f"Found {stats.failed_logins} failed login attempts in system logs",
                severity="medium" if stats.failed_logins > 10 else "low",
                category="authentication",
                source_stage="logs",
                target=target_str,
                evidence=f"{stats.failed_logins} failed login attempts",
                recommendation="Investigate failed login attempts. Review /var/log/auth.log for patterns. Consider fail2ban.",
            ))

        if stats.root_logins > 0:
            findings.append(make_finding(
                title=f"Direct root logins: {stats.root_logins}",
                description=f"Found {stats.root_logins} direct root login(s) (not via su/sudo)",
                severity="high",
                category="authentication",
                source_stage="logs",
                target=target_str,
                evidence=f"{stats.root_logins} direct root login(s)",
                recommendation="Disable direct root login. Use sudo instead.",
            ))

        if stats.sudo_events > 100:
            findings.append(make_finding(
                title=f"High sudo usage: {stats.sudo_events} events",
                description=f"Found {stats.sudo_events} sudo events in logs",
                severity="low",
                category="information",
                source_stage="logs",
                target=target_str,
                evidence=f"{stats.sudo_events} sudo events",
            ))

        return entries, stats

    def _save_results(self, result: LogsResult) -> Path:
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "entries": [asdict(e) for e in result.entries],
            "stats": asdict(result.stats),
            "warnings": result.warnings,
            "findings": [f.to_dict() for f in result.findings],
        }
        return self.context.store.save("os/logs.json", payload)

    def _print_summary(self, result: LogsResult) -> None:
        print("----------------------------------------")
        print("Log Audit")
        print("----------------------------------------")
        print(f"Log Entries     : {len(result.entries)}")
        print(f"Failed Logins   : {result.stats.failed_logins}")
        print(f"Sudo Events     : {result.stats.sudo_events}")
        print(f"Root Logins     : {result.stats.root_logins}")
        print(f"Findings        : {len(result.findings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(command="logs", args=(), returncode=1, stdout="", stderr="", duration_seconds=0.0, timed_out=False, missing_executable=False, full_command="logs")


__all__ = ["LogsModule", "LogEntry", "LogStatistics", "LogsResult"]
