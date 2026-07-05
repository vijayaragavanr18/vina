"""OS-level scheduled task inspection stage.

Examines /etc/crontab, cron.d, cron.daily, cron.weekly, cron.monthly,
and user crontabs for security issues.
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
class CronEntry:
    schedule: str
    command: str
    user: str | None = None
    source: str = ""
    line: int | None = None


@dataclass(slots=True)
class CronDirEntry:
    directory: str
    files: list[str] = field(default_factory=list)
    writable_files: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CronResult:
    target: TargetInput
    command_result: CommandResult
    entries: list[CronEntry] = field(default_factory=list)
    dir_entries: list[CronDirEntry] = field(default_factory=list)
    total_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


_CRON_DIRS = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.hourly"]


class CronModule:
    """Inspect scheduled tasks and cron configuration."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> CronResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("cat_crontab", self.config.tool_bin("cat", "cat"), ["/etc/crontab"]),
            ("crontab_l", self.config.tool_bin("crontab", "crontab"), ["-l"]),
        ]
        for d in _CRON_DIRS:
            safe = d.replace("/", "_")
            commands.append((f"ls_{safe}", self.config.tool_bin("ls", "ls"), ["-la", d]))

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
        entries = self._parse_entries(results, warnings, findings, target_input)
        dir_entries = self._parse_dir_entries(results, warnings, findings, target_input)

        if not entries and not dir_entries:
            warnings.append("No cron entries could be read")

        primary = results.get("cat_crontab") or results.get("crontab_l") or self._empty_command_result()

        result = CronResult(
            target=target_input,
            command_result=primary,
            entries=entries,
            dir_entries=dir_entries,
            total_count=len(entries),
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_entries(self, results: dict[str, CommandResult], warnings: list[str], findings: list[Finding], target: TargetInput) -> list[CronEntry]:
        entries: list[CronEntry] = []
        target_str = target.normalized

        # /etc/crontab
        cr = results.get("cat_crontab")
        if cr and cr.succeeded and cr.stdout.strip():
            for line_no, raw in enumerate(cr.stdout.splitlines(), 1):
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("SHELL") or line.startswith("PATH") or line.startswith("MAILTO"):
                    continue
                parts = line.split()
                if len(parts) >= 6:
                    schedule = " ".join(parts[:5])
                    user = parts[5]
                    command = " ".join(parts[6:])
                    entry = CronEntry(schedule=schedule, command=command, user=user, source="/etc/crontab", line=line_no)
                    entries.append(entry)
                    if user in ("root",) and any(w in command.lower() for w in ("wget", "curl", "bash", "sh", "python", "perl")):
                        findings.append(make_finding(
                            title=f"Root cron job: {command[:60]}",
                            description=f"Root runs cron job: {command}",
                            severity="medium",
                            category="scheduled_task",
                            source_stage="cron",
                            target=target_str,
                            evidence=f"schedule={schedule} user={user} command={command}",
                            recommendation="Verify this cron job is intentional and the target script is not world-writable",
                        ))

        # User crontab
        ucr = results.get("crontab_l")
        if ucr and ucr.succeeded and ucr.stdout.strip():
            for line_no, raw in enumerate(ucr.stdout.splitlines(), 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 6:
                    schedule = " ".join(parts[:5])
                    command = " ".join(parts[5:])
                    entries.append(CronEntry(schedule=schedule, command=command, source="user crontab", line=line_no))
                elif len(parts) >= 5:
                    schedule = " ".join(parts[:5])
                    command = " ".join(parts[5:])
                    entries.append(CronEntry(schedule=schedule, command=command, source="user crontab", line=line_no))

        return entries

    def _parse_dir_entries(self, results: dict[str, CommandResult], warnings: list[str], findings: list[Finding], target: TargetInput) -> list[CronDirEntry]:
        dir_entries: list[CronDirEntry] = []
        target_str = target.normalized

        for d in _CRON_DIRS:
            safe = d.replace("/", "_")
            cr = results.get(f"ls_{safe}")
            if cr is None or not cr.stdout.strip():
                continue

            files: list[str] = []
            writable: list[str] = []
            for line in cr.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("total"):
                    continue
                parts = line.split()
                if len(parts) >= 9:
                    name = parts[-1]
                    perm = parts[0]
                    if not name.startswith("."):
                        files.append(name)
                        if len(perm) >= 4 and perm[3] == "w":
                            writable.append(f"{name} ({perm})")

            dir_entries.append(CronDirEntry(directory=d, files=files, writable_files=writable))

            if writable:
                findings.append(make_finding(
                    title=f"Writable files in {d}",
                    description=f"Found {len(writable)} writable file(s) in {d}",
                    severity="high",
                    category="misconfiguration",
                    source_stage="cron",
                    target=target_str,
                    evidence="\n".join(writable),
                    recommendation="Ensure cron files are owned by root and not world-writable",
                ))

        return dir_entries

    def _save_results(self, result: CronResult) -> Path:
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "entries": [asdict(e) for e in result.entries],
            "dir_entries": [asdict(d) for d in result.dir_entries],
            "total_count": result.total_count,
            "warnings": result.warnings,
            "findings": [f.to_dict() for f in result.findings],
        }
        return self.context.store.save("os/cron.json", payload)

    def _print_summary(self, result: CronResult) -> None:
        print("----------------------------------------")
        print("Cron Audit")
        print("----------------------------------------")
        print(f"Cron Entries   : {result.total_count}")
        print(f"Dir Entries    : {len(result.dir_entries)}")
        print(f"Findings       : {len(result.findings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(command="cron", args=(), returncode=1, stdout="", stderr="", duration_seconds=0.0, timed_out=False, missing_executable=False, full_command="cron")


__all__ = ["CronModule", "CronEntry", "CronDirEntry", "CronResult"]
