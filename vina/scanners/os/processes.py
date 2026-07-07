"""OS-level process audit stage.

Lists running processes, builds parent-child relationships,
identifies processes running as root, and flags suspicious binaries.
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

_SUSPICIOUS_BINARIES = (
    "nc",
    "netcat",
    "ncat",
    "socat",
    "tcpdump",
    "tshark",
    "john",
    "hashcat",
    "hydra",
    "medusa",
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "crack",
    "aircrack",
    "reaver",
    "miner",
    "xmrig",
    "cpuminer",
    "stratum",
)

_SUSPICIOUS_PATHS = ("/tmp", "/dev/shm", "/var/tmp", "/home/")  # nosec: B108


@dataclass(slots=True)
class ProcessInfo:
    pid: int
    user: str
    command: str
    cpu: str = ""
    mem: str = ""
    parent_pid: int = 0
    full_command: str = ""
    running_as_root: bool = False
    suspicious: bool = False


@dataclass(slots=True)
class ProcessesResult:
    target: TargetInput
    command_result: CommandResult
    processes: list[ProcessInfo] = field(default_factory=list)
    root_processes: int = 0
    suspicious_processes: int = 0
    total_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class ProcessesModule:
    """Audit running processes on the local host."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> ProcessesResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("ps_aux", self.config.tool_bin("ps", "ps"), ["aux"]),
            ("ps_ef", self.config.tool_bin("ps", "ps"), ["-ef"]),
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

        processes, root_count, susp_count = self._parse_processes(results, warnings, findings, target_str)

        if not processes:
            warnings.append("No process information could be collected")

        primary = results.get("ps_aux") or results.get("ps_ef") or self._empty_command_result()

        result = ProcessesResult(
            target=target_input,
            command_result=primary,
            processes=processes,
            root_processes=root_count,
            suspicious_processes=susp_count,
            total_count=len(processes),
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_processes(
        self, results: dict[str, CommandResult], _warnings: list[str], findings: list[Finding], target_str: str
    ) -> tuple[list[ProcessInfo], int, int]:
        processes: list[ProcessInfo] = []
        root_count = 0
        susp_count = 0

        cr = results.get("ps_aux") or results.get("ps_ef")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return processes, 0, 0

        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("USER") or line.startswith("UID"):
                continue
            parts = line.split()
            if len(parts) < 7:
                continue

            user = parts[0]
            pid_str = parts[1]
            try:
                pid = int(pid_str)
            except ValueError:
                continue

            # Parse based on whether it's `ps aux` or `ps -ef`
            if line.count(" ") > 10:  # ps aux format
                cpu = parts[2]
                mem = parts[3]
                cmd_start = 10 if len(parts) > 10 else len(parts)
                command = " ".join(parts[cmd_start - 1 :]) if cmd_start > 0 else ""
                full_cmd = " ".join(parts[10:]) if len(parts) > 10 else ""
                ppid = 0
            else:  # ps -ef format
                cpu = ""
                mem = ""
                ppid_str = parts[2] if len(parts) > 2 else "0"
                try:
                    ppid = int(ppid_str)
                except ValueError:
                    ppid = 0
                command = " ".join(parts[7:]) if len(parts) > 7 else ""
                full_cmd = command

            is_root = user == "root"
            bin_name = command.split()[0] if command else ""
            is_suspicious = self._is_suspicious(bin_name, full_cmd)

            if is_suspicious:
                findings.append(
                    make_finding(
                        title=f"Suspicious process: {bin_name}",
                        description=f"Suspicious binary running: {bin_name}",
                        severity="high",
                        category="process",
                        source_stage="processes",
                        target=target_str,
                        evidence=f"pid={pid} user={user} cmd={command[:120]}",
                        recommendation="Investigate this process. It may indicate a compromised system.",
                    )
                )
                susp_count += 1

            processes.append(
                ProcessInfo(
                    pid=pid,
                    user=user,
                    command=command[:100],
                    cpu=cpu,
                    mem=mem,
                    parent_pid=ppid,
                    full_command=full_cmd,
                    running_as_root=is_root,
                    suspicious=is_suspicious,
                )
            )
            if is_root:
                root_count += 1

        # Alert on too many root processes
        if root_count > 50:
            findings.append(
                make_finding(
                    title=f"High number of root processes ({root_count})",
                    description=f"Found {root_count} processes running as root",
                    severity="low",
                    category="process",
                    source_stage="processes",
                    target=target_str,
                    evidence=f"{root_count} root processes",
                    recommendation="Review whether all root processes are necessary",
                )
            )

        return processes, root_count, susp_count

    @staticmethod
    def _is_suspicious(bin_name: str, _full_cmd: str) -> bool:
        if not bin_name:
            return False
        base = bin_name.split("/")[-1].lower() if "/" in bin_name else bin_name.lower()
        if base in _SUSPICIOUS_BINARIES:
            return True
        return any(bin_name.startswith(p) for p in _SUSPICIOUS_PATHS)

    def _save_results(self, result: ProcessesResult) -> Path:
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "processes": [asdict(p) for p in result.processes],
            "root_processes": result.root_processes,
            "suspicious_processes": result.suspicious_processes,
            "total_count": result.total_count,
            "warnings": result.warnings,
            "findings": [f.to_dict() for f in result.findings],
        }
        return self.context.store.save("os/processes.json", payload)

    def _print_summary(self, result: ProcessesResult) -> None:
        print("----------------------------------------")
        print("Process Audit")
        print("----------------------------------------")
        print(f"Processes         : {result.total_count}")
        print(f"Root Processes    : {result.root_processes}")
        print(f"Suspicious        : {result.suspicious_processes}")
        print(f"Findings          : {len(result.findings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="processes",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="processes",
        )


__all__ = ["ProcessInfo", "ProcessesModule", "ProcessesResult"]
