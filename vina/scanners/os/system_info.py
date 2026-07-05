"""OS-level system-information collection stage.

Gathers local host metadata (hostname, kernel, CPU, memory, etc.)
by running lightweight system commands through AsyncCommandRunner.
"""

from __future__ import annotations

import contextlib
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SystemInfo:
    """Collected system metadata for the local host."""

    hostname: str | None = None
    operating_system: str | None = None
    kernel_version: str | None = None
    architecture: str | None = None
    distribution: str | None = None
    uptime: str | None = None
    current_user: str | None = None
    cpu_model: str | None = None
    cpu_count: int | None = None
    memory_total: str | None = None
    memory_used: str | None = None
    memory_available: str | None = None


@dataclass(slots=True)
class SystemInfoResult:
    """Structured result for the system-info collection stage."""

    target: TargetInput
    command_result: CommandResult
    system_info: SystemInfo | None = None
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class SystemInfoModule:
    """Collect local system metadata by running OS commands."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> SystemInfoResult:
        """Execute system commands and return collected metadata.

        Parameters
        ----------
        target:
            Target metadata attached to the result.
        """
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("hostname", self.config.tool_bin("hostname", "hostname"), []),
            ("kernel", self.config.tool_bin("uname", "uname"), ["-s"]),
            ("kernel_version", self.config.tool_bin("uname", "uname"), ["-r"]),
            ("architecture", self.config.tool_bin("uname", "uname"), ["-m"]),
            ("distribution", self.config.tool_bin("cat", "cat"), ["/etc/os-release"]),
            ("uptime", self.config.tool_bin("uptime", "uptime"), ["-p"]),
            ("whoami", self.config.tool_bin("whoami", "whoami"), []),
            ("cpu", self.config.tool_bin("lscpu", "lscpu"), []),
            ("memory", self.config.tool_bin("free", "free"), ["-h"]),
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
                stderr_snippet = cr.stderr.strip()[:120] if cr.stderr.strip() else ""
                msg = f"{name} exited with code {cr.returncode}"
                if stderr_snippet:
                    msg += f": {stderr_snippet}"
                warnings.append(msg)

        info = self._parse_info(results, warnings)

        primary = results.get("hostname") or next(
            (cr for cr in results.values() if cr.succeeded), self._empty_command_result()
        )

        if info is None:
            warnings.append("No system information could be collected")
        elif not any((info.hostname, info.kernel_version, info.architecture, info.distribution, info.current_user)):
            warnings.append("System information is incomplete")

        result = SystemInfoResult(
            target=target_input,
            command_result=primary,
            system_info=info,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_info(self, results: dict[str, CommandResult], _warnings: list[str]) -> SystemInfo | None:
        """Parse collected command outputs into a SystemInfo instance."""
        hostname = self._stdout_or_none(results.get("hostname"))
        kernel_raw = self._stdout_or_none(results.get("kernel"))
        kernel_version = self._stdout_or_none(results.get("kernel_version"))
        architecture = self._stdout_or_none(results.get("architecture"))
        distribution_raw = self._stdout_or_none(results.get("distribution"))
        uptime = self._stdout_or_none(results.get("uptime"))
        current_user = self._stdout_or_none(results.get("whoami"))
        cpu_raw = self._stdout_or_none(results.get("cpu"))
        memory_raw = self._stdout_or_none(results.get("memory"))

        if not hostname and not kernel_version and not architecture and not distribution_raw and not current_user:
            return None

        distribution = self._parse_distribution(distribution_raw) if distribution_raw else None
        cpu_model, cpu_count = self._parse_cpu_info(cpu_raw) if cpu_raw else (None, None)
        mem_total, mem_used, mem_avail = self._parse_memory(memory_raw) if memory_raw else (None, None, None)

        if uptime and uptime.startswith("up "):
            uptime = uptime
        elif uptime and not uptime.startswith("up"):
            uptime = f"up {uptime}"

        return SystemInfo(
            hostname=hostname,
            operating_system=kernel_raw,
            kernel_version=kernel_version,
            architecture=architecture,
            distribution=distribution,
            uptime=uptime,
            current_user=current_user,
            cpu_model=cpu_model,
            cpu_count=cpu_count,
            memory_total=mem_total,
            memory_used=mem_used,
            memory_available=mem_avail,
        )

    @staticmethod
    def _parse_distribution(raw: str) -> str | None:
        """Extract a human-readable distro string from ``/etc/os-release``."""
        fields: dict[str, str] = {}
        for line in raw.splitlines():
            line = line.strip()
            if "=" in line:
                key, _, value = line.partition("=")
                fields[key.strip()] = value.strip().strip('"').strip("'")
        pretty = fields.get("PRETTY_NAME")
        if pretty:
            return pretty
        name = fields.get("NAME")
        version = fields.get("VERSION_ID")
        if name and version:
            return f"{name} {version}"
        return name or None

    @staticmethod
    def _parse_cpu_info(raw: str) -> tuple[str | None, int | None]:
        """Parse ``lscpu`` output for model name and core count."""
        model: str | None = None
        cores: int | None = None
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("Model name:"):
                model = line.split(":", 1)[1].strip()
            elif line.startswith("CPU(s):"):
                with contextlib.suppress(ValueError, IndexError):
                    cores = int(line.split(":", 1)[1].strip())
        return model, cores

    @staticmethod
    def _parse_memory(raw: str) -> tuple[str | None, str | None, str | None]:
        """Parse ``free -h`` output for Mem line values."""
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("Mem:"):
                parts = line.split()
                if len(parts) >= 7:
                    return parts[1], parts[2], parts[6]
                if len(parts) >= 4:
                    return parts[1], parts[2], parts[3]
        return None, None, None

    @staticmethod
    def _stdout_or_none(cr: CommandResult | None) -> str | None:
        """Return stripped stdout if the command succeeded, else ``None``."""
        if cr is None or not cr.succeeded:
            return None
        text = cr.stdout.strip()
        return text if text else None

    @staticmethod
    def _deduplicate(info: SystemInfo) -> SystemInfo:
        """Return the SystemInfo unchanged (no dedup needed)."""
        return info

    def _save_results(self, result: SystemInfoResult) -> Path:
        """Persist system-info results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "system_info": asdict(result.system_info) if result.system_info else None,
            "warnings": result.warnings,
        }
        return self.context.store.save("os/system_info.json", payload)

    def _print_summary(self, result: SystemInfoResult) -> None:
        """Print a concise summary of collected system info."""
        print("----------------------------------------")
        print("System Info")
        print("----------------------------------------")
        info = result.system_info
        if info is None:
            print("No system information collected")
            return
        print(f"Hostname    : {info.hostname or 'N/A'}")
        print(f"OS          : {info.operating_system or 'N/A'}")
        print(f"Kernel      : {info.kernel_version or 'N/A'}")
        print(f"Arch        : {info.architecture or 'N/A'}")
        print(f"Distro      : {info.distribution or 'N/A'}")
        print(f"Uptime      : {info.uptime or 'N/A'}")
        print(f"User        : {info.current_user or 'N/A'}")
        print(f"CPU         : {info.cpu_model or 'N/A'}")
        print(f"CPU Cores   : {info.cpu_count or 'N/A'}")
        print(
            f"Memory      : {info.memory_total or 'N/A'} "
            f"(used {info.memory_used or 'N/A'}, "
            f"available {info.memory_available or 'N/A'})"
        )

    @staticmethod
    def _empty_command_result() -> CommandResult:
        """Build a no-op CommandResult for the no-data case."""
        return CommandResult(
            command="system_info",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="system_info",
        )


__all__ = ["SystemInfo", "SystemInfoModule", "SystemInfoResult"]
