"""OS-level service-discovery stage.

Collects system service information by running systemctl or
falling back to service --status-all through AsyncCommandRunner.
"""

from __future__ import annotations

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
class ServiceInfo:
    """A single system service entry."""

    name: str
    state: str | None = None
    enabled: str | None = None
    unit_file: str | None = None
    description: str | None = None
    source_command: str | None = None


@dataclass(slots=True)
class ServicesResult:
    """Structured result for the service-discovery stage."""

    target: TargetInput
    command_result: CommandResult
    services: list[ServiceInfo] = field(default_factory=list)
    active_count: int = 0
    inactive_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class ServicesModule:
    """Collect system service information using systemctl or fallback."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(
        self,
        target: TargetInput,
    ) -> ServicesResult:
        """Execute system commands and return discovered services.

        Parameters
        ----------
        target:
            Target metadata attached to the result.
        """
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            (
                "systemctl_list_units",
                self.config.tool_bin("systemctl", "systemctl"),
                ["list-units", "--type=service", "--all", "--no-pager", "--no-legend"],
            ),
            (
                "systemctl_list_files",
                self.config.tool_bin("systemctl", "systemctl"),
                ["list-unit-files", "--type=service", "--no-pager", "--no-legend"],
            ),
            (
                "service_status",
                self.config.tool_bin("service", "service"),
                ["--status-all"],
            ),
        ]

        results: dict[str, CommandResult] = {}
        for name, executable, args in commands:
            cr = await self.context.runner.run(
                executable,
                args,
                timeout_seconds=self.context.timeout_seconds,
            )
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

        services = self._parse_services(results, warnings)

        primary = (
            results.get("systemctl_list_units")
            or results.get("systemctl_list_files")
            or results.get("service_status")
            or self._empty_command_result()
        )

        if not services:
            warnings.append("No services could be discovered")

        active_count = sum(1 for s in services if s.state and s.state in ("running", "active"))
        inactive_count = sum(1 for s in services if s.state and s.state not in ("running", "active", None, ""))

        result = ServicesResult(
            target=target_input,
            command_result=primary,
            services=services,
            active_count=active_count,
            inactive_count=inactive_count,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_services(
        self,
        results: dict[str, CommandResult],
        warnings: list[str],
    ) -> list[ServiceInfo]:
        """Parse command outputs into a deduplicated list of ServiceInfo."""
        units_result = results.get("systemctl_list_units")
        files_result = results.get("systemctl_list_files")
        service_result = results.get("service_status")

        units: list[ServiceInfo] = []
        files: dict[str, ServiceInfo] = {}
        fallback: list[ServiceInfo] = []

        if units_result and units_result.succeeded and units_result.stdout.strip():
            units = self._parse_list_units(units_result.stdout, warnings)
        if files_result and files_result.succeeded and files_result.stdout.strip():
            parsed = self._parse_list_files(files_result.stdout, warnings)
            for svc in parsed:
                files[svc.name] = svc

        merged: dict[str, ServiceInfo] = {}
        for svc in units:
            file_info = files.pop(svc.name, None)
            merged[svc.name] = ServiceInfo(
                name=svc.name,
                state=svc.state,
                enabled=file_info.enabled if file_info else svc.enabled,
                unit_file=svc.unit_file,
                description=svc.description,
                source_command="systemctl list-units",
            )
        for svc in files.values():
            if svc.name not in merged:
                merged[svc.name] = ServiceInfo(
                    name=svc.name,
                    state=svc.state,
                    enabled=svc.enabled,
                    unit_file=svc.unit_file,
                    source_command="systemctl list-unit-files",
                )

        if not merged and service_result and service_result.succeeded and service_result.stdout.strip():
            fallback = self._parse_service_status(service_result.stdout, warnings)
            for svc in fallback:
                merged[svc.name] = svc

        return list(merged.values())

    @staticmethod
    def _parse_list_units(stdout: str, warnings: list[str]) -> list[ServiceInfo]:
        """Parse ``systemctl list-units`` output into ServiceInfo objects."""
        services: list[ServiceInfo] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            tokens = line.split()
            if len(tokens) < 4:
                continue
            try:
                unit = tokens[0]
                active = tokens[2]
                sub = tokens[3]
                description = " ".join(tokens[4:]) if len(tokens) > 4 else ""
                state = "running" if active == "active" and sub == "running" else sub or active
                services.append(
                    ServiceInfo(
                        name=unit,
                        state=state,
                        enabled=None,
                        unit_file=unit,
                        description=description or None,
                        source_command="systemctl list-units",
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse systemctl unit line: {line}")
        return services

    @staticmethod
    def _parse_list_files(stdout: str, warnings: list[str]) -> list[ServiceInfo]:
        """Parse ``systemctl list-unit-files`` output into ServiceInfo objects."""
        services: list[ServiceInfo] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            tokens = line.split()
            if len(tokens) < 2:
                continue
            try:
                unit = tokens[0]
                enabled = tokens[1]
                services.append(
                    ServiceInfo(
                        name=unit,
                        state=None,
                        enabled=enabled,
                        unit_file=unit,
                        source_command="systemctl list-unit-files",
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse systemctl unit-file line: {line}")
        return services

    @staticmethod
    def _parse_service_status(stdout: str, warnings: list[str]) -> list[ServiceInfo]:
        """Parse ``service --status-all`` output into ServiceInfo objects."""
        services: list[ServiceInfo] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("["):
                continue
            tokens = line.split()
            if len(tokens) < 3:
                continue
            try:
                indicator = tokens[1]
                name = tokens[-1]
                if indicator == "+":
                    state = "running"
                elif indicator == "-":
                    state = "stopped"
                else:
                    state = "unknown"
                services.append(
                    ServiceInfo(
                        name=name,
                        state=state,
                        enabled=None,
                        unit_file=None,
                        description=None,
                        source_command="service --status-all",
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse service status line: {line}")
        return services

    @staticmethod
    def _deduplicate(services: list[ServiceInfo]) -> list[ServiceInfo]:
        """Deduplicate services by name, keeping the first occurrence."""
        seen: set[str] = set()
        deduped: list[ServiceInfo] = []
        for svc in services:
            if svc.name not in seen:
                seen.add(svc.name)
                deduped.append(svc)
        return deduped

    def _save_results(self, result: ServicesResult) -> Path:
        """Persist service results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "services": [asdict(svc) for svc in result.services],
            "active_count": result.active_count,
            "inactive_count": result.inactive_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("os/services.json", payload)

    def _print_summary(self, result: ServicesResult) -> None:
        """Print a concise summary of discovered services."""
        print("----------------------------------------")
        print("Services")
        print("----------------------------------------")
        print(f"Total Services : {len(result.services)}")
        print(f"Active         : {result.active_count}")
        print(f"Inactive       : {result.inactive_count}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        """Build a no-op CommandResult for the no-data case."""
        return CommandResult(
            command="services",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="services",
        )


__all__ = ["ServiceInfo", "ServicesModule", "ServicesResult"]
