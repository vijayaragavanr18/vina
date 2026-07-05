"""Web port-scan stage powered by Naabu."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...models.findings import Finding, make_finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NaabuRecord:
    """Single Naabu JSON record."""

    host: str
    port: int
    protocol: str = "tcp"
    raw: dict[str, Any] = field(default_factory=dict)
    line_number: int | None = None


@dataclass(slots=True)
class NaabuResult:
    """Structured result for the Naabu port scan stage."""

    target: TargetInput
    command_result: CommandResult
    records: list[NaabuRecord] = field(default_factory=list)
    open_ports: list[str] = field(default_factory=list)
    input_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class NaabuModule:
    """Scan alive hosts with Naabu and persist discovered open ports."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(
        self,
        alive_hosts: list[str],
        target: TargetInput,
    ) -> NaabuResult:
        """Execute Naabu against alive hosts and return open ports.

        Parameters
        ----------
        alive_hosts:
            URLs from the previous httpx stage (e.g. ``https://example.com``).
        target:
            Target metadata attached to the result.
        """
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        executable = self.config.tool_bin("naabu", "naabu")

        hostnames = self._extract_hostnames(alive_hosts)
        input_count = len(hostnames)

        if not hostnames:
            warnings.append("No hostnames were provided")
            command_result = self._empty_command_result(executable)
            records: list[NaabuRecord] = []
        else:
            command_result = await self.context.runner.run(
                executable,
                ["-json", "-silent"],
                timeout_seconds=self.context.timeout_seconds,
                input_text="\n".join(hostnames) + "\n",
            )
            records = self._parse_records(command_result.stdout, warnings)

        open_ports = self._deduplicate(records)

        if command_result.missing_executable:
            warnings.append(f"Missing executable: {executable}")
        if command_result.timed_out:
            warnings.append(f"Naabu timed out after {self.context.timeout_seconds} seconds")
        if (
            command_result.returncode not in (0, None)
            and not command_result.timed_out
            and not command_result.missing_executable
        ):
            warnings.append(f"Naabu failed with exit code {command_result.returncode}")
        if hostnames and not records and command_result.stdout.strip() and not command_result.timed_out:
            warnings.append("No valid JSON records were produced")
        if not open_ports:
            warnings.append("No open ports discovered")

        findings = []
        for port_str in open_ports:
            host = port_str.split(":")[0] if ":" in port_str else ""
            port_part = port_str.split(":")[-1] if ":" in port_str else ""
            port_num = port_part.split("/")[0] if "/" in port_part else port_part
            protocol = port_part.split("/")[-1] if "/" in port_part else "tcp"
            try:
                port_int = int(port_num) if port_num else None
            except ValueError:
                port_int = None
            findings.append(
                make_finding(
                    title=f"Open port: {port_str}",
                    description="Open port discovered via naabu",
                    severity="medium",
                    category="open_port",
                    source_stage="naabu",
                    target=target_input.root_domain or target_input.hostname or target_input.normalized,
                    host=host,
                    port=port_int,
                    protocol=protocol,
                )
            )

        result = NaabuResult(
            target=target_input,
            command_result=command_result,
            records=records,
            open_ports=open_ports,
            input_count=input_count,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_records(self, output: str, warnings: list[str]) -> list[NaabuRecord]:
        """Parse JSON lines output from Naabu into typed records."""
        records: list[NaabuRecord] = []
        for line_number, raw_line in enumerate(output.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                msg = f"Invalid JSON on line {line_number}: {exc.msg}"
                logger.warning(msg)
                warnings.append(msg)
                continue
            if not isinstance(payload, Mapping):
                msg = f"Invalid JSON on line {line_number}: expected object"
                logger.warning(msg)
                warnings.append(msg)
                continue

            host = self._normalize_text(payload.get("host"))
            port = self._parse_int(payload.get("port"))
            if not host or port is None:
                msg = f"Skipping record on line {line_number}: missing host or port"
                logger.warning(msg)
                warnings.append(msg)
                continue

            protocol = self._normalize_text(payload.get("protocol")) or "tcp"
            records.append(
                NaabuRecord(
                    host=host,
                    port=port,
                    protocol=protocol,
                    raw=dict(payload),
                    line_number=line_number,
                )
            )
        return records

    @staticmethod
    def _deduplicate(records: list[NaabuRecord]) -> list[str]:
        """Deduplicate records by (host, port, protocol)."""
        seen: set[tuple[str, int, str]] = set()
        open_ports: list[str] = []
        for record in records:
            key = (record.host, record.port, record.protocol)
            if key not in seen:
                seen.add(key)
                open_ports.append(f"{record.host}:{record.port}/{record.protocol}")
        return open_ports

    def _save_results(self, result: NaabuResult) -> Path:
        """Persist Naabu results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "records": [asdict(record) for record in result.records],
            "open_ports": result.open_ports,
            "input_count": result.input_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("web/open_ports.json", payload)

    def _print_summary(self, result: NaabuResult) -> None:
        """Print a concise summary of Naabu results."""
        print("----------------------------------------")
        print("Naabu")
        print("----------------------------------------")
        print(f"Alive Hosts : {result.input_count}")
        print(f"Open Ports  : {len(result.open_ports)}")

    @staticmethod
    def _extract_hostnames(alive_hosts: list[str]) -> list[str]:
        """Extract unique hostnames from a list of URLs."""
        hostnames: list[str] = []
        seen: set[str] = set()
        for entry in alive_hosts:
            candidate = entry if "://" in entry else f"//{entry}"
            parsed = urlparse(candidate)
            hostname = parsed.hostname or entry.strip().lower().rstrip(".")
            if hostname and hostname not in seen:
                seen.add(hostname)
                hostnames.append(hostname)
        return hostnames

    @staticmethod
    def _empty_command_result(command: str) -> CommandResult:
        """Build a no-op CommandResult for the empty-input case."""
        return CommandResult(
            command=command,
            args=("-json", "-silent"),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command=command,
        )

    @staticmethod
    def _normalize_text(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        text = value.strip()
        return text or None

    @staticmethod
    def _parse_int(value: Any) -> int | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            try:
                return int(float(text))
            except ValueError:
                return None
        return None


__all__ = ["NaabuModule", "NaabuRecord", "NaabuResult"]
