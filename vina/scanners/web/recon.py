"""Web recon stage powered by Subfinder."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...models.findings import Finding, make_finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SubfinderRecord:
    """Single Subfinder JSON record."""

    host: str
    source: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    line_number: int | None = None


@dataclass(slots=True)
class WebReconResult:
    """Structured result for the web recon stage."""

    target: TargetInput
    command_result: CommandResult
    records: list[SubfinderRecord] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class ReconModule:
    """Run Subfinder against a target and persist discovered subdomains."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: str | TargetInput) -> WebReconResult:
        """Execute Subfinder and return deduplicated subdomains."""

        target_input = self._coerce_target(target)
        domain = target_input.root_domain or target_input.hostname or target_input.normalized
        started_at = time.perf_counter()
        warnings: list[str] = []

        executable = self.config.tool_bin("subfinder", "subfinder")
        command_result = await self.context.runner.run(
            executable,
            ["-d", domain, "-silent", "-json"],
            timeout_seconds=self.context.timeout_seconds,
        )

        records = self._parse_records(command_result.stdout, warnings)
        subdomains = self._deduplicate(records)

        if command_result.missing_executable:
            warnings.append(f"Missing executable: {executable}")
        if command_result.timed_out:
            warnings.append(f"Subfinder timed out after {self.context.timeout_seconds} seconds")
        if (
            command_result.returncode not in (0, None)
            and not command_result.timed_out
            and not command_result.missing_executable
        ):
            warnings.append(f"Subfinder failed with exit code {command_result.returncode}")
        if not records and command_result.stdout.strip() and not command_result.timed_out:
            warnings.append("No valid JSON records were produced")
        if not subdomains:
            warnings.append("No subdomains discovered")

        findings = [
            make_finding(
                title=f"Subdomain: {sub}",
                description="Discovered subdomain via subfinder",
                severity="info",
                category="subdomain",
                source_stage="subfinder",
                target=target_input.root_domain or target_input.hostname or target_input.normalized,
                host=sub,
                url=f"https://{sub}" if sub else "",
            )
            for sub in subdomains
        ]

        result = WebReconResult(
            target=target_input,
            command_result=command_result,
            records=records,
            subdomains=subdomains,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_records(self, output: str, warnings: list[str]) -> list[SubfinderRecord]:
        records: list[SubfinderRecord] = []
        for line_number, raw_line in enumerate(output.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                warning = f"Invalid JSON on line {line_number}: {exc.msg}"
                logger.warning(warning)
                warnings.append(warning)
                continue
            if not isinstance(payload, Mapping):
                warning = f"Invalid JSON on line {line_number}: expected object"
                logger.warning(warning)
                warnings.append(warning)
                continue

            host = self._normalize_host(payload.get("host"))
            if not host:
                warning = f"Skipping record on line {line_number}: missing host"
                logger.warning(warning)
                warnings.append(warning)
                continue

            source_value = payload.get("source")
            source = str(source_value).strip() if isinstance(source_value, str) and source_value.strip() else None
            records.append(
                SubfinderRecord(
                    host=host,
                    source=source,
                    raw=dict(payload),
                    line_number=line_number,
                )
            )
        return records

    @staticmethod
    def _deduplicate(records: list[SubfinderRecord]) -> list[str]:
        seen: set[str] = set()
        subdomains: list[str] = []
        for record in records:
            if record.host not in seen:
                seen.add(record.host)
                subdomains.append(record.host)
        return subdomains

    def _save_results(self, result: WebReconResult) -> Path:
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "records": [asdict(record) for record in result.records],
            "subdomains": result.subdomains,
            "warnings": result.warnings,
        }
        return self.context.store.save("web/subdomains.json", payload)

    def _print_summary(self, result: WebReconResult) -> None:
        output_file = result.output_file or Path("output/web/subdomains.json")
        print("----------------------------------")
        print(f"Target: {result.target.normalized}")
        print(f"Subdomains found: {len(result.subdomains)}")
        print(f"Execution time: {result.execution_time_seconds:.2f}s")
        print(f"Output file: {output_file}")
        print("----------------------------------")

    @staticmethod
    def _normalize_host(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        host = value.strip().lower().rstrip(".")
        if host.startswith("*."):
            host = host[2:]
        return host or None

    @staticmethod
    def _coerce_target(target: str | TargetInput) -> TargetInput:
        if isinstance(target, TargetInput):
            return target
        return TargetInput.from_raw(target)


__all__ = ["ReconModule", "SubfinderRecord", "WebReconResult"]
