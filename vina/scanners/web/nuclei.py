"""Web vulnerability-scan stage powered by Nuclei."""

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
from .url_aggregator import AggregatedUrl

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NucleiFinding:
    """A single finding discovered by Nuclei."""

    template_id: str
    template_name: str | None = None
    severity: str | None = None
    matched_url: str | None = None
    host: str | None = None
    protocol: str | None = None
    tags: list[str] = field(default_factory=list)
    matcher_name: str | None = None
    extracted_results: list[str] = field(default_factory=list)
    timestamp: str | None = None


@dataclass(slots=True)
class NucleiResult:
    """Structured result for the Nuclei vulnerability scan stage."""

    target: TargetInput
    command_result: CommandResult
    findings: list[NucleiFinding] = field(default_factory=list)
    url_count: int = 0
    template_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    unified_findings: list[Finding] = field(default_factory=list)


class NucleiModule:
    """Scan aggregated URLs with Nuclei and return findings."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, urls: list[AggregatedUrl], target: TargetInput) -> NucleiResult:
        """Execute Nuclei against aggregated URLs and return findings.

        Parameters
        ----------
        urls:
            Aggregated URLs from the UrlAggregator stage.
        target:
            Target metadata attached to the result.
        """
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        executable = self.config.tool_bin("nuclei", "nuclei")

        url_strings = [u.url for u in urls if u.url]
        url_count = len(url_strings)

        if not url_strings:
            warnings.append("No URLs were provided")
            command_result = self._empty_command_result(executable)
            findings: list[NucleiFinding] = []
        else:
            command_result = await self.context.runner.run(
                executable,
                ["-json", "-silent"],
                timeout_seconds=self.context.timeout_seconds,
                input_text="\n".join(url_strings) + "\n",
            )
            findings = self._parse_output(command_result.stdout, warnings)

        if command_result.missing_executable:
            warnings.append(f"Missing executable: {executable}")
        if command_result.timed_out:
            warnings.append(f"Nuclei timed out after {self.context.timeout_seconds} seconds")
        if (
            command_result.returncode not in (0, None)
            and not command_result.timed_out
            and not command_result.missing_executable
        ):
            warnings.append(f"Nuclei failed with exit code {command_result.returncode}")
        if url_strings and not findings and command_result.stdout.strip() and not command_result.timed_out:
            warnings.append("No valid JSON records were produced")
        if not findings:
            warnings.append("No findings discovered")

        findings = self._deduplicate(findings)
        template_count = self._count_templates(findings)

        unified_findings: list[Finding] = []
        for nf in findings:
            description = nf.template_name or nf.template_id
            unified_findings.append(
                make_finding(
                    title=f"Nuclei: {nf.template_id}",
                    description=description,
                    severity=nf.severity or "info",
                    category="vulnerability",
                    source_stage="nuclei",
                    target=target_input.root_domain or target_input.hostname or target_input.normalized,
                    evidence=nf.matched_url or "",
                    host=nf.host or "",
                    url=nf.matched_url or "",
                    tags=nf.tags,
                )
            )

        result = NucleiResult(
            target=target_input,
            command_result=command_result,
            findings=findings,
            url_count=url_count,
            template_count=template_count,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            unified_findings=unified_findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_output(self, output: str, warnings: list[str]) -> list[NucleiFinding]:
        """Parse Nuclei JSON lines into typed records."""
        findings: list[NucleiFinding] = []

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

            finding = self._parse_finding(payload, line_number, warnings)
            if finding is not None:
                findings.append(finding)

        return findings

    def _parse_finding(self, payload: Mapping[str, Any], line_number: int, warnings: list[str]) -> NucleiFinding | None:
        """Parse a single Nuclei JSON line into a NucleiFinding."""
        template_id = payload.get("template-id")
        if not template_id or not isinstance(template_id, str):
            msg = f"Skipping record on line {line_number}: missing template-id"
            logger.warning(msg)
            warnings.append(msg)
            return None

        info = payload.get("info")
        info_dict: dict[str, Any] = {}
        if isinstance(info, Mapping):
            info_dict = dict(info)

        template_name = self._normalize_text(info_dict.get("name")) or template_id

        severity = (
            self._normalize_text(info_dict.get("severity")) or self._normalize_text(payload.get("severity")) or "info"
        )

        matched_url = self._normalize_text(payload.get("matched-at") or payload.get("url") or payload.get("matched"))
        host = self._normalize_text(payload.get("host"))
        protocol = self._normalize_text(payload.get("type"))
        matcher_name = self._normalize_text(payload.get("matcher-name"))
        timestamp = self._normalize_text(payload.get("timestamp"))

        tags = self._parse_tags(info_dict)

        extracted: list[str] = []
        extracted_raw = payload.get("extracted-results")
        if isinstance(extracted_raw, list):
            for item in extracted_raw:
                if isinstance(item, str) and item.strip():
                    extracted.append(item.strip())
        elif isinstance(extracted_raw, str) and extracted_raw.strip():
            extracted.append(extracted_raw.strip())

        return NucleiFinding(
            template_id=template_id,
            template_name=template_name,
            severity=severity,
            matched_url=matched_url,
            host=host,
            protocol=protocol,
            tags=tags,
            matcher_name=matcher_name,
            extracted_results=extracted,
            timestamp=timestamp,
        )

    @staticmethod
    def _parse_tags(info: dict[str, Any]) -> list[str]:
        """Extract tags from the info dict, handling list or string."""
        tags_raw = info.get("tags")
        if isinstance(tags_raw, list):
            return [str(t).strip() for t in tags_raw if isinstance(t, (str, int, float))]
        if isinstance(tags_raw, str):
            return [t.strip() for t in tags_raw.split(",") if t.strip()]
        return []

    @staticmethod
    def _deduplicate(findings: list[NucleiFinding]) -> list[NucleiFinding]:
        """Deduplicate findings by (template_id, matched_url)."""
        seen: set[tuple[str, str]] = set()
        deduped: list[NucleiFinding] = []
        for f in findings:
            key = (f.template_id.lower(), (f.matched_url or "").lower())
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    @staticmethod
    def _count_templates(findings: list[NucleiFinding]) -> int:
        """Count unique template IDs across findings."""
        seen: set[str] = set()
        for f in findings:
            seen.add(f.template_id.lower())
        return len(seen)

    def _save_results(self, result: NucleiResult) -> Path:
        """Persist Nuclei results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "findings": [asdict(f) for f in result.findings],
            "url_count": result.url_count,
            "template_count": result.template_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("web/nuclei_findings.json", payload)

    def _print_summary(self, result: NucleiResult) -> None:
        """Print a concise summary of Nuclei results."""
        print("----------------------------------------")
        print("Nuclei Scan")
        print("----------------------------------------")
        print(f"URLs Scanned:      {result.url_count}")
        print(f"Templates Matched: {result.template_count}")
        print(f"Unique Findings:   {len(result.findings)}")
        print(f"Warnings:          {len(result.warnings)}")

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


__all__ = ["NucleiFinding", "NucleiModule", "NucleiResult"]
