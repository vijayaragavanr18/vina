"""Web alive-host discovery stage powered by httpx."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse, urlunparse

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...models.findings import Finding, make_finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class HttpxRecord:
    """Single httpx JSON record normalized into structured data."""

    host: str
    url: str
    status_code: int | None = None
    title: str | None = None
    ip: str | None = None
    technologies: list[str] = field(default_factory=list)
    content_length: int | None = None
    scheme: str | None = None
    port: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    line_number: int | None = None


@dataclass(slots=True)
class HttpxResult:
    """Structured result for the httpx stage."""

    target: TargetInput
    command_result: CommandResult
    records: list[HttpxRecord] = field(default_factory=list)
    alive_hosts: list[str] = field(default_factory=list)
    http_count: int = 0
    https_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class HttpxModule:
    """Probe discovered subdomains with httpx and persist alive hosts."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, subdomains: Sequence[str], target: str | TargetInput | None = None) -> HttpxResult:
        """Execute httpx against discovered subdomains.

        Parameters
        ----------
        subdomains:
            Discovered hostnames from the previous web recon stage.
        target:
            Optional target used only for result metadata.
        """

        target_input = self._coerce_target(target, subdomains)
        started_at = time.perf_counter()
        warnings: list[str] = []
        normalized_inputs = self._deduplicate_inputs(subdomains)

        executable = self.config.tool_bin("httpx", "httpx")
        if not normalized_inputs:
            warnings.append("No subdomains were provided")
            command_result = self._empty_command_result(executable)
            records: list[HttpxRecord] = []
        else:
            command_result = await self.context.runner.run(
                executable,
                ["-json", "-silent", "-sc", "-title", "-tech-detect", "-content-length", "-ip"],
                timeout_seconds=self.context.timeout_seconds,
                input_text="\n".join(normalized_inputs) + "\n",
            )
            records = self._parse_records(command_result.stdout, warnings)

        alive_hosts = self._deduplicate_records(records)
        http_count, https_count = self._scheme_counts(records)

        if command_result.missing_executable:
            warnings.append(f"Missing executable: {executable}")
        if command_result.timed_out:
            warnings.append(f"httpx timed out after {self.context.timeout_seconds} seconds")
        if command_result.returncode not in (0, None) and not command_result.timed_out and not command_result.missing_executable:
            warnings.append(f"httpx failed with exit code {command_result.returncode}")
        if normalized_inputs and not records and command_result.stdout.strip() and not command_result.timed_out:
            warnings.append("No valid JSON records were produced")
        if not alive_hosts:
            warnings.append("No alive hosts discovered")

        findings = [
            make_finding(
                title=f"Alive host: {url}",
                description=f"Discovered alive host via httpx (status: {next((r.status_code for r in records if r.url == url), '?')})",
                severity="info",
                category="alive_host",
                source_stage="httpx",
                target=target_input.root_domain or target_input.hostname or target_input.normalized,
                url=url,
            )
            for url in alive_hosts
        ]

        result = HttpxResult(
            target=target_input,
            command_result=command_result,
            records=records,
            alive_hosts=alive_hosts,
            http_count=http_count,
            https_count=https_count,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_records(self, output: str, warnings: list[str]) -> list[HttpxRecord]:
        records: list[HttpxRecord] = []
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

            record = self._normalize_record(payload, line_number)
            if record is None:
                warning = f"Skipping record on line {line_number}: missing host or URL"
                logger.warning(warning)
                warnings.append(warning)
                continue
            records.append(record)
        return records

    def _normalize_record(self, payload: Mapping[str, Any], line_number: int) -> HttpxRecord | None:
        host = self._normalize_text(payload.get("host"))
        url = self._normalize_text(payload.get("url"))
        scheme = self._normalize_text(payload.get("scheme"))
        port = self._parse_int(payload.get("port"))

        if not url and host:
            url = self._build_url(host, scheme, port)
        if not host and url:
            parsed = urlparse(url)
            host = self._normalize_text(parsed.hostname)
            if not scheme:
                scheme = parsed.scheme or None
            if port is None:
                port = parsed.port
        if not host or not url:
            return None

        if not scheme:
            scheme = urlparse(url).scheme or None
        if port is None:
            port = urlparse(url).port

        status_code = self._parse_int(payload.get("status_code"))
        title = self._normalize_text(payload.get("title"))
        ip = self._normalize_text(payload.get("ip")) or self._normalize_text(payload.get("host_ip"))
        content_length = self._parse_int(payload.get("content_length"))
        technologies = self._parse_technologies(payload)

        return HttpxRecord(
            host=host,
            url=url,
            status_code=status_code,
            title=title,
            ip=ip,
            technologies=technologies,
            content_length=content_length,
            scheme=scheme,
            port=port,
            raw=dict(payload),
            line_number=line_number,
        )

    @staticmethod
    def _parse_technologies(payload: Mapping[str, Any]) -> list[str]:
        value = payload.get("technologies")
        if value is None:
            value = payload.get("tech")
        technologies: list[str] = []
        if isinstance(value, str):
            text = value.strip()
            if text:
                technologies.append(text)
        elif isinstance(value, Mapping):
            for item in value.values():
                text = HttpxModule._normalize_text(item)
                if text:
                    technologies.append(text)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for item in value:
                if isinstance(item, str):
                    text = item.strip()
                elif isinstance(item, Mapping):
                    text = (
                        HttpxModule._normalize_text(item.get("name"))
                        or HttpxModule._normalize_text(item.get("technology"))
                        or HttpxModule._normalize_text(item.get("value"))
                        or HttpxModule._normalize_text(item.get("product"))
                    )
                else:
                    text = HttpxModule._normalize_text(item)
                if text:
                    technologies.append(text)
        return list(dict.fromkeys(technologies))

    @staticmethod
    def _deduplicate_inputs(subdomains: Sequence[str]) -> list[str]:
        seen: set[str] = set()
        normalized_inputs: list[str] = []
        for item in subdomains:
            host = HttpxModule._normalize_text(item)
            if not host:
                continue
            if host not in seen:
                seen.add(host)
                normalized_inputs.append(host)
        return normalized_inputs

    @staticmethod
    def _deduplicate_records(records: list[HttpxRecord]) -> list[str]:
        seen: set[tuple[str, str]] = set()
        alive_hosts: list[str] = []
        for record in records:
            key = (record.scheme or "", record.url)
            if key not in seen:
                seen.add(key)
                alive_hosts.append(record.url)
        return alive_hosts

    @staticmethod
    def _scheme_counts(records: list[HttpxRecord]) -> tuple[int, int]:
        http_count = 0
        https_count = 0
        seen: set[tuple[str, str]] = set()
        for record in records:
            key = (record.scheme or "", record.url)
            if key in seen:
                continue
            seen.add(key)
            scheme = (record.scheme or "").lower()
            if scheme == "http":
                http_count += 1
            elif scheme == "https":
                https_count += 1
        return http_count, https_count

    def _save_results(self, result: HttpxResult) -> Path:
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "records": [asdict(record) for record in result.records],
            "alive_hosts": result.alive_hosts,
            "http_count": result.http_count,
            "https_count": result.https_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("web/alive_hosts.json", payload)

    def _print_summary(self, result: HttpxResult) -> None:
        output_file = result.output_file or Path("output/web/alive_hosts.json")
        print("----------------------------------")
        print(f"Alive hosts: {len(result.alive_hosts)}")
        print(f"HTTP: {result.http_count}")
        print(f"HTTPS: {result.https_count}")
        print(f"Execution time: {result.execution_time_seconds:.2f}s")
        print(f"Output file: {output_file}")
        print("----------------------------------")

    @staticmethod
    def _empty_command_result(command: str) -> CommandResult:
        return CommandResult(
            command=command,
            args=("-json", "-silent", "-sc", "-title", "-tech-detect", "-content-length", "-ip"),
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

    @staticmethod
    def _build_url(host: str, scheme: str | None, port: int | None) -> str:
        parsed = urlparse(host if "://" in host else f"//{host}")
        hostname = parsed.hostname or host
        final_scheme = scheme or "http"
        netloc = hostname
        if port is not None:
            netloc = f"{hostname}:{port}"
        return urlunparse((final_scheme, netloc, parsed.path or "", parsed.params or "", parsed.query or "", parsed.fragment or ""))

    @staticmethod
    def _coerce_target(target: str | TargetInput | None, subdomains: Sequence[str]) -> TargetInput:
        if isinstance(target, TargetInput):
            return target
        if isinstance(target, str):
            return TargetInput.from_raw(target)
        if subdomains:
            first = HttpxModule._normalize_text(subdomains[0]) or "unknown"
            return TargetInput.from_raw(first)
        return TargetInput.from_raw("unknown")


__all__ = ["HttpxModule", "HttpxRecord", "HttpxResult"]
