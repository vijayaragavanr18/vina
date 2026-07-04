"""Web crawling stage powered by Katana."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class KatanaEndpoint:
    """A single endpoint discovered by Katana."""

    url: str
    host: str | None = None
    path: str | None = None
    method: str | None = None
    source: str | None = None
    depth: int | None = None
    content_type: str | None = None
    status_code: int | None = None
    forms: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    line_number: int | None = None


@dataclass(slots=True)
class KatanaResult:
    """Structured result for the Katana crawling stage."""

    target: TargetInput
    command_result: CommandResult
    endpoints: list[KatanaEndpoint] = field(default_factory=list)
    host_count: int = 0
    js_count: int = 0
    form_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class KatanaModule:
    """Crawl alive hosts with Katana and discover endpoints."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(
        self,
        alive_hosts: list[str],
        target: TargetInput,
    ) -> KatanaResult:
        """Execute Katana against alive hosts and return discovered endpoints.

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
        executable = self.config.tool_bin("katana", "katana")

        if not alive_hosts:
            warnings.append("No alive hosts were provided")
            command_result = self._empty_command_result(executable)
            endpoints: list[KatanaEndpoint] = []
            host_count = 0
            js_count = 0
            form_count = 0
        else:
            command_result = await self.context.runner.run(
                executable,
                ["-silent", "-json"],
                timeout_seconds=self.context.timeout_seconds,
                input_text="\n".join(alive_hosts) + "\n",
            )
            endpoints = self._parse_output(command_result.stdout, warnings)
            host_count = self._count_hosts(endpoints)
            js_count = self._count_js_files(endpoints)
            form_count = self._count_forms(endpoints)

        if command_result.missing_executable:
            warnings.append(f"Missing executable: {executable}")
        if command_result.timed_out:
            warnings.append(
                f"Katana timed out after {self.context.timeout_seconds} seconds"
            )
        if (
            command_result.returncode not in (0, None)
            and not command_result.timed_out
            and not command_result.missing_executable
        ):
            warnings.append(
                f"Katana failed with exit code {command_result.returncode}"
            )
        if (
            alive_hosts
            and not endpoints
            and command_result.stdout.strip()
            and not command_result.timed_out
        ):
            warnings.append("No valid JSON records were produced")
        if not endpoints:
            warnings.append("No endpoints discovered")

        endpoints = self._deduplicate(endpoints)

        result = KatanaResult(
            target=target_input,
            command_result=command_result,
            endpoints=endpoints,
            host_count=host_count,
            js_count=js_count,
            form_count=form_count,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_output(
        self,
        output: str,
        warnings: list[str],
    ) -> list[KatanaEndpoint]:
        """Parse Katana JSON lines into typed records."""
        endpoints: list[KatanaEndpoint] = []

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

            endpoint = self._parse_endpoint(payload, line_number, warnings)
            if endpoint is not None:
                endpoints.append(endpoint)

        return endpoints

    def _parse_endpoint(
        self,
        payload: Mapping[str, Any],
        line_number: int,
        warnings: list[str],
    ) -> KatanaEndpoint | None:
        """Parse a single Katana JSON line into a KatanaEndpoint."""
        url = payload.get("url") or payload.get("request")
        if not url or not isinstance(url, str):
            msg = (
                f"Skipping record on line {line_number}: "
                f"missing url"
            )
            logger.warning(msg)
            warnings.append(msg)
            return None

        host = self._normalize_text(payload.get("host"))
        if not host:
            host = self._extract_hostname(url)

        raw_path = payload.get("path") or urlparse(url).path or None
        path = self._normalize_text(raw_path) if raw_path else None

        method = self._normalize_text(
            payload.get("method")
        )
        source = self._normalize_text(
            payload.get("source")
        )
        depth = self._parse_int(payload.get("depth"))
        content_type = self._normalize_text(
            payload.get(
                "content_type",
                payload.get("content-type"),
            )
        )
        status_code = self._parse_int(
            payload.get(
                "status_code",
                payload.get("status-code"),
            )
        )

        inputs_raw = payload.get("inputs") or payload.get("params") or []
        parameters = self._extract_strings(inputs_raw)

        forms: list[str] = []
        js_files: list[str] = []
        api_endpoints: list[str] = []
        assets: list[str] = []
        links_list: list[str] = []

        endpoint_type = self._normalize_text(payload.get("type"))
        if endpoint_type == "javascript":
            js_files.append(url)
        elif content_type and "javascript" in content_type.lower():
            js_files.append(url)
        elif path and path.lower().endswith(".js"):
            js_files.append(url)

        if path and ("/api/" in path.lower() or "/v1/" in path.lower() or "/v2/" in path.lower()):
            api_endpoints.append(url)

        if parameters:
            forms.append(url)

        ext = ""
        if path:
            dot = path.rfind(".")
            if dot != -1 and "/" not in path[dot:]:
                ext = path[dot:].lower()
        asset_extensions = {".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webp", ".pdf"}
        if ext in asset_extensions:
            assets.append(url)

        if source and source != url:
            links_list.append(source)

        return KatanaEndpoint(
            url=url,
            host=host,
            path=path,
            method=method,
            source=source,
            depth=depth,
            content_type=content_type,
            status_code=status_code,
            forms=forms,
            parameters=parameters,
            js_files=js_files,
            api_endpoints=api_endpoints,
            assets=assets,
            links=links_list,
            raw=dict(payload),
            line_number=line_number,
        )

    @staticmethod
    def _extract_strings(raw: Any) -> list[str]:
        """Extract string values from a mixed-type list."""
        if not isinstance(raw, list):
            return []
        result: list[str] = []
        for item in raw:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, Mapping):
                name = item.get("name")
                if isinstance(name, str) and name.strip():
                    result.append(name.strip())
            elif isinstance(item, (int, float)):
                result.append(str(item))
        return result

    @staticmethod
    def _count_hosts(endpoints: list[KatanaEndpoint]) -> int:
        """Count unique hosts across endpoints."""
        seen: set[str] = set()
        for ep in endpoints:
            if ep.host:
                seen.add(ep.host.lower())
        return len(seen)

    @staticmethod
    def _count_js_files(endpoints: list[KatanaEndpoint]) -> int:
        """Count unique JavaScript file URLs across endpoints."""
        seen: set[str] = set()
        for ep in endpoints:
            for js in ep.js_files:
                seen.add(js)
        return len(seen)

    @staticmethod
    def _count_forms(endpoints: list[KatanaEndpoint]) -> int:
        """Count endpoints containing form data."""
        return sum(1 for ep in endpoints if ep.forms)

    @staticmethod
    def _deduplicate(
        endpoints: list[KatanaEndpoint],
    ) -> list[KatanaEndpoint]:
        """Deduplicate endpoints by URL."""
        seen: set[str] = set()
        deduped: list[KatanaEndpoint] = []
        for ep in endpoints:
            key = ep.url.lower()
            if key not in seen:
                seen.add(key)
                deduped.append(ep)
        return deduped

    @staticmethod
    def _extract_hostname(url: str) -> str | None:
        """Extract the hostname from a URL string."""
        candidate = url if "://" in url else f"//{url}"
        parsed = urlparse(candidate)
        hostname = parsed.hostname or url.strip().lower().rstrip(".")
        return hostname or None

    def _save_results(self, result: KatanaResult) -> Path:
        """Persist Katana results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "endpoints": [asdict(ep) for ep in result.endpoints],
            "host_count": result.host_count,
            "js_count": result.js_count,
            "form_count": result.form_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("web/endpoints.json", payload)

    def _print_summary(self, result: KatanaResult) -> None:
        """Print a concise summary of Katana results."""
        print("----------------------------------------")
        print("Katana")
        print("----------------------------------------")
        print(f"Hosts Crawled : {result.host_count}")
        print(f"Endpoints     : {len(result.endpoints)}")
        print(f"JS Files      : {result.js_count}")
        print(f"Forms         : {result.form_count}")

    @staticmethod
    def _empty_command_result(command: str) -> CommandResult:
        """Build a no-op CommandResult for the empty-input case."""
        return CommandResult(
            command=command,
            args=("-silent", "-json"),
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


__all__ = [
    "KatanaModule",
    "KatanaEndpoint",
    "KatanaResult",
]
