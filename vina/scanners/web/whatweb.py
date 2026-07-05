"""Web technology-detection stage powered by WhatWeb."""

from __future__ import annotations

import contextlib
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
from ...models.findings import Finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class WhatWebTechnology:
    """A single technology detected by WhatWeb."""

    name: str
    version: str | None = None
    certainty: int | None = None
    categories: list[str] = field(default_factory=list)


@dataclass(slots=True)
class WhatWebHost:
    """A single host analysed by WhatWeb with its technologies."""

    url: str
    host: str | None = None
    ip: str | None = None
    http_status: int | None = None
    server: str | None = None
    frameworks: list[str] = field(default_factory=list)
    cms: list[str] = field(default_factory=list)
    language: list[str] = field(default_factory=list)
    js_libraries: list[str] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    technologies: list[WhatWebTechnology] = field(default_factory=list)
    plugins: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(slots=True)
class WhatWebResult:
    """Structured result for the WhatWeb technology detection stage."""

    target: TargetInput
    command_result: CommandResult
    hosts: list[WhatWebHost] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    host_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class WhatWebModule:
    """Analyse alive hosts with WhatWeb and detect technologies."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, alive_hosts: list[str], target: TargetInput) -> WhatWebResult:
        """Execute WhatWeb against alive hosts and return detected technologies.

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
        executable = self.config.tool_bin("whatweb", "WhatWeb")

        if not alive_hosts:
            warnings.append("No alive hosts were provided")
            command_result = self._empty_command_result(executable)
            hosts: list[WhatWebHost] = []
            all_technologies: list[str] = []
            host_count = 0
        else:
            command_result = await self.context.runner.run(
                executable, ["--log-json=-", "--no-errors", *alive_hosts], timeout_seconds=self.context.timeout_seconds
            )
            hosts, all_technologies = self._parse_output(command_result.stdout, warnings)
            host_count = len(hosts)

        if command_result.missing_executable:
            warnings.append(f"Missing executable: {executable}")
        if command_result.timed_out:
            warnings.append(f"WhatWeb timed out after {self.context.timeout_seconds} seconds")
        if (
            command_result.returncode not in (0, None)
            and not command_result.timed_out
            and not command_result.missing_executable
        ):
            warnings.append(f"WhatWeb failed with exit code {command_result.returncode}")
        if alive_hosts and not hosts and command_result.stdout.strip() and not command_result.timed_out:
            warnings.append("No valid JSON records were produced")
        if not hosts:
            warnings.append("No hosts were successfully analysed")

        all_technologies = self._deduplicate_technologies(all_technologies)

        result = WhatWebResult(
            target=target_input,
            command_result=command_result,
            hosts=hosts,
            technologies=all_technologies,
            host_count=host_count,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_output(self, output: str, warnings: list[str]) -> tuple[list[WhatWebHost], list[str]]:
        """Parse WhatWeb JSON lines into typed records.

        Returns (hosts, flat_technology_names).
        """
        hosts: list[WhatWebHost] = []
        all_technologies: list[str] = []

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

            host = self._parse_host(payload, line_number, warnings)
            if host is not None:
                hosts.append(host)
                all_technologies.extend(t.name for t in host.technologies)

        return hosts, all_technologies

    def _parse_host(self, payload: Mapping[str, Any], line_number: int, warnings: list[str]) -> WhatWebHost | None:
        """Parse a single WhatWeb JSON line into a WhatWebHost."""
        target_url = payload.get("target") or payload.get("url")
        if not target_url or not isinstance(target_url, str):
            msg = f"Skipping record on line {line_number}: missing target or url"
            logger.warning(msg)
            warnings.append(msg)
            return None

        plugins_raw = payload.get("plugins")
        plugins: dict[str, dict[str, Any]] = {}
        if isinstance(plugins_raw, Mapping):
            for plugin_name, details in plugins_raw.items():
                if isinstance(details, dict):
                    plugins[plugin_name] = dict(details)

        hostname = self._extract_hostname(target_url)
        http_status = self._parse_int(payload.get("http_status"))

        categorized = self._categorize_plugins(plugins)
        technologies = categorized["technologies"]
        return WhatWebHost(
            url=target_url,
            host=hostname,
            ip=categorized.get("ip"),
            http_status=http_status,
            server=categorized.get("server"),
            frameworks=categorized.get("frameworks", []),
            cms=categorized.get("cms", []),
            language=categorized.get("language", []),
            js_libraries=categorized.get("js_libraries", []),
            cookies=categorized.get("cookies", []),
            headers={},
            technologies=technologies,
            plugins=plugins,
        )

    @staticmethod
    def _categorize_plugins(plugins: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Categorize WhatWeb plugins into structured groups."""
        technologies: list[WhatWebTechnology] = []
        frameworks: list[str] = []
        cms_list: list[str] = []
        language_list: list[str] = []
        js_list: list[str] = []
        cookies_list: list[str] = []
        server: str | None = None
        ip: str | None = None

        for name, details in plugins.items():
            if not isinstance(details, dict):
                continue

            certainty = None
            certainty_raw = details.get("certainty")
            if isinstance(certainty_raw, (int, str)):
                with contextlib.suppress(ValueError, TypeError):
                    certainty = int(certainty_raw)

            version = WhatWebModule._normalize_text(details.get("version"))
            categories_raw = details.get("categories", [])
            categories: list[str] = []
            if isinstance(categories_raw, list):
                for c in categories_raw:
                    if isinstance(c, str):
                        categories.append(c)

            technologies.append(
                WhatWebTechnology(name=name, version=version, certainty=certainty, categories=categories)
            )

            cat_lower = [c.lower() for c in categories]
            name_lower = name.lower()

            if "server" in name_lower and not server:
                server = version or name
            if name_lower == "ip":
                raw = WhatWebModule._normalize_text(details.get("string"))
                if raw:
                    ip = raw

            if "cms" in cat_lower:
                cms_list.append(name)
            if any("language" in c or "programming" in c for c in cat_lower):
                language_list.append(name)
            if any("javascript" in c or "js" in c or "framework" in c for c in cat_lower):
                js_list.append(name)
            if "framework" in cat_lower:
                frameworks.append(name)
            if "framework" in name_lower and name not in frameworks:
                frameworks.append(name)
            if "cookie" in name_lower:
                cookie_val = WhatWebModule._normalize_text(details.get("string")) or version
                if cookie_val:
                    cookies_list.append(cookie_val)

        return {
            "technologies": technologies,
            "frameworks": list(dict.fromkeys(frameworks)),
            "cms": list(dict.fromkeys(cms_list)),
            "language": list(dict.fromkeys(language_list)),
            "js_libraries": list(dict.fromkeys(js_list)),
            "cookies": list(dict.fromkeys(cookies_list)),
            "server": server,
            "ip": ip,
        }

    @staticmethod
    def _deduplicate_technologies(names: list[str]) -> list[str]:
        """Deduplicate technology names preserving order."""
        seen: set[str] = set()
        deduped: list[str] = []
        for name in names:
            key = name.lower()
            if key not in seen:
                seen.add(key)
                deduped.append(name)
        return sorted(deduped)

    @staticmethod
    def _extract_hostname(url: str) -> str | None:
        """Extract the hostname from a URL string."""
        candidate = url if "://" in url else f"//{url}"
        parsed = urlparse(candidate)
        hostname = parsed.hostname or url.strip().lower().rstrip(".")
        return hostname or None

    def _save_results(self, result: WhatWebResult) -> Path:
        """Persist WhatWeb results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "hosts": [asdict(host) for host in result.hosts],
            "technologies": result.technologies,
            "host_count": result.host_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("web/technologies.json", payload)

    def _print_summary(self, result: WhatWebResult) -> None:
        """Print a concise summary of WhatWeb results."""
        print("----------------------------------------")
        print("WhatWeb")
        print("----------------------------------------")
        print(f"Hosts Analysed : {result.host_count}")
        print(f"Technologies   : {len(result.technologies)}")

    @staticmethod
    def _empty_command_result(command: str) -> CommandResult:
        """Build a no-op CommandResult for the empty-input case."""
        return CommandResult(
            command=command,
            args=("--log-json=-", "--no-errors"),
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


__all__ = ["WhatWebHost", "WhatWebModule", "WhatWebResult", "WhatWebTechnology"]
