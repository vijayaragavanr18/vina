"""Web historical-URL collection stage powered by GAU."""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...models.findings import Finding, make_finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class GauUrl:
    """A single historical URL discovered by GAU."""

    url: str
    host: str | None = None
    path: str | None = None
    query_string: str | None = None
    file_extension: str | None = None
    parameter_names: list[str] = field(default_factory=list)
    source: str | None = None


@dataclass(slots=True)
class GauResult:
    """Structured result for the GAU historical URL stage."""

    target: TargetInput
    command_result: CommandResult
    urls: list[GauUrl] = field(default_factory=list)
    host_count: int = 0
    input_count: int = 0
    param_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class GauModule:
    """Collect historical URLs from GAU for target hosts."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(
        self,
        alive_hosts: list[str],
        target: TargetInput,
    ) -> GauResult:
        """Execute GAU against each hostname and return historical URLs.

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
        executable = self.config.tool_bin("gau", "gau")

        hostnames = self._extract_hostnames(alive_hosts)
        host_count = len(hostnames)

        if not hostnames:
            warnings.append("No hostnames were provided")
            command_result = self._empty_command_result(executable)
            gau_urls: list[GauUrl] = []
        else:
            all_stdout_parts: list[str] = []
            last_result: CommandResult | None = None
            had_fatal = False

            for hostname in hostnames:
                if had_fatal:
                    break

                result = await self.context.runner.run(
                    executable,
                    [hostname],
                    timeout_seconds=self.context.timeout_seconds,
                )
                last_result = result

                if result.stdout:
                    all_stdout_parts.append(result.stdout)

                if result.missing_executable:
                    warnings.append(
                        f"Missing executable: {executable}"
                    )
                    had_fatal = True
                elif result.timed_out:
                    warnings.append(
                        f"GAU timed out for {hostname} after "
                        f"{self.context.timeout_seconds} seconds"
                    )
                elif (
                    result.returncode not in (0, None)
                ):
                    warnings.append(
                        f"GAU failed for {hostname} with exit "
                        f"code {result.returncode}"
                    )

            command_result = last_result or self._empty_command_result(executable)
            all_stdout = "\n".join(all_stdout_parts)
            gau_urls = self._parse_output(all_stdout, warnings)

        if not gau_urls:
            warnings.append("No historical URLs discovered")

        input_count = len(gau_urls)
        gau_urls = self._deduplicate(gau_urls)
        param_count = self._count_unique_params(gau_urls)

        result = GauResult(
            target=target_input,
            command_result=command_result,
            urls=gau_urls,
            host_count=host_count,
            input_count=input_count,
            param_count=param_count,
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
    ) -> list[GauUrl]:
        """Parse GAU line-based output into typed records."""
        gau_urls: list[GauUrl] = []

        for line_number, raw_line in enumerate(
            output.splitlines(), start=1
        ):
            line = raw_line.strip()
            if not line:
                continue

            url_obj = self._parse_url_line(line, line_number, warnings)
            if url_obj is not None:
                gau_urls.append(url_obj)

        return gau_urls

    def _parse_url_line(
        self,
        line: str,
        line_number: int,
        warnings: list[str],
    ) -> GauUrl | None:
        """Parse a single URL line into a GauUrl."""
        candidate = line if "://" in line else f"//{line}"
        parsed = urlparse(candidate)
        if not parsed.hostname:
            msg = f"Skipping line {line_number}: not a valid URL"
            logger.warning(msg)
            warnings.append(msg)
            return None

        host = parsed.hostname.lower()
        path = parsed.path or "/"
        query = parsed.query or None

        ext: str | None = None
        if path and "." in path:
            _, _, tail = path.rpartition("/")
            dot = tail.rfind(".")
            if dot != -1 and dot > 0:
                ext = tail[dot:].lower()

        params: list[str] = []
        if query:
            params = [
                name
                for name, _ in parse_qsl(
                    query, keep_blank_values=True
                )
                if name
            ]

        return GauUrl(
            url=line,
            host=host,
            path=path,
            query_string=query,
            file_extension=ext,
            parameter_names=params,
            source="gau",
        )

    @staticmethod
    def _normalize_url(url_str: str) -> str:
        """Normalize a URL for stable deduplication.

        - Lowercases scheme and host
        - Strips default ports (80 / 443)
        - Collapses duplicate trailing slashes
        - Normalizes query parameter ordering
        """
        candidate = url_str if "://" in url_str else f"//{url_str}"
        parsed = urlparse(candidate)
        scheme = (parsed.scheme or "http").lower()
        host = (parsed.hostname or "").lower()

        if not host:
            return url_str.strip().lower()

        port = parsed.port
        if port is not None:
            if (scheme == "http" and port == 80) or (
                scheme == "https" and port == 443
            ):
                port = None

        path = parsed.path
        while len(path) > 1 and path.endswith("//"):
            path = path[:-1]
        path = path.rstrip("/") if path != "/" else path

        query_parts = parse_qsl(
            parsed.query, keep_blank_values=True
        )
        query_parts.sort(key=lambda x: x[0])
        query = (
            "&".join(
                f"{k}={v}" if v else k for k, v in query_parts
            )
            if query_parts
            else ""
        )

        netloc = host
        if port is not None:
            netloc = f"{netloc}:{port}"

        normalized = f"{scheme}://{netloc}{path or '/'}"
        if query:
            normalized = f"{normalized}?{query}"
        return normalized

    @staticmethod
    def _deduplicate(gau_urls: list[GauUrl]) -> list[GauUrl]:
        """Deduplicate GauUrl records by normalized URL."""
        seen: set[str] = set()
        deduped: list[GauUrl] = []
        for url_obj in gau_urls:
            key = GauModule._normalize_url(url_obj.url)
            if key not in seen:
                seen.add(key)
                deduped.append(url_obj)
        return deduped

    @staticmethod
    def _count_unique_params(gau_urls: list[GauUrl]) -> int:
        """Count unique parameter names across all URLs."""
        seen: set[str] = set()
        for url_obj in gau_urls:
            for param in url_obj.parameter_names:
                seen.add(param.lower())
        return len(seen)

    @staticmethod
    def _extract_hostnames(alive_hosts: list[str]) -> set[str]:
        """Extract unique hostnames from a list of URLs."""
        hostnames: set[str] = set()
        for entry in alive_hosts:
            candidate = entry if "://" in entry else f"//{entry}"
            parsed = urlparse(candidate)
            hostname = parsed.hostname or entry.strip().lower().rstrip(".")
            if hostname:
                hostnames.add(hostname.lower())
        return hostnames

    def _save_results(self, result: GauResult) -> Path:
        """Persist GAU results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "urls": [asdict(u) for u in result.urls],
            "host_count": result.host_count,
            "input_count": result.input_count,
            "param_count": result.param_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("web/gau_urls.json", payload)

    def _print_summary(self, result: GauResult) -> None:
        """Print a concise summary of GAU results."""
        print("----------------------------------------")
        print("GAU")
        print("----------------------------------------")
        print(f"Hosts Processed : {result.host_count}")
        print(f"URLs Found      : {len(result.urls)}")
        print(f"Unique Params   : {result.param_count}")

    @staticmethod
    def _empty_command_result(command: str) -> CommandResult:
        """Build a no-op CommandResult for the empty-input case."""
        return CommandResult(
            command=command,
            args=(),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command=command,
        )


__all__ = [
    "GauModule",
    "GauUrl",
    "GauResult",
]
