"""Web historical-URL collection stage powered by Waybackurls."""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...models.findings import Finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class WaybackUrl:
    """A single historical URL discovered by Waybackurls."""

    url: str
    host: str | None = None
    path: str | None = None
    query_string: str | None = None
    file_extension: str | None = None
    parameter_names: list[str] = field(default_factory=list)


@dataclass(slots=True)
class WaybackurlsResult:
    """Structured result for the Waybackurls historical URL stage."""

    target: TargetInput
    command_result: CommandResult
    urls: list[WaybackUrl] = field(default_factory=list)
    host_count: int = 0
    param_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class WaybackurlsModule:
    """Collect historical URLs from Waybackurls for target hosts."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(
        self,
        alive_hosts: list[str],
        target: TargetInput,
    ) -> WaybackurlsResult:
        """Execute Waybackurls against target hosts and return historical URLs.

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
        executable = self.config.tool_bin("waybackurls", "waybackurls")

        hostnames = self._extract_hostnames(alive_hosts)
        host_count = len(hostnames)

        if not hostnames:
            warnings.append("No hostnames were provided")
            command_result = self._empty_command_result(executable)
            wayback_urls: list[WaybackUrl] = []
        else:
            command_result = await self.context.runner.run(
                executable,
                [],
                timeout_seconds=self.context.timeout_seconds,
                input_text="\n".join(hostnames) + "\n",
            )
            wayback_urls = self._parse_output(command_result.stdout, warnings)

        if command_result.missing_executable:
            warnings.append(f"Missing executable: {executable}")
        if command_result.timed_out:
            warnings.append(f"Waybackurls timed out after {self.context.timeout_seconds} seconds")
        if (
            command_result.returncode not in (0, None)
            and not command_result.timed_out
            and not command_result.missing_executable
        ):
            warnings.append(f"Waybackurls failed with exit code {command_result.returncode}")
        if hostnames and not wayback_urls and command_result.stdout.strip() and not command_result.timed_out:
            warnings.append("No valid URL lines were produced")
        if not wayback_urls:
            warnings.append("No historical URLs discovered")

        wayback_urls = self._deduplicate(wayback_urls)
        param_count = self._count_unique_params(wayback_urls)

        result = WaybackurlsResult(
            target=target_input,
            command_result=command_result,
            urls=wayback_urls,
            host_count=host_count,
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
    ) -> list[WaybackUrl]:
        """Parse Waybackurls line-based output into typed records."""
        wayback_urls: list[WaybackUrl] = []

        for line_number, raw_line in enumerate(output.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue

            url_obj = self._parse_url_line(line, line_number, warnings)
            if url_obj is not None:
                wayback_urls.append(url_obj)

        return wayback_urls

    def _parse_url_line(
        self,
        line: str,
        line_number: int,
        warnings: list[str],
    ) -> WaybackUrl | None:
        """Parse a single URL line into a WaybackUrl."""
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
            params = [name for name, _ in parse_qsl(query, keep_blank_values=True) if name]

        return WaybackUrl(
            url=line,
            host=host,
            path=path,
            query_string=query,
            file_extension=ext,
            parameter_names=params,
        )

    @staticmethod
    def _normalize_url(url_str: str) -> str:
        """Normalize a URL for stable deduplication."""
        candidate = url_str if "://" in url_str else f"//{url_str}"
        parsed = urlparse(candidate)
        scheme = (parsed.scheme or "http").lower()
        host = (parsed.hostname or "").lower()

        if not host:
            return url_str.strip().lower()

        port = parsed.port
        if port is not None and ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            port = None

        path = parsed.path.rstrip("/") if parsed.path != "/" else parsed.path
        query_parts = parse_qsl(parsed.query, keep_blank_values=True)
        query_parts.sort(key=lambda x: x[0])
        query = "&".join(f"{k}={v}" if v else k for k, v in query_parts) if query_parts else ""

        netloc = host.lower()
        if port is not None:
            netloc = f"{netloc}:{port}"

        normalized = f"{scheme}://{netloc}{path or '/'}"
        if query:
            normalized = f"{normalized}?{query}"
        return normalized

    @staticmethod
    def _deduplicate(
        wayback_urls: list[WaybackUrl],
    ) -> list[WaybackUrl]:
        """Deduplicate WaybackUrl records by normalized URL."""
        seen: set[str] = set()
        deduped: list[WaybackUrl] = []
        for url_obj in wayback_urls:
            key = WaybackurlsModule._normalize_url(url_obj.url)
            if key not in seen:
                seen.add(key)
                deduped.append(url_obj)
        return deduped

    @staticmethod
    def _count_unique_params(
        wayback_urls: list[WaybackUrl],
    ) -> int:
        """Count unique parameter names across all URLs."""
        seen: set[str] = set()
        for url_obj in wayback_urls:
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

    def _save_results(self, result: WaybackurlsResult) -> Path:
        """Persist Waybackurls results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "urls": [asdict(u) for u in result.urls],
            "host_count": result.host_count,
            "param_count": result.param_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("web/wayback_urls.json", payload)

    def _print_summary(self, result: WaybackurlsResult) -> None:
        """Print a concise summary of Waybackurls results."""
        print("----------------------------------------")
        print("WAYBACKURLS")
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
    "WaybackUrl",
    "WaybackurlsModule",
    "WaybackurlsResult",
]
