"""URL aggregation stage for VINA.

Merges, normalises, and deduplicates URLs from Katana, GAU,
and Waybackurls into a single typed dataset for downstream scanners.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...models.findings import Finding
from ...modules.common import ModuleContext
from ..web.gau import GauResult
from ..web.katana import KatanaResult
from ..web.waybackurls import WaybackurlsResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AggregatedUrl:
    """A single URL with metadata from one or more sources."""

    url: str
    host: str | None = None
    path: str | None = None
    query_string: str | None = None
    parameter_names: list[str] = field(default_factory=list)
    file_extension: str | None = None
    sources: list[str] = field(default_factory=list)


@dataclass(slots=True)
class UrlAggregatorResult:
    """Structured result for the URL aggregation stage."""

    target: TargetInput
    command_result: CommandResult
    urls: list[AggregatedUrl] = field(default_factory=list)
    input_count: int = 0
    unique_count: int = 0
    unique_hosts: int = 0
    unique_params: int = 0
    duplicates_removed: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class UrlAggregatorModule:
    """Merge, normalise, and deduplicate URLs from multiple sources."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(
        self,
        katana_result: KatanaResult,
        gau_result: GauResult,
        wayback_result: WaybackurlsResult,
    ) -> UrlAggregatorResult:
        """Merge URLs from Katana, GAU, and Waybackurls into one dataset.

        Parameters
        ----------
        katana_result:
            Output from the Katana crawling stage.
        gau_result:
            Output from the GAU historical-URL stage.
        wayback_result:
            Output from the Waybackurls historical-URL stage.
        """
        target_input = katana_result.target or gau_result.target or wayback_result.target

        warnings: list[str] = []

        raw_urls: list[tuple[str, str]] = []

        # Collect URLs with source attribution
        for ep in katana_result.endpoints:
            raw_urls.append((ep.url, "katana"))

        for gu in gau_result.urls:
            raw_urls.append((gu.url, "gau"))

        for wu in wayback_result.urls:
            raw_urls.append((wu.url, "waybackurls"))

        input_count = len(raw_urls)

        merged = self._merge(raw_urls)

        urls = list(merged.values())
        unique_count = len(urls)
        duplicates_removed = input_count - unique_count
        unique_hosts = self._count_unique_hosts(urls)
        unique_params = self._count_unique_params(urls)

        dummy_command = CommandResult(
            command="url_aggregator",
            args=(),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="url_aggregator",
        )

        result = UrlAggregatorResult(
            target=target_input,
            command_result=dummy_command,
            urls=urls,
            input_count=input_count,
            unique_count=unique_count,
            unique_hosts=unique_hosts,
            unique_params=unique_params,
            duplicates_removed=duplicates_removed,
            warnings=warnings,
            execution_time_seconds=0.0,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _merge(
        self,
        raw_urls: list[tuple[str, str]],
    ) -> dict[str, AggregatedUrl]:
        """Normalize and deduplicate URLs, merging source attribution."""
        merged: dict[str, AggregatedUrl] = {}

        for raw_url, source in raw_urls:
            normalized = self._normalize_url(raw_url)

            if normalized not in merged:
                parsed = urlparse(raw_url if "://" in raw_url else f"//{raw_url}")
                host = parsed.hostname.lower() if parsed.hostname else None
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

                merged[normalized] = AggregatedUrl(
                    url=raw_url,
                    host=host,
                    path=path,
                    query_string=query,
                    parameter_names=params,
                    file_extension=ext,
                    sources=[source],
                )
            else:
                existing = merged[normalized]
                if source not in existing.sources:
                    existing.sources.append(source)

        return merged

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
        if port is not None and ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            port = None

        path = parsed.path
        while len(path) > 1 and path.endswith("//"):
            path = path[:-1]
        path = path.rstrip("/") if path != "/" else path

        query_parts = parse_qsl(parsed.query, keep_blank_values=True)
        query_parts.sort(key=lambda x: x[0])
        query = "&".join(f"{k}={v}" if v else k for k, v in query_parts) if query_parts else ""

        netloc = host
        if port is not None:
            netloc = f"{netloc}:{port}"

        normalized = f"{scheme}://{netloc}{path or '/'}"
        if query:
            normalized = f"{normalized}?{query}"
        return normalized

    @staticmethod
    def _count_unique_hosts(urls: list[AggregatedUrl]) -> int:
        """Count unique hostnames across aggregated URLs."""
        seen: set[str] = set()
        for u in urls:
            if u.host:
                seen.add(u.host.lower())
        return len(seen)

    @staticmethod
    def _count_unique_params(urls: list[AggregatedUrl]) -> int:
        """Count unique parameter names across aggregated URLs."""
        seen: set[str] = set()
        for u in urls:
            for param in u.parameter_names:
                seen.add(param.lower())
        return len(seen)

    def _save_results(self, result: UrlAggregatorResult) -> Path:
        """Persist aggregated URLs as JSON via the JsonStore."""
        payload = {
            "urls": [asdict(u) for u in result.urls],
            "input_count": result.input_count,
            "unique_count": result.unique_count,
            "unique_hosts": result.unique_hosts,
            "unique_params": result.unique_params,
            "duplicates_removed": result.duplicates_removed,
            "warnings": result.warnings,
        }
        return self.context.store.save("web/aggregated_urls.json", payload)

    def _print_summary(self, result: UrlAggregatorResult) -> None:
        """Print a concise summary of URL aggregation results."""
        print("----------------------------------------")
        print("URL AGGREGATOR")
        print("----------------------------------------")
        print(f"Input URLs        : {result.input_count}")
        print(f"Unique URLs       : {result.unique_count}")
        print(f"Unique Hosts      : {result.unique_hosts}")
        print(f"Unique Parameters : {result.unique_params}")
        print(f"Duplicates Removed: {result.duplicates_removed}")


__all__ = [
    "AggregatedUrl",
    "UrlAggregatorModule",
    "UrlAggregatorResult",
]
