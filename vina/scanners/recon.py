"""Subdomain reconnaissance stage.

This module hosts the active recon implementation for VINA.
It preserves the existing ReconResult contract and uses the shared
AsyncCommandRunner via ModuleContext to execute external tools safely.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from ..core.config import AppConfig
from ..core.runner import CommandResult
from ..models.common import Asset, TargetInput
from ..modules.common import ModuleContext

logger = logging.getLogger(__name__)

_DOMAIN_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)


@dataclass(slots=True)
class ReconResult:
    """Structured result for the reconnaissance stage."""

    target: TargetInput
    assets: list[Asset] = field(default_factory=list)
    command_results: list[CommandResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ReconModule:
    """Run passive subdomain enumeration tools and collect unique assets."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> ReconResult:
        """Execute configured recon tools for the supplied target.

        The stage preserves the existing behavior: it resolves a domain from
        the normalized target, runs subfinder, assetfinder, and amass in
        parallel, deduplicates the discovered lines into Asset objects, and
        persists the normalized subdomain set to ``output/subdomains.json``.
        """

        started_at = time.perf_counter()
        domain = target.root_domain or target.hostname or target.normalized
        if not self._is_valid_domain(domain):
            warning = f"Invalid target domain for recon: {domain}"
            logger.warning(warning)
            result = ReconResult(target=target, warnings=[warning])
            self._save_subdomains(result)
            logger.info("Recon finished for %s in %.3fs (0 subdomains)", domain, time.perf_counter() - started_at)
            return result

        commands = [
            (self.config.tool_bin("subfinder", "subfinder"), ["-silent", "-d", domain]),
            (self.config.tool_bin("assetfinder", "assetfinder"), ["--subs-only", domain]),
            (self.config.tool_bin("amass", "amass"), ["enum", "-passive", "-d", domain]),
        ]
        gathered = await asyncio.gather(
            *[
                self.context.runner.run(command, args, timeout_seconds=self.context.timeout_seconds)
                for command, args in commands
            ],
            return_exceptions=True,
        )
        command_results = self._normalize_command_results(gathered)
        assets = self._parse_assets(command_results)
        warnings = self._collect_warnings(command_results, gathered)
        result = ReconResult(target=target, assets=assets, command_results=list(command_results), warnings=warnings)
        self._save_subdomains(result)
        elapsed_seconds = time.perf_counter() - started_at
        logger.info(
            "Recon finished for %s in %.3fs (%d unique subdomains)",
            domain,
            elapsed_seconds,
            len(assets),
        )
        return result

    def _parse_assets(self, results: list[CommandResult]) -> list[Asset]:
        """Extract unique asset values from the combined command output."""

        seen: set[str] = set()
        assets: list[Asset] = []
        for result in results:
            for value in self._extract_candidates(result.stdout):
                normalized = self._normalize_domain(value)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    assets.append(Asset(value=normalized, source=result.command))
        return assets

    def _collect_warnings(
        self,
        command_results: list[CommandResult],
        gathered: list[CommandResult | BaseException | object],
    ) -> list[str]:
        warnings: list[str] = []
        for item in gathered:
            if isinstance(item, BaseException):
                warning = f"Recon tool failed: {item}"
                logger.warning(warning)
                warnings.append(warning)
        for result in command_results:
            if result.stderr and not result.succeeded:
                warnings.append(result.stderr)
        return warnings

    @staticmethod
    def _normalize_command_results(
        gathered: list[CommandResult | BaseException | object],
    ) -> list[CommandResult]:
        command_results: list[CommandResult] = []
        for item in gathered:
            if isinstance(item, CommandResult):
                command_results.append(item)
        return command_results

    @staticmethod
    def _extract_candidates(output: str) -> list[str]:
        candidates: list[str] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parsed = urlparse(line if "://" in line else f"//{line}")
            candidate = parsed.hostname or line.split("/")[0]
            if candidate:
                candidates.append(candidate.lower().rstrip("."))
        return candidates

    @staticmethod
    def _normalize_domain(value: str) -> str | None:
        candidate = value.strip().lower().rstrip(".")
        if candidate.startswith("*."):
            candidate = candidate[2:]
        if not candidate or len(candidate) > 253:
            return None
        labels = candidate.split(".")
        if len(labels) < 2:
            return None
        if any(not label or not _DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
            return None
        return candidate

    @classmethod
    def _is_valid_domain(cls, value: str) -> bool:
        return cls._normalize_domain(value) is not None

    def _save_subdomains(self, result: ReconResult) -> None:
        output_root = Path(__file__).resolve().parents[2] / "output"
        output_root.mkdir(parents=True, exist_ok=True)
        destination = output_root / "subdomains.json"
        payload = {
            "target": result.target.normalized,
            "subdomains": [asset.value for asset in result.assets],
            "warnings": result.warnings,
        }
        destination.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.debug("Saved recon output to %s", destination)
