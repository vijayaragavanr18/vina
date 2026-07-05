"""Parameter discovery stage."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.config import AppConfig
from ..core.runner import CommandResult
from ..models.common import ParameterCandidate, extract_query_parameters
from ..parsers.tool_outputs import unique_lines
from .common import ModuleContext


@dataclass(slots=True)
class ParameterDiscoveryResult:
    parameters: list[ParameterCandidate] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    command_results: list[CommandResult] = field(default_factory=list)


class ParameterDiscoveryModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, urls: list[str]) -> ParameterDiscoveryResult:
        if not urls:
            return ParameterDiscoveryResult()
        normalized = await self.context.runner.run(
            self.config.tool_bin("uro", "uro"),
            [],
            timeout_seconds=self.context.timeout_seconds,
            input_text="\n".join(urls) + "\n",
        )
        qsreplace = await self.context.runner.run(
            self.config.tool_bin("qsreplace", "qsreplace"),
            ["FUZZ"],
            timeout_seconds=self.context.timeout_seconds,
            input_text="\n".join(urls) + "\n",
        )
        collected_urls = unique_lines(f"{normalized.stdout}\n{qsreplace.stdout}\n" + "\n".join(urls))
        parameters: list[ParameterCandidate] = []
        for url in collected_urls:
            for parameter in extract_query_parameters(url):
                parameters.append(
                    ParameterCandidate(
                        url=url,
                        parameter=parameter,
                        source=normalized.command if url in normalized.stdout else qsreplace.command,
                    )
                )
        warnings = [result.stderr for result in (normalized, qsreplace) if result.stderr and not result.succeeded]
        return ParameterDiscoveryResult(
            parameters=self._dedupe(parameters), warnings=warnings, command_results=[normalized, qsreplace]
        )

    @staticmethod
    def _dedupe(parameters: list[ParameterCandidate]) -> list[ParameterCandidate]:
        seen: set[tuple[str, str]] = set()
        deduped: list[ParameterCandidate] = []
        for parameter in parameters:
            key = (parameter.url, parameter.parameter)
            if key not in seen:
                seen.add(key)
                deduped.append(parameter)
        return deduped
