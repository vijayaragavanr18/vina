"""Desktop Environment and GUI Layer Security Stage for VINA.

PS-06: Audits desktop environments, display managers, session security, clipboard,
Wayland vs X11 windowing, remote desktop configs, browser settings, and Polkit policies.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding
from ....modules.common import ModuleContext
from .browsers import BrowsersModule, BrowsersResult
from .desktop import DesktopModule, DesktopResult
from .polkit import PolkitModule, PolkitResult
from .remote_desktop import RemoteDesktopModule, RemoteDesktopResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class GuiSecurityResult:
    """Aggregate result from all GUI layer security sub-scanners."""

    target: TargetInput
    command_result: CommandResult
    desktop: DesktopResult | None = None
    remote_desktop: RemoteDesktopResult | None = None
    browsers: BrowsersResult | None = None
    polkit: PolkitResult | None = None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class GuiSecurityModule:
    """Orchestrate all GUI layer security audits."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> GuiSecurityResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        desktop_mod = DesktopModule(self.config, self.context)
        desktop_res = await desktop_mod.run(target_input)
        findings.extend(desktop_res.findings)
        warnings.extend(desktop_res.warnings)

        rd_mod = RemoteDesktopModule(self.config, self.context)
        rd_res = await rd_mod.run(target_input)
        findings.extend(rd_res.findings)
        warnings.extend(rd_res.warnings)

        browsers_mod = BrowsersModule(self.config, self.context)
        browsers_res = await browsers_mod.run(target_input)
        findings.extend(browsers_res.findings)
        warnings.extend(browsers_res.warnings)

        polkit_mod = PolkitModule(self.config, self.context)
        polkit_res = await polkit_mod.run(target_input)
        findings.extend(polkit_res.findings)
        warnings.extend(polkit_res.warnings)

        primary = (
            desktop_res.command_result
            or rd_res.command_result
            or browsers_res.command_result
            or polkit_res.command_result
            or self._empty_command_result()
        )

        result = GuiSecurityResult(
            target=target_input,
            command_result=primary,
            desktop=desktop_res,
            remote_desktop=rd_res,
            browsers=browsers_res,
            polkit=polkit_res,
            findings=findings,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _save_results(self, result: GuiSecurityResult) -> Path:
        payload: dict[str, Any] = {
            "target": result.target.normalized,
            "duration_seconds": result.execution_time_seconds,
            "findings": [f.to_dict() for f in result.findings],
            "warnings": result.warnings,
        }
        return self.context.store.save("os/gui_security.json", payload)

    def _print_summary(self, result: GuiSecurityResult) -> None:
        print("----------------------------------------")
        print("GUI Security")
        print("----------------------------------------")
        print(f"Findings       : {len(result.findings)}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="gui_security",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="gui_security",
        )


__all__ = [
    "GuiSecurityModule",
    "GuiSecurityResult",
]
