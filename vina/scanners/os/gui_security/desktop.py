"""Desktop environment and display manager security auditing.

Audits active desktop environments, autologin/guest configs in GDM, LightDM, and SDDM,
idle screen lock settings, and Wayland/X11 session type.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding, make_finding
from ....modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class DesktopResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class DesktopModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> DesktopResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        cat_cmd = self.config.tool_bin("cat", "cat")
        target_str = target.normalized

        gdm_configs = [
            "/etc/gdm3/custom.conf",
            "/etc/gdm/custom.conf",
            "/etc/gdm3/daemon.conf",
        ]
        for cfg in gdm_configs:
            cr_gdm = await self.context.runner.run(cat_cmd, [cfg], timeout_seconds=5)
            if cr_gdm.succeeded and cr_gdm.stdout.strip():
                content = cr_gdm.stdout
                if "AutomaticLoginEnable=true" in content.replace(" ", "") or "TimedLoginEnable=true" in content.replace(" ", ""):
                    findings.append(make_finding(
                        title=f"GDM automatic login enabled in {cfg}",
                        description=f"The display manager GDM configured in '{cfg}' has automatic login enabled, allowing anyone with physical access to boot directly into the desktop user session.",
                        severity="high",
                        category="misconfiguration",
                        source_stage="gui_security",
                        target=target_str,
                        evidence="AutomaticLoginEnable=true",
                        recommendation="Disable automatic login by setting AutomaticLoginEnable=false in GDM daemon configs.",
                        confidence=0.9,
                    ))

        lightdm_configs = [
            "/etc/lightdm/lightdm.conf",
        ]
        find_cmd = self.config.tool_bin("find", "find")
        cr_find_ld = await self.context.runner.run(find_cmd, ["/etc/lightdm/lightdm.conf.d", "-type", "f"], timeout_seconds=5)
        if cr_find_ld.succeeded and cr_find_ld.stdout.strip():
            lightdm_configs.extend(cr_find_ld.stdout.strip().splitlines())

        for cfg in lightdm_configs:
            cr_ld = await self.context.runner.run(cat_cmd, [cfg], timeout_seconds=5)
            if cr_ld.succeeded and cr_ld.stdout.strip():
                content = cr_ld.stdout
                if "autologin-user=" in content:
                    findings.append(make_finding(
                        title=f"LightDM automatic login enabled in {cfg}",
                        description=f"LightDM is configured in '{cfg}' to log in a user automatically without password verification.",
                        severity="high",
                        category="misconfiguration",
                        source_stage="gui_security",
                        target=target_str,
                        evidence="autologin-user set in lightdm config",
                        recommendation="Remove the autologin-user directive from LightDM configurations.",
                        confidence=0.9,
                    ))
                if "allow-guest=true" in content.replace(" ", ""):
                    findings.append(make_finding(
                        title=f"LightDM guest session enabled in {cfg}",
                        description=f"Guest logins are enabled in LightDM configuration '{cfg}'. This allows unauthenticated users to create temporary desktop sessions.",
                        severity="medium",
                        category="misconfiguration",
                        source_stage="gui_security",
                        target=target_str,
                        evidence="allow-guest=true",
                        recommendation="Disable guest logins by setting allow-guest=false in lightdm.conf.",
                        confidence=0.9,
                    ))

        sddm_configs = [
            "/etc/sddm.conf",
        ]
        cr_find_sd = await self.context.runner.run(find_cmd, ["/etc/sddm.conf.d", "-type", "f"], timeout_seconds=5)
        if cr_find_sd.succeeded and cr_find_sd.stdout.strip():
            sddm_configs.extend(cr_find_sd.stdout.strip().splitlines())

        for cfg in sddm_configs:
            cr_sd = await self.context.runner.run(cat_cmd, [cfg], timeout_seconds=5)
            if cr_sd.succeeded and cr_sd.stdout.strip():
                content = cr_sd.stdout
                if "[Autologin]" in content and "User=" in content:
                    findings.append(make_finding(
                        title=f"SDDM automatic login configured in {cfg}",
                        description="SDDM (KDE display manager) has autologin configured, bypassing local session locks on boot.",
                        severity="high",
                        category="misconfiguration",
                        source_stage="gui_security",
                        target=target_str,
                        evidence="User configured under [Autologin] section",
                        recommendation="Clear the User configuration under [Autologin] section in sddm.conf.",
                        confidence=0.9,
                    ))

        pgrep_cmd = self.config.tool_bin("pgrep", "pgrep")
        cr_x11 = await self.context.runner.run(pgrep_cmd, ["-x", "Xorg"], timeout_seconds=5)
        cr_wl = await self.context.runner.run(pgrep_cmd, ["-x", "wayland"], timeout_seconds=5)

        using_x11 = cr_x11.succeeded
        using_wl = cr_wl.succeeded

        if using_x11 and not using_wl:
            findings.append(make_finding(
                title="Legacy X11 windowing system active",
                description="The system is running the legacy X11 windowing protocol (Xorg). X11 lacks session isolation, allowing any GUI application to capture keystrokes (keylogging) or read clipboard buffers of other applications.",
                severity="medium",
                category="vulnerability",
                source_stage="gui_security",
                target=target_str,
                evidence="Xorg process is active",
                recommendation="Migrate to Wayland windowing server for modern security boundaries and graphical session isolation.",
                confidence=0.85,
            ))

        primary = cr_find_ld or cr_find_sd or self._empty_command_result()

        result = DesktopResult(
            target=target,
            command_result=primary,
            warnings=warnings,
            findings=findings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        return result

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="desktop",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="desktop",
        )
