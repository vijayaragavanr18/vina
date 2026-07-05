"""Remote desktop service auditing.

Audits VNC and RDP/xrdp server configurations.
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
class RemoteDesktopResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class RemoteDesktopModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> RemoteDesktopResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        pgrep_cmd = self.config.tool_bin("pgrep", "pgrep")
        cr_vnc = await self.context.runner.run(pgrep_cmd, ["-f", "vnc"], timeout_seconds=5)

        if cr_vnc.succeeded:
            findings.append(make_finding(
                title="Active VNC server session detected",
                description="A VNC server is currently running. VNC traffic is unencrypted by default, allowing network eavesdroppers to capture keystrokes and session screen buffers.",
                severity="medium",
                category="vulnerability",
                source_stage="gui_security",
                target=target_str,
                evidence=f"Running VNC processes found: {cr_vnc.stdout.strip()}",
                recommendation="Tunnel VNC traffic over SSH ('ssh -L 5901:localhost:5901') or migrate to RDP with TLS encryption.",
                confidence=0.9,
            ))

        xrdp_ini = "/etc/xrdp/xrdp.ini"
        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_xrdp = await self.context.runner.run(cat_cmd, [xrdp_ini], timeout_seconds=5)

        if cr_xrdp.succeeded and cr_xrdp.stdout.strip():
            content = cr_xrdp.stdout

            sec_layer = "negotiate"
            for line in content.splitlines():
                if line.strip().startswith("security_layer="):
                    sec_layer = line.partition("=")[2].strip().lower()

            if sec_layer == "rdp":
                findings.append(make_finding(
                    title="Insecure security layer configured in xrdp",
                    description="The xrdp server is configured to use the native 'rdp' security layer instead of TLS. This allows MITM attacks and lacks proper endpoint verification.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="gui_security",
                    target=target_str,
                    evidence=f"security_layer={sec_layer}",
                    recommendation="Set 'security_layer=tls' or 'security_layer=negotiate' in /etc/xrdp/xrdp.ini.",
                    confidence=0.9,
                ))

            crypt_level = "high"
            for line in content.splitlines():
                if line.strip().startswith("crypt_level="):
                    crypt_level = line.partition("=")[2].strip().lower()

            if crypt_level in ("low", "none"):
                findings.append(make_finding(
                    title="Weak encryption level configured in xrdp",
                    description=f"The xrdp server encryption level is set to '{crypt_level}', which does not provide strong confidentiality protection.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="gui_security",
                    target=target_str,
                    evidence=f"crypt_level={crypt_level}",
                    recommendation="Set 'crypt_level=high' in /etc/xrdp/xrdp.ini.",
                    confidence=0.9,
                ))

        primary = cr_vnc or cr_xrdp or self._empty_command_result()

        result = RemoteDesktopResult(
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
            command="remote_desktop",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="remote_desktop",
        )
