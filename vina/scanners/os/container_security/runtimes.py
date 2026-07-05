"""Container runtimes and orchestrators security auditing.

Checks for active runtimes (Docker, Podman, containerd, CRI-O, Kubernetes) and audits configs.
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
class RuntimesResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class RuntimesModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> RuntimesResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        pgrep_cmd = self.config.tool_bin("pgrep", "pgrep")
        cr_docker = await self.context.runner.run(pgrep_cmd, ["-x", "dockerd"], timeout_seconds=5)
        cr_kubelet = await self.context.runner.run(pgrep_cmd, ["-x", "kubelet"], timeout_seconds=5)
        cr_crio = await self.context.runner.run(pgrep_cmd, ["-x", "crio"], timeout_seconds=5)

        if cr_docker.succeeded:
            cat_cmd = self.config.tool_bin("cat", "cat")
            cr_json = await self.context.runner.run(cat_cmd, ["/etc/docker/daemon.json"], timeout_seconds=5)

            userns_configured = False
            if cr_json.succeeded and cr_json.stdout.strip():
                content = cr_json.stdout
                if "userns-remap" in content:
                    userns_configured = True

            if not userns_configured:
                findings.append(
                    make_finding(
                        title="Docker user namespace remapping is disabled",
                        description="User namespace remapping ('userns-remap') is not configured in Docker. Root inside a container maps directly to the root user on the host, increasing the risk of container escape.",
                        severity="high",
                        category="misconfiguration",
                        source_stage="container_security",
                        target=target_str,
                        evidence="userns-remap not found in /etc/docker/daemon.json",
                        recommendation="Configure user namespace remapping in /etc/docker/daemon.json.",
                        confidence=0.9,
                    )
                )

        if cr_kubelet.succeeded:
            cat_cmd = self.config.tool_bin("cat", "cat")
            cr_kconfig = await self.context.runner.run(cat_cmd, ["/var/lib/kubelet/config.yaml"], timeout_seconds=5)
            if cr_kconfig.succeeded and cr_kconfig.stdout.strip():
                content = cr_kconfig.stdout
                if (
                    "anonymous: \n      enabled: true" in content.replace(" ", "")
                    or "anonymous:\n    enabled: true" in content
                ):
                    findings.append(
                        make_finding(
                            title="Kubelet anonymous authentication is enabled",
                            description="Kubelet anonymous authentication is enabled in configuration, allowing unauthenticated requests to read Node or Pod details.",
                            severity="high",
                            category="vulnerability",
                            source_stage="container_security",
                            target=target_str,
                            evidence="anonymous authentication enabled",
                            recommendation="Set authentication.anonymous.enabled to false in Kubelet configuration.",
                            confidence=0.9,
                        )
                    )

        primary = cr_docker or cr_kubelet or cr_crio or self._empty_command_result()

        result = RuntimesResult(
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
            command="runtimes",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="runtimes",
        )
