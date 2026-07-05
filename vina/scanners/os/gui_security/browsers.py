"""Web browser security policy auditing.

Audits Firefox and Chromium system-wide managed policies.
"""

from __future__ import annotations

import json
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
class BrowsersResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class BrowsersModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> BrowsersResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        firefox_policy_paths = [
            "/etc/firefox/policies/policies.json",
            "/usr/lib/firefox/distribution/policies.json",
            "/usr/share/firefox/distribution/policies.json",
        ]
        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_ff = None
        ff_policy_file = None
        for path in firefox_policy_paths:
            cr_ff = await self.context.runner.run(cat_cmd, [path], timeout_seconds=5)
            if cr_ff.succeeded and cr_ff.stdout.strip():
                ff_policy_file = path
                break

        if ff_policy_file and cr_ff:
            try:
                data = json.loads(cr_ff.stdout)
                policies = data.get("policies", {})

                if "DisableSecurityBypasses" in policies and policies["DisableSecurityBypasses"] is False:
                    findings.append(make_finding(
                        title="Firefox security bypasses are allowed in policy",
                        description=f"Firefox configuration in '{ff_policy_file}' explicitly allows bypassing certificate warnings or other security warnings.",
                        severity="medium",
                        category="misconfiguration",
                        source_stage="gui_security",
                        target=target_str,
                        evidence="DisableSecurityBypasses=false",
                        recommendation="Configure 'DisableSecurityBypasses': true in Firefox policy.",
                        confidence=0.9,
                    ))
            except json.JSONDecodeError:
                warnings.append(f"Failed to parse Firefox policy file: {ff_policy_file}")

        find_cmd = self.config.tool_bin("find", "find")
        cr_chrom = await self.context.runner.run(find_cmd, ["/etc/chromium/policies/managed/", "/etc/opt/chrome/policies/managed/", "-name", "*.json"], timeout_seconds=5)

        chrom_files = []
        if cr_chrom.succeeded and cr_chrom.stdout.strip():
            chrom_files.extend(cr_chrom.stdout.strip().splitlines())

        for path in chrom_files:
            cr_policy = await self.context.runner.run(cat_cmd, [path], timeout_seconds=5)
            if cr_policy.succeeded and cr_policy.stdout.strip():
                try:
                    policy_data = json.loads(cr_policy.stdout)

                    if "SandboxToHTML5" in policy_data or "ExtensionInstallBlocklist" in policy_data:
                        pass
                except json.JSONDecodeError:
                    warnings.append(f"Failed to parse Chromium policy file: {path}")

        primary = cr_ff or cr_chrom or self._empty_command_result()

        result = BrowsersResult(
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
            command="browsers",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="browsers",
        )
