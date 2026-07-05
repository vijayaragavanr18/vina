"""Polkit and pkexec privilege escalation auditing.

Audits pkexec permissions and custom Polkit rules for passwordless authorization overrides.
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
class PolkitResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class PolkitModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> PolkitResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        stat_cmd = self.config.tool_bin("stat", "stat")
        cr_pk = await self.context.runner.run(stat_cmd, ["-c", "%a %U %G", "/usr/bin/pkexec"], timeout_seconds=5)

        if cr_pk.succeeded and cr_pk.stdout.strip():
            parts = cr_pk.stdout.strip().split()
            owner = parts[1] if len(parts) >= 2 else ""

            if owner != "root":
                findings.append(
                    make_finding(
                        title="pkexec binary is not owned by root",
                        description="The pkexec privilege escalation utility is not owned by root. This is a critical permission bypass.",
                        severity="critical",
                        category="permissions",
                        source_stage="gui_security",
                        target=target_str,
                        evidence=f"Owner: {owner}",
                        recommendation="Change owner of pkexec to root: 'chown root /usr/bin/pkexec'.",
                        confidence=0.95,
                    )
                )

        find_cmd = self.config.tool_bin("find", "find")
        cr_find = await self.context.runner.run(
            find_cmd, ["/etc/polkit-1/rules.d/", "-type", "f", "-name", "*.rules"], timeout_seconds=5
        )

        rules_files = []
        if cr_find.succeeded and cr_find.stdout.strip():
            rules_files.extend(cr_find.stdout.strip().splitlines())

        cat_cmd = self.config.tool_bin("cat", "cat")
        for path in rules_files:
            cr_rule = await self.context.runner.run(cat_cmd, [path], timeout_seconds=5)
            if cr_rule.succeeded and cr_rule.stdout.strip():
                content = cr_rule.stdout

                if "polkit.Result.YES" in content and "auth_admin" not in content and "auth_self" not in content:
                    findings.append(
                        make_finding(
                            title=f"Polkit rule allows passwordless privilege escalation in {path}",
                            description=f"Polkit rule file '{path}' contains an authorization rule that returns 'polkit.Result.YES' without requiring administrative authentication.",
                            severity="high",
                            category="misconfiguration",
                            source_stage="gui_security",
                            target=target_str,
                            evidence="polkit.Result.YES configured without auth check",
                            recommendation="Review the custom polkit rule and require auth_admin or auth_self validation.",
                            confidence=0.85,
                        )
                    )

        primary = cr_pk or cr_find or self._empty_command_result()

        result = PolkitResult(
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
            command="polkit",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="polkit",
        )
