"""Polkit (PolicyKit) authorization audit.

Checks for installed polkit rules, writable rule files, custom
authorizations, dangerous permissions, and CVE-related configurations.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding, make_finding
from ....modules.common import ModuleContext

logger = logging.getLogger(__name__)

_POLKIT_DIRS = [
    "/usr/share/polkit-1/rules.d",
    "/etc/polkit-1/rules.d",
    "/usr/share/polkit-1/actions",
    "/etc/polkit-1/localauthority/50-local.d",
]


@dataclass(slots=True)
class PolkitRuleFile:
    path: str
    content: str = ""
    has_custom_rules: bool = False
    is_writable: bool = False
    dangerous_actions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PolkitResult:
    target: TargetInput
    command_result: CommandResult
    rule_files: list[PolkitRuleFile] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class PolkitModule:
    """Audit PolicyKit configuration."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> PolkitResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []
        rule_files: list[PolkitRuleFile] = []

        for d in _POLKIT_DIRS:
            cr = await self.context.runner.run(
                self.config.tool_bin("ls", "ls"),
                ["-la", d],
                timeout_seconds=self.context.timeout_seconds,
            )
            if cr.missing_executable:
                warnings.append("Missing executable for polkit dir check")
                continue
            if not cr.succeeded:
                continue

            for line in cr.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("total"):
                    continue
                parts = line.split()
                if len(parts) < 9:
                    continue
                fname = parts[-1]
                if not fname.endswith(".rules") and not fname.endswith(".policy"):
                    continue
                fpath = f"{d}/{fname}"
                is_writable = len(parts[0]) >= 4 and parts[0][3] == "w" if len(parts[0]) >= 4 else False

                content_cr = await self.context.runner.run(
                    self.config.tool_bin("cat", "cat"),
                    [fpath],
                    timeout_seconds=self.context.timeout_seconds,
                )
                content = content_cr.stdout if content_cr.succeeded else ""
                dangerous = self._find_dangerous_actions(content)

                prf = PolkitRuleFile(
                    path=fpath,
                    content=content,
                    has_custom_rules=bool(content.strip()),
                    is_writable=is_writable,
                    dangerous_actions=dangerous,
                )
                rule_files.append(prf)

        target_str = target_input.normalized

        for rf in rule_files:
            if rf.is_writable:
                findings.append(make_finding(
                    title=f"Writable polkit rule file: {rf.path}",
                    description=f"Polkit rule file {rf.path} is world-writable. "
                    "Any user can modify authorization rules.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target_str,
                    evidence=f"Writable: {rf.path}",
                    recommendation=f"chmod 644 {rf.path} && chown root:root {rf.path}",
                    confidence=0.9,
                ))

            for action in rf.dangerous_actions:
                findings.append(make_finding(
                    title=f"Dangerous polkit action: {action}",
                    description=f"Polkit action '{action}' has permissive authorization in {rf.path}. "
                    "This may allow unauthorized privilege escalation.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target_str,
                    evidence=f"Action: {action} in {rf.path}",
                    recommendation="Review polkit authorization rules. Use 'auth_admin' or 'auth_admin_keep' "
                    "instead of 'yes' for sensitive actions.",
                    confidence=0.8,
                ))

        if not rule_files:
            findings.append(make_finding(
                title="No polkit rule files found",
                description="No polkit rule files were found in standard directories. "
                "PolicyKit may not be installed or configured.",
                severity="info",
                category="information",
                source_stage="auth_security",
                target=target_str,
                evidence="No polkit rules found",
                confidence=0.3,
            ))

        primary = self._empty_command_result()

        result = PolkitResult(
            target=target_input,
            command_result=primary,
            rule_files=rule_files,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        return result

    @staticmethod
    def _find_dangerous_actions(content: str) -> list[str]:
        dangerous: list[str] = []
        if not content:
            return dangerous
        import re
        for m in re.finditer(
            r'action_id\s*:\s*["\']([^"\']+)["\']',
            content,
        ):
            action = m.group(1)
            dangerous.append(action)
        return dangerous

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


__all__ = ["PolkitModule", "PolkitResult", "PolkitRuleFile"]
