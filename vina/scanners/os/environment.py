"""OS-level environment variable audit stage.

Checks PATH for writable entries, and examines
environment variables for potential security issues.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...models.findings import Finding, make_finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)

_SENSITIVE_ENV_PATTERNS = ("SECRET", "TOKEN", "PASSWORD", "PASS", "API_KEY", "AWS_", "AZURE_", "GITHUB_", "GITLAB_", "DOCKER_", "DB_", "DATABASE", "REDIS_", "MONGODB_", "PGPASSWORD", "MYSQL_")


@dataclass(slots=True)
class EnvVariable:
    key: str
    value: str
    sensitive: bool = False


@dataclass(slots=True)
class PathEntry:
    path: str
    writable: bool = False
    missing: bool = False


@dataclass(slots=True)
class EnvironmentResult:
    target: TargetInput
    command_result: CommandResult
    variables: list[EnvVariable] = field(default_factory=list)
    path_entries: list[PathEntry] = field(default_factory=list)
    writable_path_count: int = 0
    sensitive_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class EnvironmentModule:
    """Audit environment variables and PATH security."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> EnvironmentResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("env", self.config.tool_bin("env", "env"), []),
            ("echo_path", self.config.tool_bin("echo", "echo"), ["$PATH"]),
            ("cat_env", self.config.tool_bin("cat", "cat"), ["/etc/environment"]),
            ("cat_profile", self.config.tool_bin("cat", "cat"), ["/etc/profile"]),
            ("cat_bashrc", self.config.tool_bin("cat", "cat"), ["/etc/bash.bashrc"]),
        ]

        results: dict[str, CommandResult] = {}
        for name, executable, args in commands:
            cr = await self.context.runner.run(executable, args, timeout_seconds=self.context.timeout_seconds)
            results[name] = cr
            if cr.missing_executable:
                warnings.append(f"Missing executable: {executable}")
            if cr.timed_out:
                warnings.append(f"{name} timed out after {self.context.timeout_seconds}s")
            if cr.returncode not in (0, None) and not cr.timed_out and not cr.missing_executable:
                warnings.append(f"{name} exited with code {cr.returncode}")

        findings: list[Finding] = []
        target_str = target_input.normalized

        variables = self._parse_env(results, findings, target_str)
        path_entries, writable_path_count = await self._parse_path(results, findings, target_str)
        sensitive_count = sum(1 for v in variables if v.sensitive)

        if not variables:
            warnings.append("No environment variables could be read")

        primary = results.get("env") or results.get("echo_path") or self._empty_command_result()

        result = EnvironmentResult(
            target=target_input,
            command_result=primary,
            variables=variables,
            path_entries=path_entries,
            writable_path_count=writable_path_count,
            sensitive_count=sensitive_count,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_env(self, results: dict[str, CommandResult], findings: list[Finding], target_str: str) -> list[EnvVariable]:
        variables: list[EnvVariable] = []
        cr = results.get("env")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return variables
        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            sensitive = any(p in key.upper() for p in _SENSITIVE_ENV_PATTERNS)
            variables.append(EnvVariable(key=key, value=value, sensitive=sensitive))
            if sensitive:
                findings.append(make_finding(
                    title=f"Sensitive env variable: {key}",
                    description=f"Environment variable '{key}' may contain sensitive information",
                    severity="medium",
                    category="exposure",
                    source_stage="environment",
                    target=target_str,
                    evidence=f"{key}=***masked***",
                    recommendation=f"Review whether {key} needs to be exposed in the environment. Use secrets management.",
                ))

        cr2 = results.get("cat_env")
        if cr2 and cr2.succeeded and cr2.stdout.strip():
            for line in cr2.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip().strip('"').strip("'")
                value = value.strip().strip('"').strip("'")
                sensitive = any(p in key.upper() for p in _SENSITIVE_ENV_PATTERNS)
                if not any(v.key == key for v in variables):
                    variables.append(EnvVariable(key=key, value=value, sensitive=sensitive))
                    if sensitive:
                        findings.append(make_finding(
                            title=f"Sensitive env variable: {key} (in /etc/environment)",
                            description=f"Environment variable '{key}' in /etc/environment may contain sensitive information",
                            severity="medium",
                            category="exposure",
                            source_stage="environment",
                            target=target_str,
                            evidence=f"{key}=***masked*** (in /etc/environment)",
                            recommendation="Remove sensitive data from /etc/environment",
                        ))

        return variables

    async def _parse_path(self, results: dict[str, CommandResult], findings: list[Finding], target_str: str) -> tuple[list[PathEntry], int]:
        entries: list[PathEntry] = []
        writable_count = 0
        cr = results.get("echo_path")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            # Try env output for PATH
            for v in self._parse_env(results, [], target_str):
                if v.key == "PATH" and v.value:
                    cr = CommandResult(command="echo", args=("$PATH",), returncode=0, stdout=v.value, stderr="", duration_seconds=0.0, full_command="echo $PATH")
                    break

        if cr is None or not cr.stdout.strip():
            return entries, 0

        path_str = cr.stdout.strip()
        for p in path_str.split(":"):
            p = p.strip()
            if not p:
                continue
            entry = PathEntry(path=p)
            # Check if writable
            stat_cr = await self.context.runner.run(self.config.tool_bin("stat", "stat"), [p], timeout_seconds=5)
            if stat_cr.succeeded:
                entry.missing = False
            else:
                entry.missing = True
            # Check writable stat
            ls_cr = await self.context.runner.run(self.config.tool_bin("ls", "ls"), ["-la", "-d", p], timeout_seconds=5)
            if ls_cr.succeeded and ls_cr.stdout.strip():
                ls_line = ls_cr.stdout.strip().splitlines()[0] if ls_cr.stdout.strip() else ""
                parts = ls_line.split()
                if len(parts) >= 1:
                    perm = parts[0]
                    if len(perm) >= 9:
                        if perm[8] == "w":
                            entry.writable = True
                            writable_count += 1
            entries.append(entry)

        if writable_count > 0:
            writable_paths = [e.path for e in entries if e.writable]
            findings.append(make_finding(
                title=f"Writable PATH entries ({writable_count})",
                description=f"Found {writable_count} world-writable directories in PATH",
                severity="high",
                category="misconfiguration",
                source_stage="environment",
                target=target_str,
                evidence="\n".join(writable_paths[:10]),
                recommendation="Remove write permissions or remove these directories from PATH",
            ))

        return entries, writable_count

    def _save_results(self, result: EnvironmentResult) -> Path:
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "variables": [asdict(v) for v in result.variables],
            "path_entries": [asdict(p) for p in result.path_entries],
            "writable_path_count": result.writable_path_count,
            "sensitive_count": result.sensitive_count,
            "warnings": result.warnings,
            "findings": [f.to_dict() for f in result.findings],
        }
        return self.context.store.save("os/environment.json", payload)

    def _print_summary(self, result: EnvironmentResult) -> None:
        print("----------------------------------------")
        print("Environment Audit")
        print("----------------------------------------")
        print(f"Variables       : {len(result.variables)}")
        print(f"Sensitive       : {result.sensitive_count}")
        print(f"PATH entries    : {len(result.path_entries)}")
        print(f"Writable PATH   : {result.writable_path_count}")
        print(f"Findings        : {len(result.findings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(command="environment", args=(), returncode=1, stdout="", stderr="", duration_seconds=0.0, timed_out=False, missing_executable=False, full_command="environment")


__all__ = ["EnvironmentModule", "EnvVariable", "PathEntry", "EnvironmentResult"]
