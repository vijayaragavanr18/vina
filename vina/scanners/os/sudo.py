"""OS-level sudo-privilege discovery stage.

Collects sudo rules by running sudo -l or falling back to
reading /etc/sudoers and /etc/sudoers.d/* through
AsyncCommandRunner.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ...core.config import AppConfig
from ...core.runner import CommandResult, classify_command_error
from ...models.common import TargetInput
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SudoEntry:
    """A single sudo privilege entry."""

    username: str
    rule: str
    nopasswd: bool = False
    command: str | None = None
    source_command: str | None = None


@dataclass(slots=True)
class SudoResult:
    """Structured result for the sudo-privilege discovery stage."""

    target: TargetInput
    command_result: CommandResult
    entries: list[SudoEntry] = field(default_factory=list)
    entry_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class SudoModule:
    """Collect sudo privilege information using sudo -l or fallback."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> SudoResult:
        """Execute system commands and return discovered sudo rules.

        Parameters
        ----------
        target:
            Target metadata attached to the result.
        """
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("sudo_l", self.config.tool_bin("sudo", "sudo"), ["-n", "-l"]),
            ("cat_sudoers", self.config.tool_bin("cat", "cat"), ["/etc/sudoers"]),
            ("ls_sudoers_d", self.config.tool_bin("ls", "ls"), ["/etc/sudoers.d"]),
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
                _, msg = classify_command_error(name, cr)
                warnings.append(msg)

        entries = self._parse_sudo_l(results, warnings)

        if not entries:
            fallback_entries = self._parse_fallback(results, warnings)
            entries.extend(fallback_entries)

        sudoers_d_files = self._collect_sudoers_d_files(results, warnings)
        if sudoers_d_files and not entries:
            for fpath in sudoers_d_files:
                cr = await self.context.runner.run(
                    self.config.tool_bin("cat", "cat"), [fpath], timeout_seconds=self.context.timeout_seconds
                )
                results[f"cat_{fpath}"] = cr
                if cr.missing_executable:
                    warnings.append("Missing executable: cat")
                if cr.timed_out:
                    warnings.append(f"cat {fpath} timed out")
                if cr.returncode not in (0, None) and not cr.timed_out and not cr.missing_executable:
                    _, msg = classify_command_error(f"cat {fpath}", cr)
                    warnings.append(msg)
                if cr.succeeded and cr.stdout.strip():
                    parsed = SudoModule._parse_sudoers_content(cr.stdout, fpath, warnings)
                    entries.extend(parsed)

        entries = self._deduplicate(entries)

        if not entries:
            warnings.append("No sudo rules could be discovered")

        primary = (
            results.get("sudo_l")
            or results.get("cat_sudoers")
            or results.get("ls_sudoers_d")
            or self._empty_command_result()
        )

        result = SudoResult(
            target=target_input,
            command_result=primary,
            entries=entries,
            entry_count=len(entries),
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    @staticmethod
    def _parse_sudo_l(results: dict[str, CommandResult], warnings: list[str]) -> list[SudoEntry]:
        """Parse ``sudo -n -l`` output into SudoEntry objects."""
        entries: list[SudoEntry] = []
        cr = results.get("sudo_l")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return entries

        current_user: str | None = None
        in_privileges = False

        for line in cr.stdout.splitlines():
            line = line.rstrip()
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith("User ") and " may run" in stripped:
                parts = stripped.split()
                if len(parts) >= 2:
                    current_user = parts[1]
                in_privileges = True
                continue

            if stripped.startswith("Matching Defaults"):
                in_privileges = False
                continue

            if not in_privileges:
                continue

            if not stripped.startswith("("):
                if stripped.startswith("    ") or stripped.startswith("\t"):
                    continue
                in_privileges = False
                continue

            try:
                runas_end = stripped.index(")")
                _ = stripped[1:runas_end].strip()
                rest = stripped[runas_end + 1 :].strip()
                nopasswd = "NOPASSWD" in rest
                tags_end = rest.index(":") if ":" in rest else -1
                commands_str = rest[tags_end + 1 :].strip() if tags_end >= 0 else rest

                commands_str = commands_str.rstrip(",").strip()
                if commands_str == "ALL":
                    commands_list = ["ALL"]
                else:
                    commands_list = [c.strip() for c in commands_str.split(",") if c.strip()]

                rule = stripped
                for cmd in commands_list:
                    entries.append(
                        SudoEntry(
                            username=current_user or "unknown",
                            rule=rule,
                            nopasswd=nopasswd,
                            command=cmd,
                            source_command="sudo -l",
                        )
                    )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse sudo -l line: {stripped}")
                continue

        return entries

    @staticmethod
    def _parse_fallback(results: dict[str, CommandResult], warnings: list[str]) -> list[SudoEntry]:
        """Parse ``/etc/sudoers`` as fallback."""
        entries: list[SudoEntry] = []
        cr = results.get("cat_sudoers")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return entries
        return SudoModule._parse_sudoers_content(cr.stdout, "/etc/sudoers", warnings)

    @staticmethod
    def _collect_sudoers_d_files(results: dict[str, CommandResult], _warnings: list[str]) -> list[str]:
        """Collect file paths from ``ls /etc/sudoers.d`` output."""
        cr = results.get("ls_sudoers_d")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return []
        files: list[str] = []
        for line in cr.stdout.splitlines():
            name = line.strip()
            if name and not name.startswith("."):
                files.append(f"/etc/sudoers.d/{name}")
        return files

    @staticmethod
    def _parse_sudoers_content(content: str, source: str, warnings: list[str]) -> list[SudoEntry]:
        """Parse sudoers-format content into SudoEntry objects.

        Format: <user> <hosts>=<runas> <tags>: <commands>
        """
        entries: list[SudoEntry] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue

            try:
                user_part, rest = line.split("=", 1)
                user_part = user_part.strip()
                username = user_part.split()[0] if user_part.split() else user_part

                nopasswd = "NOPASSWD" in rest
                tags_end = rest.index(":") if ":" in rest else -1
                commands_str = rest[tags_end + 1 :].strip() if tags_end >= 0 else rest.strip()

                commands_str = commands_str.rstrip(",").strip()
                if commands_str == "ALL":
                    commands_list = ["ALL"]
                else:
                    commands_list = [c.strip() for c in commands_str.split(",") if c.strip()]

                rule = line
                for cmd in commands_list:
                    entries.append(
                        SudoEntry(username=username, rule=rule, nopasswd=nopasswd, command=cmd, source_command=source)
                    )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse sudoers line: {line}")
                continue
        return entries

    @staticmethod
    def _deduplicate(entries: list[SudoEntry]) -> list[SudoEntry]:
        """Deduplicate entries by (username, command)."""
        seen: set[tuple[str, str | None]] = set()
        deduped: list[SudoEntry] = []
        for entry in entries:
            key = (entry.username, entry.command)
            if key not in seen:
                seen.add(key)
                deduped.append(entry)
        return deduped

    def _save_results(self, result: SudoResult) -> Path:
        """Persist sudo results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "entries": [asdict(e) for e in result.entries],
            "entry_count": result.entry_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("os/sudo.json", payload)

    def _print_summary(self, result: SudoResult) -> None:
        """Print a concise summary of discovered sudo rules."""
        print("----------------------------------------")
        print("Sudo")
        print("----------------------------------------")
        print(f"Rules Found    : {result.entry_count}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        """Build a no-op CommandResult for the no-data case."""
        return CommandResult(
            command="sudo",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="sudo",
        )


__all__ = ["SudoEntry", "SudoModule", "SudoResult"]
