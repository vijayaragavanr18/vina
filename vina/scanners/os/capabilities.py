"""OS-level capability-discovery stage.

Enumerates binaries with Linux file capabilities using getcap
and enriches metadata with stat through AsyncCommandRunner.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CapabilityEntry:
    """A single binary with Linux file capabilities."""

    path: str
    capabilities: list[str] = field(default_factory=list)
    owner: str | None = None
    group: str | None = None
    permissions: str | None = None
    executable: bool = False
    source_command: str | None = None


@dataclass(slots=True)
class CapabilitiesResult:
    """Structured result for the capability-discovery stage."""

    target: TargetInput
    command_result: CommandResult
    entries: list[CapabilityEntry] = field(default_factory=list)
    entry_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class CapabilitiesModule:
    """Enumerate binaries with file capabilities using getcap and stat."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> CapabilitiesResult:
        """Execute system commands and return discovered capabilities.

        Parameters
        ----------
        target:
            Target metadata attached to the result.
        """
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [("getcap", self.config.tool_bin("getcap", "getcap"), ["-r", "/"])]

        results: dict[str, CommandResult] = {}
        for name, executable, args in commands:
            cr = await self.context.runner.run(executable, args, timeout_seconds=self.context.timeout_seconds)
            results[name] = cr
            if cr.missing_executable:
                warnings.append(f"Missing executable: {executable}")
            if cr.timed_out:
                warnings.append(f"{name} timed out after {self.context.timeout_seconds}s")
            if cr.returncode not in (0, None) and not cr.timed_out and not cr.missing_executable:
                stderr_snippet = cr.stderr.strip()[:120] if cr.stderr.strip() else ""
                msg = f"{name} exited with code {cr.returncode}"
                if stderr_snippet:
                    msg += f": {stderr_snippet}"
                warnings.append(msg)

        entries = self._parse_getcap(results, warnings)
        paths = [e.path for e in entries if e.path]

        if paths:
            stat_args = ["--format=%a %U %G %s %n", *paths]
            stat_cr = await self.context.runner.run(
                self.config.tool_bin("stat", "stat"), stat_args, timeout_seconds=self.context.timeout_seconds
            )
            results["stat"] = stat_cr
            if stat_cr.missing_executable:
                warnings.append("Missing executable: stat")
            if stat_cr.timed_out:
                warnings.append("stat timed out")
            if stat_cr.returncode not in (0, None) and not stat_cr.timed_out and not stat_cr.missing_executable:
                stderr_snippet = stat_cr.stderr.strip()[:120] if stat_cr.stderr.strip() else ""
                msg = f"stat exited with code {stat_cr.returncode}"
                if stderr_snippet:
                    msg += f": {stderr_snippet}"
                warnings.append(msg)

            self._enrich_with_stat(entries, stat_cr, warnings)

        if not entries:
            warnings.append("No capability binaries could be discovered")

        primary = results.get("getcap") or results.get("stat") or self._empty_command_result()

        result = CapabilitiesResult(
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
    def _parse_getcap(results: dict[str, CommandResult], warnings: list[str]) -> list[CapabilityEntry]:
        """Parse ``getcap -r /`` output into CapabilityEntry objects.

        Format: <path> = <capability1>,<capability2>+<flags>
        """
        entries: list[CapabilityEntry] = []
        cr = results.get("getcap")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return entries

        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if " =" not in line:
                continue
            try:
                path_part, caps_part = line.split(" =", 1)
                path = path_part.strip()
                caps_str = caps_part.strip()
                parsed_caps: list[str] = []
                for cap in caps_str.split(","):
                    cap = cap.strip()
                    if cap:
                        parsed_caps.append(cap)
                entries.append(CapabilityEntry(path=path, capabilities=parsed_caps, source_command="getcap"))
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse getcap line: {line}")
        return entries

    @staticmethod
    def _enrich_with_stat(entries: list[CapabilityEntry], stat_cr: CommandResult | None, warnings: list[str]) -> None:
        """Enrich capability entries with owner, group, permissions from stat."""
        if stat_cr is None or not stat_cr.succeeded or not stat_cr.stdout.strip():
            return

        stat_map: dict[str, tuple[str | None, str | None, str | None, bool]] = {}
        for line in stat_cr.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            try:
                mode_oct = parts[0]
                owner = parts[1]
                group = parts[2]
                path = parts[4]
                perms = CapabilitiesModule._octal_to_rwx(mode_oct)
                mode_int = int(mode_oct, 8) if mode_oct.isdigit() else 0
                executable = bool(mode_int & 0o111)
                stat_map[path] = (owner, group, perms, executable)
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse stat line: {line}")

        for entry in entries:
            meta = stat_map.get(entry.path)
            if meta is not None:
                entry.owner = meta[0]
                entry.group = meta[1]
                entry.permissions = meta[2]
                entry.executable = meta[3]

    @staticmethod
    def _octal_to_rwx(octal: str) -> str:
        """Convert an octal permission string to rwx notation (e.g. 755 → rwxr-xr-x)."""
        bits_map = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"]
        padded = octal.zfill(3)
        parts: list[str] = []
        for ch in padded[-3:]:
            try:
                parts.append(bits_map[int(ch)])
            except (ValueError, IndexError):
                parts.append("???")
        return "".join(parts)

    @staticmethod
    def _deduplicate(entries: list[CapabilityEntry]) -> list[CapabilityEntry]:
        """Deduplicate entries by canonical path, merging capabilities."""
        seen: dict[str, CapabilityEntry] = {}
        for entry in entries:
            existing = seen.get(entry.path)
            if existing is None:
                seen[entry.path] = entry
            else:
                for cap in entry.capabilities:
                    if cap not in existing.capabilities:
                        existing.capabilities.append(cap)
        return list(seen.values())

    def _save_results(self, result: CapabilitiesResult) -> Path:
        """Persist capability results as JSON via the JsonStore."""
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
        return self.context.store.save("os/capabilities.json", payload)

    def _print_summary(self, result: CapabilitiesResult) -> None:
        """Print a concise summary of discovered capabilities."""
        print("----------------------------------------")
        print("Capabilities")
        print("----------------------------------------")
        print(f"Files Scanned     : {result.entry_count}")
        print(f"Capability Files  : {result.entry_count}")
        if result.warnings:
            print(f"Warnings          : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        """Build a no-op CommandResult for the no-data case."""
        return CommandResult(
            command="capabilities",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="capabilities",
        )


__all__ = ["CapabilitiesModule", "CapabilitiesResult", "CapabilityEntry"]
