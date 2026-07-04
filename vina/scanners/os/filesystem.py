"""OS-level filesystem-discovery stage.

Collects mounted filesystems, disk usage, and interesting
filesystem entries using mount, df, find, and stat through
AsyncCommandRunner.
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
class FilesystemEntry:
    """A single filesystem entry (mount point, directory, or file)."""

    path: str
    type: str | None = None
    owner: str | None = None
    group: str | None = None
    permissions: str | None = None
    size: str | None = None
    mount_point: str | None = None
    filesystem: str | None = None
    writable: bool = False
    executable: bool = False
    source_command: str | None = None


@dataclass(slots=True)
class FilesystemResult:
    """Structured result for the filesystem-discovery stage."""

    target: TargetInput
    command_result: CommandResult
    entries: list[FilesystemEntry] = field(default_factory=list)
    entry_count: int = 0
    mount_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class FilesystemModule:
    """Collect filesystem information using mount, df, find, and stat."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(
        self,
        target: TargetInput,
    ) -> FilesystemResult:
        """Execute system commands and return discovered filesystem entries.

        Parameters
        ----------
        target:
            Target metadata attached to the result.
        """
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            (
                "mount",
                self.config.tool_bin("mount", "mount"),
                [],
            ),
            (
                "df",
                self.config.tool_bin("df", "df"),
                ["-h"],
            ),
            (
                "find_writable",
                self.config.tool_bin("find", "find"),
                ["/", "-maxdepth", "3", "-type", "d", "-perm", "-0002"],
            ),
            (
                "find_suid",
                self.config.tool_bin("find", "find"),
                ["/", "-maxdepth", "4", "-type", "f", "-perm", "-4000"],
            ),
        ]

        results: dict[str, CommandResult] = {}
        for name, executable, args in commands:
            cr = await self.context.runner.run(
                executable,
                args,
                timeout_seconds=self.context.timeout_seconds,
            )
            results[name] = cr
            if cr.missing_executable:
                warnings.append(f"Missing executable: {executable}")
            if cr.timed_out:
                warnings.append(
                    f"{name} timed out after {self.context.timeout_seconds}s"
                )
            if cr.returncode not in (0, None) and not cr.timed_out and not cr.missing_executable:
                stderr_snippet = cr.stderr.strip()[:120] if cr.stderr.strip() else ""
                msg = f"{name} exited with code {cr.returncode}"
                if stderr_snippet:
                    msg += f": {stderr_snippet}"
                warnings.append(msg)

        mount_entries = self._parse_mount(results, warnings)
        mount_points = [e.path for e in mount_entries if e.path]

        stat_result = None
        if mount_points:
            stat_args = ["--format=%a %U %G %s %n"] + mount_points
            stat_cr = await self.context.runner.run(
                self.config.tool_bin("stat", "stat"),
                stat_args,
                timeout_seconds=self.context.timeout_seconds,
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
            stat_result = stat_cr

        entries = self._build_entries(
            results, mount_entries, stat_result, warnings,
        )

        if not entries:
            warnings.append("No filesystem entries could be discovered")

        mount_count = sum(
            1 for e in entries if e.type == "mount"
        )

        primary = (
            results.get("mount")
            or results.get("df")
            or results.get("find_writable")
            or results.get("find_suid")
            or results.get("stat")
            or self._empty_command_result()
        )

        result = FilesystemResult(
            target=target_input,
            command_result=primary,
            entries=entries,
            entry_count=len(entries),
            mount_count=mount_count,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _build_entries(
        self,
        results: dict[str, CommandResult],
        mount_entries: list[FilesystemEntry],
        stat_result: CommandResult | None,
        warnings: list[str],
    ) -> list[FilesystemEntry]:
        """Merge mount, df, stat, and find data into final entry list."""
        seen: dict[str, FilesystemEntry] = {}

        for entry in mount_entries:
            seen[entry.path] = entry

        df_cr = results.get("df")
        if df_cr and df_cr.succeeded and df_cr.stdout.strip():
            df_entries = self._parse_df(df_cr.stdout, warnings)
            for df_entry in df_entries:
                existing = seen.get(df_entry.path)
                if existing is not None:
                    existing.size = df_entry.size
                    existing.mount_point = df_entry.mount_point
                else:
                    seen[df_entry.path] = df_entry

        if stat_result and stat_result.succeeded and stat_result.stdout.strip():
            stat_entries = self._parse_stat(stat_result.stdout, warnings)
            for st in stat_entries:
                existing = seen.get(st.path)
                if existing is not None:
                    existing.permissions = st.permissions
                    existing.owner = st.owner
                    existing.group = st.group
                    existing.size = st.size or existing.size
                    existing.writable = st.writable
                    existing.executable = st.executable

        for key in ("find_writable", "find_suid"):
            cr = results.get(key)
            if cr and cr.succeeded and cr.stdout.strip():
                entries = self._parse_find_output(cr.stdout, key, warnings)
                for entry in entries:
                    seen[entry.path] = entry

        return list(seen.values())

    @staticmethod
    def _parse_mount(
        results: dict[str, CommandResult],
        warnings: list[str],
    ) -> list[FilesystemEntry]:
        """Parse ``mount`` output into FilesystemEntry objects.

        Format: device on mount_point type filesystem (options,...)
        """
        entries: list[FilesystemEntry] = []
        cr = results.get("mount")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return entries

        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if " on /" not in line or " type " not in line:
                continue
            try:
                device = line.split(" on ")[0].strip()
                rest = line.split(" on ", 1)[1]
                mount_point = rest.split(" type ")[0].strip()
                rest2 = rest.split(" type ", 1)[1]
                filesystem = rest2.split(" (")[0].strip()
                options_str = rest2.split(" (", 1)[1].rstrip(")") if "(" in rest2 else ""
                options = [o.strip() for o in options_str.split(",")] if options_str else []
                writable = "rw" in options
                executable = "noexec" not in options
                entries.append(
                    FilesystemEntry(
                        path=mount_point,
                        type="mount",
                        mount_point=mount_point,
                        filesystem=filesystem,
                        writable=writable,
                        executable=executable,
                        source_command="mount",
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse mount line: {line}")
        return entries

    @staticmethod
    def _parse_df(
        stdout: str,
        warnings: list[str],
    ) -> list[FilesystemEntry]:
        """Parse ``df -h`` output into FilesystemEntry objects.

        Format: Filesystem  Size  Used  Avail  Use%  Mounted on
        """
        entries: list[FilesystemEntry] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Filesystem"):
                continue
            parts = line.split()
            if len(parts) < 6:
                continue
            try:
                fs = parts[0]
                size = parts[1]
                mount_point = parts[5]
                entries.append(
                    FilesystemEntry(
                        path=mount_point,
                        filesystem=fs,
                        size=size,
                        mount_point=mount_point,
                        type="mount",
                        source_command="df",
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse df line: {line}")
        return entries

    @staticmethod
    def _parse_stat(
        stdout: str,
        warnings: list[str],
    ) -> list[FilesystemEntry]:
        """Parse ``stat --format='%a %U %G %s %n'`` output.

        Format: <octal_mode> <owner> <group> <size_bytes> <path>
        """
        entries: list[FilesystemEntry] = []
        for line in stdout.splitlines():
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
                size_str = parts[3]
                path = parts[4]

                perms = FilesystemModule._octal_to_rwx(mode_oct)
                mode_int = int(mode_oct, 8) if mode_oct.isdigit() else 0
                writable = bool(mode_int & 0o222)
                executable = bool(mode_int & 0o111)

                entries.append(
                    FilesystemEntry(
                        path=path,
                        owner=owner,
                        group=group,
                        permissions=perms,
                        size=size_str,
                        writable=writable,
                        executable=executable,
                        source_command="stat",
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse stat line: {line}")
        return entries

    @staticmethod
    def _parse_find_output(
        stdout: str,
        source: str,
        warnings: list[str],
    ) -> list[FilesystemEntry]:
        """Parse ``find`` output (one path per line) into entries."""
        entries: list[FilesystemEntry] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            is_suid = "suid" in source
            is_writable = "writable" in source
            entries.append(
                FilesystemEntry(
                    path=line,
                    type="directory" if is_writable else "file",
                    writable=is_writable,
                    executable=is_suid,
                    source_command=source,
                )
            )
        return entries

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
    def _deduplicate(entries: list[FilesystemEntry]) -> list[FilesystemEntry]:
        """Deduplicate entries by canonical path, keeping the first."""
        seen: dict[str, FilesystemEntry] = {}
        for entry in entries:
            if entry.path not in seen:
                seen[entry.path] = entry
        return list(seen.values())

    def _save_results(self, result: FilesystemResult) -> Path:
        """Persist filesystem results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "entries": [asdict(e) for e in result.entries],
            "entry_count": result.entry_count,
            "mount_count": result.mount_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("os/filesystem.json", payload)

    def _print_summary(self, result: FilesystemResult) -> None:
        """Print a concise summary of discovered filesystem entries."""
        print("----------------------------------------")
        print("Filesystem")
        print("----------------------------------------")
        print(f"Mounts         : {result.mount_count}")
        print(f"Entries        : {result.entry_count}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        """Build a no-op CommandResult for the no-data case."""
        return CommandResult(
            command="filesystem",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="filesystem",
        )


__all__ = ["FilesystemModule", "FilesystemEntry", "FilesystemResult"]
