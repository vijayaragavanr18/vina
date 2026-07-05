"""OS-level user-discovery stage.

Collects local user account information by running getent or
falling back to /etc/passwd and /etc/group through AsyncCommandRunner.
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
class UserInfo:
    """A single system user entry."""

    username: str
    uid: int | None = None
    gid: int | None = None
    groups: list[str] = field(default_factory=list)
    shell: str | None = None
    home_directory: str | None = None
    is_system_user: bool = False
    source_command: str | None = None


@dataclass(slots=True)
class UsersResult:
    """Structured result for the user-discovery stage."""

    target: TargetInput
    command_result: CommandResult
    users: list[UserInfo] = field(default_factory=list)
    user_count: int = 0
    system_user_count: int = 0
    regular_user_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class UsersModule:
    """Collect system user information using getent or fallback."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> UsersResult:
        """Execute system commands and return discovered users.

        Parameters
        ----------
        target:
            Target metadata attached to the result.
        """
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("getent_passwd", self.config.tool_bin("getent", "getent"), ["passwd"]),
            ("getent_group", self.config.tool_bin("getent", "getent"), ["group"]),
            ("cat_passwd", self.config.tool_bin("cat", "cat"), ["/etc/passwd"]),
            ("cat_group", self.config.tool_bin("cat", "cat"), ["/etc/group"]),
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
                stderr_snippet = cr.stderr.strip()[:120] if cr.stderr.strip() else ""
                msg = f"{name} exited with code {cr.returncode}"
                if stderr_snippet:
                    msg += f": {stderr_snippet}"
                warnings.append(msg)

        users, group_map = self._parse_user_data(results, warnings)

        if not users:
            warnings.append("No users could be discovered")

        for user in users:
            members = group_map.get(user.username, [])
            if not members:
                for grp_name, grp_members in group_map.items():
                    if user.username in grp_members and grp_name not in user.groups:
                        user.groups.append(grp_name)
            if user.username == "root" and "root" in group_map and "root" not in user.groups:
                user.groups.append("root")

        missing_group_data = not group_map
        if missing_group_data and users:
            id_results = await self._run_id_commands(users, warnings)
            self._attach_id_groups(users, id_results)

        primary = (
            results.get("getent_passwd")
            or results.get("cat_passwd")
            or results.get("getent_group")
            or results.get("cat_group")
            or self._empty_command_result()
        )

        system_user_count = sum(1 for u in users if u.is_system_user)
        regular_user_count = sum(1 for u in users if not u.is_system_user)

        result = UsersResult(
            target=target_input,
            command_result=primary,
            users=users,
            user_count=len(users),
            system_user_count=system_user_count,
            regular_user_count=regular_user_count,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    async def _run_id_commands(self, users: list[UserInfo], warnings: list[str]) -> dict[str, CommandResult]:
        """Run ``id <username>`` for each discovered user."""
        cmd = self.config.tool_bin("id", "id")
        id_results: dict[str, CommandResult] = {}
        for user in users:
            cr = await self.context.runner.run(cmd, [user.username], timeout_seconds=self.context.timeout_seconds)
            id_results[user.username] = cr
            if cr.missing_executable:
                warnings.append(f"Missing executable: {cmd}")
                break
            if cr.timed_out:
                warnings.append(f"id for {user.username} timed out after {self.context.timeout_seconds}s")
            if cr.returncode not in (0, None) and not cr.timed_out and not cr.missing_executable:
                stderr_snippet = cr.stderr.strip()[:120] if cr.stderr.strip() else ""
                msg = f"id for {user.username} exited with code {cr.returncode}"
                if stderr_snippet:
                    msg += f": {stderr_snippet}"
                warnings.append(msg)
        return id_results

    def _parse_user_data(
        self, results: dict[str, CommandResult], warnings: list[str]
    ) -> tuple[list[UserInfo], dict[str, list[str]]]:
        """Parse passwd and group outputs into users and group memberships."""
        passwd_cr = (
            results.get("getent_passwd")
            if results.get("getent_passwd") and results["getent_passwd"].succeeded
            else results.get("cat_passwd")
        )
        group_cr = (
            results.get("getent_group")
            if results.get("getent_group") and results["getent_group"].succeeded
            else results.get("cat_group")
        )

        users: list[UserInfo] = []
        if passwd_cr and passwd_cr.succeeded and passwd_cr.stdout.strip():
            users = self._parse_passwd(passwd_cr.stdout, passwd_cr.full_command, warnings)

        group_map: dict[str, list[str]] = {}
        if group_cr and group_cr.succeeded and group_cr.stdout.strip():
            group_map = self._parse_groups(group_cr.stdout, warnings)

        return users, group_map

    @staticmethod
    def _parse_passwd(stdout: str, source: str, warnings: list[str]) -> list[UserInfo]:
        """Parse passwd-format output into UserInfo objects.

        Format: username:x:uid:gid:gecos:home:shell
        """
        users: list[UserInfo] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            try:
                username = parts[0]
                uid_str = parts[2]
                gid_str = parts[3]
                home = parts[5]
                shell = parts[6]

                uid = int(uid_str) if uid_str.isdigit() else None
                gid = int(gid_str) if gid_str.isdigit() else None
                is_system = uid is not None and uid < 1000

                users.append(
                    UserInfo(
                        username=username,
                        uid=uid,
                        gid=gid,
                        shell=shell or None,
                        home_directory=home or None,
                        is_system_user=is_system,
                        source_command=source,
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse passwd line: {line}")
        return users

    @staticmethod
    def _parse_groups(stdout: str, warnings: list[str]) -> dict[str, list[str]]:
        """Parse group-format output into a username-to-group mapping.

        Format: groupname:x:gid:user1,user2,...
        Returns a dict of ``{username: [groupname, ...]}``.
        """
        group_map: dict[str, list[str]] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 4:
                continue
            try:
                groupname = parts[0]
                members_str = parts[3]
                if members_str:
                    for member in members_str.split(","):
                        member = member.strip()
                        if member:
                            if member not in group_map:
                                group_map[member] = []
                            group_map[member].append(groupname)
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse group line: {line}")
        return group_map

    @staticmethod
    def _attach_id_groups(users: list[UserInfo], id_results: dict[str, CommandResult]) -> None:
        """Attach group memberships from ``id`` output."""
        for user in users:
            cr = id_results.get(user.username)
            if cr is None or not cr.succeeded or not cr.stdout.strip():
                continue
            groups = UsersModule._parse_id_groups(cr.stdout)
            for g in groups:
                if g not in user.groups:
                    user.groups.append(g)

    @staticmethod
    def _parse_id_groups(stdout: str) -> list[str]:
        """Extract group names from ``id`` output.

        Format: uid=1000(vijay) gid=1000(vijay) groups=1000(vijay),4(adm),...
        """
        groups_part = stdout.split("groups=")[-1] if "groups=" in stdout else ""
        if not groups_part:
            return []
        groups: list[str] = []
        for part in groups_part.split(","):
            if "(" in part and ")" in part:
                name = part[part.index("(") + 1 : part.index(")")]
                if name:
                    groups.append(name)
        return groups

    @staticmethod
    def _deduplicate(users: list[UserInfo]) -> list[UserInfo]:
        """Deduplicate users by username, merging group membership."""
        seen: dict[str, UserInfo] = {}
        for user in users:
            existing = seen.get(user.username)
            if existing is None:
                seen[user.username] = user
            else:
                for g in user.groups:
                    if g not in existing.groups:
                        existing.groups.append(g)
        return list(seen.values())

    def _save_results(self, result: UsersResult) -> Path:
        """Persist user results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "users": [asdict(u) for u in result.users],
            "user_count": result.user_count,
            "system_user_count": result.system_user_count,
            "regular_user_count": result.regular_user_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("os/users.json", payload)

    def _print_summary(self, result: UsersResult) -> None:
        """Print a concise summary of discovered users."""
        print("----------------------------------------")
        print("Users")
        print("----------------------------------------")
        print(f"Users Found    : {result.user_count}")
        print(f"System Users   : {result.system_user_count}")
        print(f"Regular Users  : {result.regular_user_count}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        """Build a no-op CommandResult for the no-data case."""
        return CommandResult(
            command="users",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="users",
        )


__all__ = ["UserInfo", "UsersModule", "UsersResult"]
