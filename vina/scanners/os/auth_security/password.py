"""Password security audit.

Audits /etc/passwd and /etc/shadow files for weak hashes, empty passwords,
expired accounts, password aging, and file permissions.
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

_WEAK_HASH_PREFIXES = {
    "": "empty/no hash",
    "$1$": "MD5",
    "$2$": "Blowfish (old)",
    "$2a$": "Blowfish",
    "$2x$": "Blowfish (old)",
    "$2y$": "Blowfish",
}
_STRONG_HASH_PREFIXES = {"$6$": "SHA-512", "$y$": "yescrypt", "$7$": "scrypt", "$5$": "SHA-256"}
_DEFAULT_HASH_PREFIX = "$y$"


@dataclass(slots=True)
class PasswordEntry:
    username: str
    uid: int
    gid: int
    hash_prefix: str = ""
    hash_type: str = ""
    last_change_days: int = -1
    min_age: int = -1
    max_age: int = -1
    warn_days: int = -1
    inactive_days: int = -1
    expiration_days: int = -1
    shell: str = ""


@dataclass(slots=True)
class PasswordResult:
    target: TargetInput
    command_result: CommandResult
    entries: list[PasswordEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class PasswordModule:
    """Audit password security from /etc/passwd and /etc/shadow."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> PasswordResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("passwd", self.config.tool_bin("cat", "cat"), ["/etc/passwd"]),
            ("shadow", self.config.tool_bin("cat", "cat"), ["/etc/shadow"]),
            ("stat_passwd", self.config.tool_bin("stat", "stat"), ["--format=%a %U %G", "/etc/passwd"]),
            ("stat_shadow", self.config.tool_bin("stat", "stat"), ["--format=%a %U %G", "/etc/shadow"]),
        ]

        results: dict[str, CommandResult] = {}
        for name, executable, args in commands:
            cr = await self.context.runner.run(executable, args, timeout_seconds=self.context.timeout_seconds)
            results[name] = cr

        passwd_lines = ""
        shadow_lines = ""
        if results.get("passwd") and results["passwd"].succeeded:
            passwd_lines = results["passwd"].stdout
        if results.get("shadow") and results["shadow"].succeeded:
            shadow_lines = results["shadow"].stdout

        entries = self._parse(passwd_lines, shadow_lines)

        self._audit_permissions(results, findings, target_input.normalized)
        self._audit_entries(entries, findings, target_input.normalized)

        primary = results.get("passwd") or results.get("shadow") or self._empty_command_result()

        result = PasswordResult(
            target=target_input,
            command_result=primary,
            entries=entries,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        return result

    @staticmethod
    def _hash_type(hash_field: str) -> tuple[str, str]:
        if not hash_field:
            return "", "empty"
        if hash_field in ("!", "*", "!!"):
            return "", "locked"
        if hash_field.startswith("!"):
            return "", "locked"
        if hash_field.startswith("$6$"):
            return "$6$", "SHA-512"
        if hash_field.startswith("$y$"):
            return "$y$", "yescrypt"
        if hash_field.startswith("$5$"):
            return "$5$", "SHA-256"
        if hash_field.startswith("$1$"):
            return "$1$", "MD5"
        if hash_field.startswith("$2"):
            return hash_field[:4], "Blowfish"
        if hash_field.startswith("$7$"):
            return "$7$", "scrypt"
        if hash_field.startswith("$"):
            end = hash_field.find("$", 1)
            prefix = hash_field[: end + 1] if end > 0 else hash_field
            return prefix, "unknown"
        return "", "DES/other"

    def _parse(self, passwd_text: str, shadow_text: str) -> list[PasswordEntry]:
        shadow_map: dict[str, tuple[str, str, int, int, int, int, int, int]] = {}
        for line in shadow_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            username = parts[0]
            hash_field = parts[1] if len(parts) > 1 else ""
            hash_prefix, hash_type = self._hash_type(hash_field)

            parts_shadow = line.split(":")
            last_change = int(parts_shadow[2]) if len(parts_shadow) > 2 and parts_shadow[2].isdigit() else -1
            min_age = int(parts_shadow[3]) if len(parts_shadow) > 3 and parts_shadow[3].isdigit() else -1
            max_age = int(parts_shadow[4]) if len(parts_shadow) > 4 and parts_shadow[4].isdigit() else -1
            warn = int(parts_shadow[5]) if len(parts_shadow) > 5 and parts_shadow[5].isdigit() else -1
            inactive = int(parts_shadow[6]) if len(parts_shadow) > 6 and parts_shadow[6].isdigit() else -1
            expire = int(parts_shadow[7]) if len(parts_shadow) > 7 and parts_shadow[7].isdigit() else -1

            shadow_map[username] = (hash_field, hash_prefix, last_change, min_age, max_age, warn, inactive, expire)

        entries: list[PasswordEntry] = []
        for line in passwd_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username = parts[0]
            uid_s, gid_s, shell = parts[2], parts[3], parts[6]
            uid = int(uid_s) if uid_s.isdigit() else -1
            gid = int(gid_s) if gid_s.isdigit() else -1

            sh = shadow_map.get(username)
            hash_prefix = sh[1] if sh else ""
            hash_type = ""
            if sh:
                _, hash_type = PasswordModule._hash_type(sh[0])

            entries.append(
                PasswordEntry(
                    username=username,
                    uid=uid,
                    gid=gid,
                    hash_prefix=hash_prefix,
                    hash_type=hash_type,
                    last_change_days=sh[2] if sh else -1,
                    min_age=sh[3] if sh else -1,
                    max_age=sh[4] if sh else -1,
                    warn_days=sh[5] if sh else -1,
                    inactive_days=sh[6] if sh else -1,
                    expiration_days=sh[7] if sh else -1,
                    shell=shell,
                )
            )

        return entries

    def _audit_permissions(self, results: dict[str, CommandResult], findings: list[Finding], target: str) -> None:
        stat_passwd = results.get("stat_passwd")
        if stat_passwd and stat_passwd.succeeded and stat_passwd.stdout.strip():
            parts = stat_passwd.stdout.strip().split()
            if parts:
                perm = parts[0]
                if perm != "644" and perm != "444":
                    findings.append(
                        make_finding(
                            title="Incorrect permissions on /etc/passwd",
                            description=f"/etc/passwd has permissions {perm}, expected 644 or 444.",
                            severity="medium",
                            category="misconfiguration",
                            source_stage="auth_security",
                            target=target,
                            evidence=f"/etc/passwd permissions: {perm}",
                            recommendation="chmod 644 /etc/passwd",
                            confidence=0.9,
                        )
                    )

        stat_shadow = results.get("stat_shadow")
        if stat_shadow and stat_shadow.succeeded and stat_shadow.stdout.strip():
            parts = stat_shadow.stdout.strip().split()
            if parts:
                perm = parts[0]
                if perm not in ("0", "400", "600", "640"):
                    findings.append(
                        make_finding(
                            title="Incorrect permissions on /etc/shadow",
                            description=f"/etc/shadow has permissions {perm}, expected 0 or 400/600/640.",
                            severity="high",
                            category="misconfiguration",
                            source_stage="auth_security",
                            target=target,
                            evidence=f"/etc/shadow permissions: {perm}",
                            recommendation="chmod 0 /etc/shadow or chmod 400 /etc/shadow",
                            confidence=0.95,
                        )
                    )

    def _audit_entries(self, entries: list[PasswordEntry], findings: list[Finding], target: str) -> None:
        for e in entries:
            if e.hash_type == "empty":
                findings.append(
                    make_finding(
                        title=f"Empty password for user {e.username}",
                        description=f"User {e.username} has an empty password hash, meaning no password is required.",
                        severity="critical",
                        category="misconfiguration",
                        source_stage="auth_security",
                        target=target,
                        evidence=f"/etc/shadow: {e.username} has empty password field",
                        recommendation=f"Set a password for {e.username}: passwd {e.username}",
                        confidence=0.95,
                    )
                )

            if e.hash_type in ("MD5", "DES/other", "Blowfish (old)"):
                findings.append(
                    make_finding(
                        title=f"Weak password hash for user {e.username}",
                        description=f"User {e.username} uses {e.hash_type} hashing, which is considered weak. "
                        "SHA-512 or yescrypt is recommended.",
                        severity="high",
                        category="misconfiguration",
                        source_stage="auth_security",
                        target=target,
                        evidence=f"Hash type: {e.hash_type} for {e.username}",
                        recommendation="Force password change to upgrade hash: passwd {e.username}",
                        confidence=0.85,
                    )
                )

            if e.max_age > 0 and e.max_age > 90:
                findings.append(
                    make_finding(
                        title=f"Password maximum age too high for {e.username}",
                        description=f"Password max age for {e.username} is {e.max_age} days (recommended: <= 90).",
                        severity="low",
                        category="misconfiguration",
                        source_stage="auth_security",
                        target=target,
                        evidence=f"max_age={e.max_age} for {e.username}",
                        recommendation=f"chage -M 90 {e.username}",
                        confidence=0.6,
                    )
                )

            if e.min_age < 0 or e.min_age == 0:
                findings.append(
                    make_finding(
                        title=f"Password minimum age not set for {e.username}",
                        description=f"Password minimum age for {e.username} is {e.min_age}. "
                        "A minimum age prevents rapid password changes.",
                        severity="low",
                        category="misconfiguration",
                        source_stage="auth_security",
                        target=target,
                        evidence=f"min_age={e.min_age} for {e.username}",
                        recommendation=f"chage -m 7 {e.username}",
                        confidence=0.5,
                    )
                )

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="password",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="password",
        )


__all__ = ["PasswordEntry", "PasswordModule", "PasswordResult"]
