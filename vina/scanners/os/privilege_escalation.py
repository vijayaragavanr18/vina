"""OS-level privilege-escalation discovery stage.

Runs multiple commands to detect potential privilege escalation
vectors: SUID binaries, capabilities, sudo rules, writable paths,
systemd services, and scheduled tasks through AsyncCommandRunner.
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

_INTERESTING_WRITABLE_PREFIXES = ("/etc", "/usr", "/opt", "/root", "/var", "/home")
_UNINTERESTING_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/tmp")


@dataclass(slots=True)
class PrivilegeEscalationFinding:
    """A single potential privilege escalation finding."""

    category: str
    title: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    target: str
    source_command: str | None = None


@dataclass(slots=True)
class PrivilegeEscalationResult:
    """Structured result for the privilege-escalation discovery stage."""

    target: TargetInput
    command_result: CommandResult
    findings: list[PrivilegeEscalationFinding] = field(default_factory=list)
    finding_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class PrivilegeEscalationModule:
    """Detect potential privilege escalation vectors on the local host."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> PrivilegeEscalationResult:
        """Execute system commands and return PE-related findings.

        Parameters
        ----------
        target:
            Target metadata attached to the result.
        """
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("suid", self.config.tool_bin("find", "find"), ["/", "-perm", "-4000", "-type", "f"]),
            ("getcap", self.config.tool_bin("getcap", "getcap"), ["-r", "/"]),
            ("sudo_l", self.config.tool_bin("sudo", "sudo"), ["-n", "-l"]),
            ("writable_dirs", self.config.tool_bin("find", "find"), ["/", "-writable", "-type", "d", "-maxdepth", "4"]),
            ("systemctl", self.config.tool_bin("systemctl", "systemctl"), ["list-unit-files"]),
            ("crontab_l", self.config.tool_bin("crontab", "crontab"), ["-l"]),
            ("cat_crontab", self.config.tool_bin("cat", "cat"), ["/etc/crontab"]),
            ("ls_cron_d", self.config.tool_bin("ls", "ls"), ["-la", "/etc/cron.d"]),
            ("ls_cron_daily", self.config.tool_bin("ls", "ls"), ["-la", "/etc/cron.daily"]),
            ("ls_cron_hourly", self.config.tool_bin("ls", "ls"), ["-la", "/etc/cron.hourly"]),
            ("ls_cron_weekly", self.config.tool_bin("ls", "ls"), ["-la", "/etc/cron.weekly"]),
            ("ls_cron_monthly", self.config.tool_bin("ls", "ls"), ["-la", "/etc/cron.monthly"]),
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

        findings: list[PrivilegeEscalationFinding] = []
        target_str = target_input.normalized

        suid_findings = self._check_suid(results, warnings, target_str)
        findings.extend(suid_findings)

        cap_findings = self._check_capabilities(results, warnings, target_str)
        findings.extend(cap_findings)

        sudo_findings = self._check_sudo(results, warnings, target_str)
        findings.extend(sudo_findings)

        writable_findings = self._check_writable_dirs(results, warnings, target_str)
        findings.extend(writable_findings)

        systemd_findings = self._check_systemd(results, warnings, target_str)
        findings.extend(systemd_findings)

        cron_findings = self._check_cron(results, warnings, target_str)
        findings.extend(cron_findings)

        if not findings:
            warnings.append("No privilege escalation vectors could be detected")

        primary = (
            results.get("suid")
            or results.get("getcap")
            or results.get("sudo_l")
            or results.get("writable_dirs")
            or results.get("systemctl")
            or results.get("crontab_l")
            or results.get("cat_crontab")
            or results.get("ls_cron_d")
            or self._empty_command_result()
        )

        result = PrivilegeEscalationResult(
            target=target_input,
            command_result=primary,
            findings=findings,
            finding_count=len(findings),
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    # ------------------------------------------------------------------
    # SUID checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_suid(
        results: dict[str, CommandResult], _warnings: list[str], target: str
    ) -> list[PrivilegeEscalationFinding]:
        """Check for SUID binaries that may be worth investigating."""
        findings: list[PrivilegeEscalationFinding] = []
        cr = results.get("suid")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return findings

        binaries = [line.strip() for line in cr.stdout.splitlines() if line.strip()]
        if not binaries:
            return findings

        interesting_suid = [
            "/usr/bin/pkexec",
            "/usr/bin/sudo",
            "/usr/bin/passwd",
            "/usr/sbin/mount.cifs",
            "/usr/bin/mount",
            "/usr/bin/umount",
            "/usr/lib/polkit-1/polkit-agent-helper-1",
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
            "/usr/bin/at",
            "/usr/bin/crontab",
            "/usr/bin/clamav",
            "/usr/lib/openssh/ssh-keysign",
            "/usr/sbin/pppd",
            "/usr/bin/newgrp",
            "/usr/bin/gpasswd",
            "/usr/bin/chsh",
            "/usr/bin/chfn",
            "/usr/bin/expiry",
            "/usr/bin/wall",
            "/usr/bin/write",
        ]

        for binary in binaries:
            is_interesting = binary in interesting_suid or any(
                binary.startswith(p) for p in ("/usr/local/", "/opt/", "/home/", "/var/")
            )
            severity = "high" if is_interesting else "medium"
            title = f"SUID binary: {binary}"
            description = (
                f"The binary {binary} has the SUID bit set. "
                "This allows it to run with the permissions of its owner "
                "(typically root)."
            )
            if is_interesting:
                description += " This binary is less common and warrants manual review."

            findings.append(
                PrivilegeEscalationFinding(
                    category="SUID Binary",
                    title=title,
                    severity=severity,
                    description=description,
                    evidence=binary,
                    target=target,
                    recommendation=(
                        "Verify that the SUID bit is required for this binary. If not, remove it with: chmod u-s <path>"
                    ),
                    source_command="find / -perm -4000 -type f",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Capability checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_capabilities(
        results: dict[str, CommandResult], warnings: list[str], target: str
    ) -> list[PrivilegeEscalationFinding]:
        """Check for dangerous file capabilities."""
        findings: list[PrivilegeEscalationFinding] = []
        cr = results.get("getcap")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return findings

        dangerous_caps = [
            "cap_setuid",
            "cap_setgid",
            "cap_sys_admin",
            "cap_dac_override",
            "cap_dac_read_search",
            "cap_sys_ptrace",
            "cap_sys_module",
            "cap_net_admin",
        ]

        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line or " =" not in line:
                continue
            try:
                path, caps_str = line.split(" =", 1)
                path = path.strip()
                caps_str = caps_str.strip()
                matched_dangerous = [c for c in dangerous_caps if c in caps_str]
                severity = "high" if matched_dangerous else "medium"
                title = f"Capability: {path}"
                bits = ", ".join(matched_dangerous) if matched_dangerous else caps_str
                description = f"The binary {path} has file capabilities: {caps_str}. "
                if matched_dangerous:
                    description += (
                        f"This includes potentially dangerous capabilities: {bits}. "
                        "These may allow privilege escalation."
                    )
                evidence = line
                findings.append(
                    PrivilegeEscalationFinding(
                        category="Capability",
                        title=title,
                        severity=severity,
                        description=description,
                        evidence=evidence,
                        target=target,
                        recommendation=(
                            "Review whether these capabilities are necessary. "
                            "Remove unnecessary capabilities with: "
                            "setcap -r <path>"
                        ),
                        source_command="getcap -r /",
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse getcap line: {line}")

        return findings

    # ------------------------------------------------------------------
    # Sudo checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_sudo(
        results: dict[str, CommandResult], warnings: list[str], target: str
    ) -> list[PrivilegeEscalationFinding]:
        """Check for NOPASSWD sudo rules or overly permissive access."""
        findings: list[PrivilegeEscalationFinding] = []
        cr = results.get("sudo_l")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return findings

        current_user: str | None = None
        in_privileges = False

        for line in cr.stdout.splitlines():
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
                continue

            try:
                is_nopasswd = "NOPASSWD" in stripped
                is_all = " ALL" in stripped or stripped.endswith("ALL")
                has_specific = not is_all

                if is_nopasswd and is_all:
                    severity = "critical"
                    title = "NOPASSWD sudo: ALL commands"
                    description = (
                        f"User {current_user or 'unknown'} can run ALL "
                        "commands via sudo without a password. "
                        "This is a potential full privilege escalation vector."
                    )
                elif is_nopasswd and has_specific:
                    severity = "high"
                    title = "NOPASSWD sudo: specific commands"
                    description = (
                        f"User {current_user or 'unknown'} can run specific "
                        "commands via sudo without a password. "
                        "Review whether these commands allow shell escape."
                    )
                elif is_all:
                    severity = "high"
                    title = "Password sudo: ALL commands"
                    description = (
                        f"User {current_user or 'unknown'} can run ALL "
                        "commands via sudo (password required). "
                        "Potential escalation vector if password is known."
                    )
                else:
                    continue

                evidence = stripped
                findings.append(
                    PrivilegeEscalationFinding(
                        category="Sudo Rule",
                        title=title,
                        severity=severity,
                        description=description,
                        evidence=evidence,
                        target=target,
                        recommendation=(
                            "Restrict sudo rules to the minimum required commands and require password authentication."
                        ),
                        source_command="sudo -n -l",
                    )
                )
            except (IndexError, ValueError):
                warnings.append(f"Failed to parse sudo line: {stripped}")

        return findings

    # ------------------------------------------------------------------
    # Writable directory checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_writable_dirs(
        results: dict[str, CommandResult], _warnings: list[str], target: str
    ) -> list[PrivilegeEscalationFinding]:
        """Check for writable directories under system paths."""
        findings: list[PrivilegeEscalationFinding] = []
        cr = results.get("writable_dirs")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return findings

        writable_paths: list[str] = []
        for line in cr.stdout.splitlines():
            path = line.strip()
            if not path:
                continue
            if any(path.startswith(p) for p in _UNINTERESTING_PREFIXES):
                continue
            if any(path.startswith(p) for p in _INTERESTING_WRITABLE_PREFIXES):
                writable_paths.append(path)

        if writable_paths:
            evidence_lines = "\n".join(writable_paths[:20])
            if len(writable_paths) > 20:
                evidence_lines += f"\n... and {len(writable_paths) - 20} more"

            findings.append(
                PrivilegeEscalationFinding(
                    category="Writable Directory",
                    title=f"Writable system directories ({len(writable_paths)} found)",
                    severity="medium",
                    description=(
                        f"Found {len(writable_paths)} writable directories under "
                        "system paths (e.g., /etc, /usr, /opt, /root, /var, /home). "
                        "Writable system directories may allow privilege escalation "
                        "through file replacement or symlink attacks."
                    ),
                    evidence=evidence_lines,
                    target=target,
                    recommendation=(
                        "Review writable permissions on system directories. "
                        "Restrict write access to authorised users only."
                    ),
                    source_command="find / -writable -type d",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Systemd checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_systemd(
        results: dict[str, CommandResult], _warnings: list[str], target: str
    ) -> list[PrivilegeEscalationFinding]:
        """Check for writable or modified systemd service files."""
        findings: list[PrivilegeEscalationFinding] = []
        cr = results.get("systemctl")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return findings

        service_count = 0
        enabled_count = 0
        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0].endswith(".service"):
                service_count += 1
                if parts[1].lower() == "enabled":
                    enabled_count += 1

        if service_count > 0:
            findings.append(
                PrivilegeEscalationFinding(
                    category="Systemd Services",
                    title=(f"Systemd services available ({service_count} total, {enabled_count} enabled)"),
                    severity="low",
                    description=(
                        f"There are {service_count} systemd service units "
                        f"({enabled_count} enabled). Writable service unit files "
                        "can be modified to run arbitrary code as root. "
                        "Review service unit file permissions manually with: "
                        f"find /etc/systemd/system /usr/lib/systemd/system "
                        "-writable -type f 2>/dev/null"
                    ),
                    evidence=(f"Total services: {service_count}, Enabled: {enabled_count}"),
                    target=target,
                    recommendation=(
                        "Ensure systemd unit files are owned by root and not "
                        "world-writable. Check with: "
                        "find /etc/systemd/system -perm /o=w -type f"
                    ),
                    source_command="systemctl list-unit-files",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Cron checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_cron(
        results: dict[str, CommandResult], _warnings: list[str], target: str
    ) -> list[PrivilegeEscalationFinding]:
        """Check for interesting scheduled tasks and writable cron dirs."""
        findings: list[PrivilegeEscalationFinding] = []

        crontab_cr = results.get("crontab_l")
        cat_crontab_cr = results.get("cat_crontab")
        cron_dirs = {
            "cron.d": results.get("ls_cron_d"),
            "cron.daily": results.get("ls_cron_daily"),
            "cron.hourly": results.get("ls_cron_hourly"),
            "cron.weekly": results.get("ls_cron_weekly"),
            "cron.monthly": results.get("ls_cron_monthly"),
        }

        has_user_crontab = crontab_cr and crontab_cr.succeeded and crontab_cr.stdout.strip()
        has_system_crontab = cat_crontab_cr and cat_crontab_cr.succeeded and cat_crontab_cr.stdout.strip()

        if has_user_crontab or has_system_crontab:
            evidence_parts: list[str] = []
            if has_user_crontab:
                assert crontab_cr is not None
                user_lines = [
                    _line
                    for _line in crontab_cr.stdout.splitlines()
                    if _line.strip() and not _line.strip().startswith("#")
                ]
                if user_lines:
                    evidence_parts.append("--- User crontab ---")
                    evidence_parts.extend(user_lines[:15])

            if has_system_crontab:
                assert cat_crontab_cr is not None
                sys_lines = [
                    _line
                    for _line in cat_crontab_cr.stdout.splitlines()
                    if _line.strip() and not _line.strip().startswith("#")
                ]
                if sys_lines:
                    evidence_parts.append("--- /etc/crontab ---")
                    evidence_parts.extend(sys_lines[:15])

            if evidence_parts:
                evidence = "\n".join(evidence_parts)
                findings.append(
                    PrivilegeEscalationFinding(
                        category="Scheduled Task",
                        title="Active cron jobs found",
                        severity="low",
                        description=(
                            "Active cron jobs are configured. "
                            "Review cron jobs for tasks running as root or "
                            "other privileged users that may be exploitable."
                        ),
                        evidence=evidence,
                        target=target,
                        recommendation=(
                            "Review all cron jobs for potential abuse. Ensure cron scripts are not world-writable."
                        ),
                        source_command="crontab -l / cat /etc/crontab",
                    )
                )

        for dirname, dir_cr in cron_dirs.items():
            if dir_cr is None or not dir_cr.succeeded or not dir_cr.stdout.strip():
                continue

            dir_path = f"/etc/{dirname}"
            writable_entries: list[str] = []
            for entry_line in dir_cr.stdout.splitlines():
                entry_line = entry_line.strip()
                if not entry_line or entry_line.startswith("total"):
                    continue
                parts = entry_line.split()
                if len(parts) >= 9:
                    perm = parts[0]
                    entry_name = parts[-1]
                    if len(perm) >= 4 and perm[3] == "w":
                        writable_entries.append(f"{entry_name} ({perm})")

            if writable_entries:
                findings.append(
                    PrivilegeEscalationFinding(
                        category="Writable Cron",
                        title=f"Writable entries in {dir_path}",
                        severity="high",
                        description=(
                            f"Found {len(writable_entries)} writable file(s) "
                            f"in {dir_path}. Writable cron scripts can be "
                            "modified to execute arbitrary code as the "
                            "scheduled user (often root)."
                        ),
                        evidence="\n".join(writable_entries),
                        target=target,
                        recommendation=("Ensure cron scripts are not world-writable and are owned by root."),
                        source_command=f"ls -la {dir_path}",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Save / Print / Helpers
    # ------------------------------------------------------------------

    def _save_results(self, result: PrivilegeEscalationResult) -> Path:
        """Persist privilege-escalation results as JSON via the JsonStore."""
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "findings": [asdict(f) for f in result.findings],
            "finding_count": result.finding_count,
            "warnings": result.warnings,
        }
        return self.context.store.save("os/privilege_escalation.json", payload)

    def _print_summary(self, result: PrivilegeEscalationResult) -> None:
        """Print a concise summary of privilege-escalation findings."""
        critical = sum(1 for f in result.findings if f.severity == "critical")
        high = sum(1 for f in result.findings if f.severity == "high")
        medium = sum(1 for f in result.findings if f.severity == "medium")
        low = sum(1 for f in result.findings if f.severity == "low")

        print("----------------------------------------")
        print("Privilege Escalation")
        print("----------------------------------------")
        print(f"Total Findings : {result.finding_count}")
        if critical:
            print(f"  Critical     : {critical}")
        if high:
            print(f"  High         : {high}")
        if medium:
            print(f"  Medium       : {medium}")
        if low:
            print(f"  Low          : {low}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        """Build a no-op CommandResult for the no-data case."""
        return CommandResult(
            command="privilege_escalation",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="privilege_escalation",
        )


__all__ = ["PrivilegeEscalationFinding", "PrivilegeEscalationModule", "PrivilegeEscalationResult"]
