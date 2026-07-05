"""OS-level SSH configuration audit stage.

Inspects sshd_config, authentication settings, authorized keys,
and known hosts for security issues.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ...core.config import AppConfig
from ...core.runner import CommandResult, classify_command_error
from ...models.common import TargetInput
from ...models.findings import Finding, make_finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SshSetting:
    key: str
    value: str
    source_file: str
    line: int | None = None


@dataclass(slots=True)
class SshKeyEntry:
    type: str
    path: str
    user: str | None = None
    valid: bool = True


@dataclass(slots=True)
class SshResult:
    target: TargetInput
    command_result: CommandResult
    settings: list[SshSetting] = field(default_factory=list)
    authorized_keys: list[SshKeyEntry] = field(default_factory=list)
    known_hosts: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class SshModule:
    """Audit SSH configuration on the local host."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> SshResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("sshd_config", self.config.tool_bin("cat", "cat"), ["/etc/ssh/sshd_config"]),
            ("ssh_config", self.config.tool_bin("cat", "cat"), ["/etc/ssh/ssh_config"]),
            ("ls_ssh", self.config.tool_bin("ls", "ls"), ["-la", "/etc/ssh/"]),
        ]

        # Authorized keys for common users
        for user_home, user in [("/root", "root"), ("/home", None)]:
            auth_file = f"{user_home}/.ssh/authorized_keys"
            commands.append((f"auth_{user or 'home'}", self.config.tool_bin("cat", "cat"), [auth_file]))

        # Known hosts
        commands.append(("known_hosts", self.config.tool_bin("cat", "cat"), ["/etc/ssh/ssh_known_hosts"]))
        commands.append(("known_hosts_root", self.config.tool_bin("cat", "cat"), ["/root/.ssh/known_hosts"]))

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

        settings = self._parse_sshd_config(results, warnings)
        authorized_keys = self._parse_authorized_keys(results, warnings)
        known_hosts = self._parse_known_hosts(results, warnings)
        issues, findings = self._audit_settings(settings, target_input)

        if not settings and not authorized_keys:
            warnings.append("No SSH configuration could be read")

        primary = results.get("sshd_config") or results.get("ssh_config") or self._empty_command_result()

        result = SshResult(
            target=target_input,
            command_result=primary,
            settings=settings,
            authorized_keys=authorized_keys,
            known_hosts=known_hosts,
            issues=issues,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_sshd_config(self, results: dict[str, CommandResult], _warnings: list[str]) -> list[SshSetting]:
        settings: list[SshSetting] = []
        cr = results.get("sshd_config")
        if cr is None or not cr.stdout.strip():
            return settings
        for line_no, raw_line in enumerate(cr.stdout.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if " " in line:
                key, _, value = line.partition(" ")
                settings.append(
                    SshSetting(key=key.strip(), value=value.strip(), source_file="/etc/ssh/sshd_config", line=line_no)
                )
        return settings

    def _parse_authorized_keys(self, results: dict[str, CommandResult], _warnings: list[str]) -> list[SshKeyEntry]:
        keys: list[SshKeyEntry] = []
        for name in ("auth_root", "auth_home"):
            cr = results.get(name)
            if cr is None or not cr.succeeded or not cr.stdout.strip():
                continue
            for line in cr.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    kt = parts[0]
                    keys.append(SshKeyEntry(type=kt, path=name.replace("auth_", ""), user=name.replace("auth_", "")))
        return keys

    @staticmethod
    def _parse_known_hosts(results: dict[str, CommandResult], _warnings: list[str]) -> list[str]:
        hosts: list[str] = []
        for name in ("known_hosts", "known_hosts_root"):
            cr = results.get(name)
            if cr is None or not cr.succeeded or not cr.stdout.strip():
                continue
            for line in cr.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    host = line.split()[0] if line.split() else line
                    if host not in hosts:
                        hosts.append(host)
        return hosts

    def _audit_settings(self, settings: list[SshSetting], target: TargetInput) -> tuple[list[str], list[Finding]]:
        issues: list[str] = []
        findings: list[Finding] = []
        target_str = target.normalized

        audit_map: dict[str, tuple[str, str, str, str]] = {
            "PermitRootLogin": (
                "high",
                "SSH root login is permitted",
                "Set PermitRootLogin to 'prohibit-password' or 'no'",
                "high",
            ),
            "PasswordAuthentication": (
                "medium",
                "SSH password authentication is enabled",
                "Use PubkeyAuthentication only and disable PasswordAuthentication",
                "medium",
            ),
            "PubkeyAuthentication": ("info", "SSH public key authentication is enabled", "", "info"),
        }

        settings_dict = {s.key.lower(): s for s in settings}

        for s in settings:
            if s.key in audit_map:
                _default_sev, default_title, default_rec, sev = audit_map[s.key]
                val_lower = s.value.lower()
                if s.key == "PermitRootLogin" and val_lower not in ("no", "prohibit-password", "without-password"):
                    issues.append(f"{s.key} = {s.value}")
                    findings.append(
                        make_finding(
                            title=default_title,
                            description=f"PermitRootLogin is set to '{s.value}' in sshd_config",
                            severity=sev,
                            category="misconfiguration",
                            source_stage="ssh",
                            target=target_str,
                            evidence=f"{s.key} = {s.value}",
                            recommendation=default_rec,
                        )
                    )
                elif s.key == "PasswordAuthentication" and val_lower != "no":
                    issues.append(f"{s.key} = {s.value}")
                    findings.append(
                        make_finding(
                            title=default_title,
                            description=f"PasswordAuthentication is set to '{s.value}' in sshd_config",
                            severity=sev,
                            category="misconfiguration",
                            source_stage="ssh",
                            target=target_str,
                            evidence=f"{s.key} = {s.value}",
                            recommendation=default_rec,
                        )
                    )
                elif s.key == "PasswordAuthentication" and val_lower == "no":
                    findings.append(
                        make_finding(
                            title="SSH password authentication is disabled",
                            description="PasswordAuthentication is disabled in sshd_config",
                            severity="info",
                            category="information",
                            source_stage="ssh",
                            target=target_str,
                            evidence=f"{s.key} = {s.value}",
                        )
                    )
                elif s.key == "PubkeyAuthentication" and val_lower == "yes":
                    findings.append(
                        make_finding(
                            title=default_title,
                            description="Public key authentication is enabled in sshd_config",
                            severity="info",
                            category="information",
                            source_stage="ssh",
                            target=target_str,
                            evidence=f"{s.key} = {s.value}",
                        )
                    )

            key_lower = s.key.lower()
            val_lower = s.value.lower()

            if key_lower == "permitemptypasswords" and val_lower == "yes":
                issues.append(f"{s.key} = {s.value}")
                findings.append(
                    make_finding(
                        title="SSH PermitEmptyPasswords is enabled",
                        description="PermitEmptyPasswords is set to yes. This allows users with empty passwords to log in via SSH.",
                        severity="critical",
                        category="misconfiguration",
                        source_stage="ssh",
                        target=target_str,
                        evidence=f"{s.key} = {s.value}",
                        recommendation="Set 'PermitEmptyPasswords no' in sshd_config",
                    )
                )

            elif key_lower == "maxauthtries":
                try:
                    val_int = int(s.value)
                    if val_int > 4:
                        issues.append(f"{s.key} = {s.value}")
                        findings.append(
                            make_finding(
                                title="SSH MaxAuthTries is set too high",
                                description=f"MaxAuthTries is set to {s.value}. CIS recommends 4 or fewer to limit brute-force attempts.",
                                severity="medium",
                                category="misconfiguration",
                                source_stage="ssh",
                                target=target_str,
                                evidence=f"{s.key} = {s.value}",
                                recommendation="Set 'MaxAuthTries 4' in sshd_config",
                            )
                        )
                except ValueError:
                    pass

            elif key_lower == "logingracetime":
                try:
                    val_clean = s.value.rstrip("sS")
                    val_int = int(val_clean)
                    if val_int > 60 or val_int == 0:
                        issues.append(f"{s.key} = {s.value}")
                        findings.append(
                            make_finding(
                                title="SSH LoginGraceTime is set too high",
                                description=f"LoginGraceTime is set to {s.value}. Excessive grace time allows connection slots to be held open, potentially leading to denial of service.",
                                severity="low",
                                category="misconfiguration",
                                source_stage="ssh",
                                target=target_str,
                                evidence=f"{s.key} = {s.value}",
                                recommendation="Set 'LoginGraceTime 60' in sshd_config",
                            )
                        )
                except ValueError:
                    pass

            elif key_lower == "ciphers":
                weak_ciphers = ["3des", "cbc", "arcfour", "blowfish", "cast"]
                found_weak = [c for c in weak_ciphers if c in val_lower]
                if found_weak:
                    issues.append(f"{s.key} = {s.value}")
                    findings.append(
                        make_finding(
                            title="SSH weak Ciphers configured",
                            description=f"SSHD is configured with weak or vulnerable ciphers: {s.value}. Avoid CBC, 3DES, and RC4 modes.",
                            severity="medium",
                            category="misconfiguration",
                            source_stage="ssh",
                            target=target_str,
                            evidence=f"{s.key} = {s.value}",
                            recommendation="Configure sshd_config to use only CTR or GCM ciphers, e.g. chacha20-poly1305@openssh.com, aes256-gcm@openssh.com.",
                        )
                    )

            elif key_lower == "macs":
                weak_macs = ["md5", "96", "sha1"]
                found_weak = [m for m in weak_macs if m in val_lower]
                if found_weak:
                    issues.append(f"{s.key} = {s.value}")
                    findings.append(
                        make_finding(
                            title="SSH weak MACs configured",
                            description=f"SSHD is configured with weak message authentication codes: {s.value}.",
                            severity="medium",
                            category="misconfiguration",
                            source_stage="ssh",
                            target=target_str,
                            evidence=f"{s.key} = {s.value}",
                            recommendation="Use only SHA-2 based MACs, e.g. hmac-sha2-512, hmac-sha2-256.",
                        )
                    )

            elif key_lower == "kexalgorithms":
                weak_kex = ["sha1", "group1", "md5"]
                found_weak = [k for k in weak_kex if k in val_lower]
                if found_weak:
                    issues.append(f"{s.key} = {s.value}")
                    findings.append(
                        make_finding(
                            title="SSH weak KexAlgorithms configured",
                            description=f"SSHD is configured with weak key exchange algorithms: {s.value}.",
                            severity="medium",
                            category="misconfiguration",
                            source_stage="ssh",
                            target=target_str,
                            evidence=f"{s.key} = {s.value}",
                            recommendation="Use modern curves and group exchange, e.g. curve25519-sha256, diffie-hellman-group-exchange-sha256.",
                        )
                    )

            elif key_lower == "hostkeyalgorithms":
                weak_hk = ["dss", "ssh-rsa"]
                found_weak = [h for h in weak_hk if h in val_lower]
                if found_weak:
                    issues.append(f"{s.key} = {s.value}")
                    findings.append(
                        make_finding(
                            title="SSH weak HostKeyAlgorithms configured",
                            description=f"SSHD is configured with weak host key algorithms: {s.value}.",
                            severity="medium",
                            category="misconfiguration",
                            source_stage="ssh",
                            target=target_str,
                            evidence=f"{s.key} = {s.value}",
                            recommendation="Restrict host key algorithms to ecdsa-sha2-nistp256, ssh-ed25519.",
                        )
                    )

        restrict_keys = {"allowusers", "allowgroups", "denyusers", "denygroups"}
        if not any(rk in settings_dict for rk in restrict_keys):
            findings.append(
                make_finding(
                    title="SSH access is not restricted by user or group",
                    description="No AllowUsers, AllowGroups, DenyUsers, or DenyGroups settings found in sshd_config. All users with shell access can attempt SSH login.",
                    severity="low",
                    category="misconfiguration",
                    source_stage="ssh",
                    target=target_str,
                    evidence="Missing AllowUsers/AllowGroups/DenyUsers/DenyGroups in sshd_config",
                    recommendation="Add AllowUsers or AllowGroups to /etc/ssh/sshd_config to restrict who can log in.",
                )
            )

        return issues, findings

    def _save_results(self, result: SshResult) -> Path:
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "settings": [asdict(s) for s in result.settings],
            "authorized_keys": [asdict(k) for k in result.authorized_keys],
            "known_hosts": result.known_hosts,
            "issues": result.issues,
            "warnings": result.warnings,
            "findings": [f.to_dict() for f in result.findings],
        }
        return self.context.store.save("os/ssh.json", payload)

    def _print_summary(self, result: SshResult) -> None:
        print("----------------------------------------")
        print("SSH Audit")
        print("----------------------------------------")
        print(f"Settings        : {len(result.settings)}")
        print(f"Authorized Keys : {len(result.authorized_keys)}")
        print(f"Known Hosts     : {len(result.known_hosts)}")
        print(f"Issues          : {len(result.issues)}")
        print(f"Findings        : {len(result.findings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="ssh",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="ssh",
        )


__all__ = ["SshKeyEntry", "SshModule", "SshResult", "SshSetting"]
