"""Session security audit.

Audits screen lock settings, idle timeout, shell history, SSH agent
forwarding, forwarded credentials, and active sessions.
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


@dataclass(slots=True)
class SessionInfo:
    user: str
    tty: str = ""
    from_addr: str = ""
    login_time: str = ""
    is_active: bool = True


@dataclass(slots=True)
class SessionsResult:
    target: TargetInput
    command_result: CommandResult
    active_sessions: list[SessionInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class SessionsModule:
    """Audit session security settings and active sessions."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> SessionsResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("who", self.config.tool_bin("who", "who"), ["-u"]),
            ("w", self.config.tool_bin("w", "w"), []),
            ("last", self.config.tool_bin("last", "last"), ["-10"]),
            ("tmout", self.config.tool_bin("cat", "cat"), ["/etc/profile"]),
            ("history_root", self.config.tool_bin("cat", "cat"), ["/root/.bash_history"]),
            ("ssh_env", self.config.tool_bin("cat", "cat"), ["/proc/self/environ"]),
            ("issue", self.config.tool_bin("cat", "cat"), ["/etc/issue"]),
            ("issue_net", self.config.tool_bin("cat", "cat"), ["/etc/issue.net"]),
            ("motd", self.config.tool_bin("cat", "cat"), ["/etc/motd"]),
            ("securetty", self.config.tool_bin("cat", "cat"), ["/etc/securetty"]),
        ]

        results: dict[str, CommandResult] = {}
        for name, executable, args in commands:
            cr = await self.context.runner.run(
                executable, args, timeout_seconds=self.context.timeout_seconds
            )
            results[name] = cr

        target_str = target_input.normalized

        active = self._parse_who(results)
        await self._check_ssh_agent(results, findings, target_str)
        await self._check_shell_history(results, findings, target_str)
        self._check_tmout(results, findings, target_str)
        self._check_login_banners(results, findings, target_str)
        self._check_securetty(results, findings, target_str)
        self._check_active_sessions(active, findings, target_str)

        primary = (
            results.get("who") or results.get("w") or self._empty_command_result()
        )

        result = SessionsResult(
            target=target_input,
            command_result=primary,
            active_sessions=active,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        return result

    @staticmethod
    def _parse_who(results: dict[str, CommandResult]) -> list[SessionInfo]:
        sessions: list[SessionInfo] = []
        cr = results.get("who")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return sessions
        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                sessions.append(SessionInfo(
                    user=parts[0],
                    tty=parts[1] if len(parts) > 1 else "",
                    from_addr=parts[4] if len(parts) > 4 else "",
                    login_time=" ".join(parts[2:4]) if len(parts) > 3 else "",
                ))
        return sessions

    async def _check_ssh_agent(
        self,
        results: dict[str, CommandResult],
        findings: list[Finding],
        target: str,
    ) -> bool:
        has_agent = False
        cr = results.get("ssh_env")
        if cr and cr.succeeded and cr.stdout.strip() and (b"SSH_AUTH_SOCK" in cr.stdout.encode() or "SSH_AUTH_SOCK" in cr.stdout):
            has_agent = True
            findings.append(make_finding(
                    title="SSH agent forwarding detected",
                    description="SSH_AUTH_SOCK is set, indicating SSH agent forwarding is active. "
                    "Forwarded SSH agent sockets can be used by attackers with root access to "
                    "authenticate as the forwarding user.",
                    severity="medium",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target,
                    evidence="SSH_AUTH_SOCK environment variable is set",
                    recommendation="Avoid SSH agent forwarding (-A flag). Use ProxyJump or SSH config ForwardAgent=no.",
                    confidence=0.7,
                ))
        return has_agent

    async def _check_shell_history(
        self,
        results: dict[str, CommandResult],
        findings: list[Finding],
        target: str,
    ) -> None:
        cr = results.get("history_root")
        if cr and cr.succeeded and cr.stdout.strip():
            history_lines = len(cr.stdout.splitlines())
            if history_lines > 500:
                findings.append(make_finding(
                    title="Large shell history file",
                    description=f"/root/.bash_history contains {history_lines} lines. "
                    "Large history files may contain sensitive data and increase credential exposure risk.",
                    severity="low",
                    category="information",
                    source_stage="auth_security",
                    target=target,
                    evidence=f"History size: {history_lines} lines",
                    recommendation="Clear sensitive commands from history: history -c. Set HISTFILESIZE to a reasonable limit.",
                    confidence=0.4,
                ))

    def _check_tmout(
        self,
        results: dict[str, CommandResult],
        findings: list[Finding],
        target: str,
    ) -> None:
        cr = results.get("tmout")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return
        has_tmout = False
        for line in cr.stdout.splitlines():
            if "TMOUT" in line and not line.strip().startswith("#"):
                has_tmout = True
                break
        if not has_tmout:
            findings.append(make_finding(
                title="Terminal idle timeout not configured",
                description="TMOUT is not set in /etc/profile. Idle SSH sessions remain open "
                "indefinitely, increasing the risk of session hijacking.",
                severity="low",
                category="misconfiguration",
                source_stage="auth_security",
                target=target,
                evidence="TMOUT not found in /etc/profile",
                recommendation="Add 'export TMOUT=900' to /etc/profile to auto-logout idle sessions after 15 minutes.",
                confidence=0.5,
            ))

    @staticmethod
    def _check_active_sessions(
        sessions: list[SessionInfo],
        findings: list[Finding],
        target: str,
    ) -> None:
        root_sessions = [s for s in sessions if s.user == "root"]
        if root_sessions:
            for s in root_sessions:
                findings.append(make_finding(
                    title=f"Active root session from {s.from_addr or 'local'}",
                    description=f"Root user has an active session on {s.tty} from {s.from_addr or 'local'} "
                    f"since {s.login_time}. Monitor root sessions for unauthorized access.",
                    severity="info",
                    category="information",
                    source_stage="auth_security",
                    target=target,
                    evidence=f"Root session: {s.user} on {s.tty} from {s.from_addr} since {s.login_time}",
                    recommendation="Use sudo instead of direct root login. Monitor all root sessions.",
                    confidence=0.3,
                ))

    def _check_login_banners(
        self,
        results: dict[str, CommandResult],
        findings: list[Finding],
        target: str,
    ) -> None:
        for name, path in [("issue", "/etc/issue"), ("issue_net", "/etc/issue.net")]:
            cr = results.get(name)
            if cr and cr.succeeded and cr.stdout.strip():
                content = cr.stdout
                import re
                if re.search(r'\\[ursmo]', content):
                    findings.append(make_finding(
                        title=f"System information leakage in login banner: {path}",
                        description=f"{path} contains escape sequences that leak system details.",
                        severity="low",
                        category="misconfiguration",
                        source_stage="auth_security",
                        target=target,
                        evidence=content.strip(),
                        recommendation="Remove escape sequences that show OS or kernel version details from the login banner.",
                        confidence=0.8,
                    ))

    def _check_securetty(
        self,
        results: dict[str, CommandResult],
        findings: list[Finding],
        target: str,
    ) -> None:
        cr = results.get("securetty")
        if cr and cr.succeeded and cr.stdout.strip():
            content = cr.stdout
            lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
            dangerous = [line for line in lines if line.startswith("pts") or "/" in line]
            if dangerous:
                findings.append(make_finding(
                    title="Root login permitted on insecure terminals",
                    description="/etc/securetty lists network or pseudo-terminals (e.g., pts/*), allowing direct root login over insecure channels.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target,
                    evidence=f"Insecure ttys: {', '.join(dangerous[:5])}",
                    recommendation="Remove network and virtual terminals (pts/*) from /etc/securetty to restrict root login to physical console.",
                    confidence=0.85,
                ))

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="sessions",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="sessions",
        )


__all__ = ["SessionInfo", "SessionsModule", "SessionsResult"]
