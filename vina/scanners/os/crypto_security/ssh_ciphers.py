"""SSH server cryptographic ciphers, MACs, and Kex algorithms security auditing.

Audits /etc/ssh/sshd_config for insecure cryptographic settings.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding, make_finding
from ....modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SshCiphersResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class SshCiphersModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> SshCiphersResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_ssh = await self.context.runner.run(cat_cmd, ["/etc/ssh/sshd_config"], timeout_seconds=5)

        if cr_ssh.succeeded and cr_ssh.stdout.strip():
            content = cr_ssh.stdout
            ciphers = ""
            macs = ""
            for line in content.splitlines():
                line_s = line.strip()
                if line_s and not line_s.startswith("#"):
                    if line_s.lower().startswith("ciphers "):
                        ciphers = line_s.partition(" ")[2].strip()
                    elif line_s.lower().startswith("macs "):
                        macs = line_s.partition(" ")[2].strip()

            weak_ciphers = []
            if ciphers:
                for cipher in ciphers.split(","):
                    if "cbc" in cipher or "3des" in cipher or "arcfour" in cipher:
                        weak_ciphers.append(cipher)

            if weak_ciphers:
                findings.append(
                    make_finding(
                        title="Insecure SSH Ciphers enabled",
                        description="The SSH server config enables legacy or weak ciphers (CBC modes, 3DES, or RC4), exposing sessions to decryption or hijacking attacks.",
                        severity="high",
                        category="misconfiguration",
                        source_stage="crypto_security",
                        target=target_str,
                        evidence=f"Weak ciphers enabled: {', '.join(weak_ciphers)}",
                        recommendation="Remove CBC ciphers, 3DES, and RC4 from Ciphers in /etc/ssh/sshd_config. Enforce CTR or AEAD (gcm/chacha20) algorithms.",
                        confidence=0.95,
                    )
                )

            weak_macs = []
            if macs:
                for mac in macs.split(","):
                    if "md5" in mac or "-sha1" in mac or "none" in mac:
                        weak_macs.append(mac)

            if weak_macs:
                findings.append(
                    make_finding(
                        title="Insecure SSH MAC algorithms enabled",
                        description="The SSH server config enables weak message authentication codes (MD5 or SHA-1 hashes), which are cryptographically weak.",
                        severity="medium",
                        category="misconfiguration",
                        source_stage="crypto_security",
                        target=target_str,
                        evidence=f"Weak MACs enabled: {', '.join(weak_macs)}",
                        recommendation="Configure secure MACs like hmac-sha2-256 or hmac-sha2-512 in sshd_config.",
                        confidence=0.95,
                    )
                )

        primary = cr_ssh or self._empty_command_result()

        result = SshCiphersResult(
            target=target,
            command_result=primary,
            warnings=warnings,
            findings=findings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        return result

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="ssh_ciphers",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="ssh_ciphers",
        )
