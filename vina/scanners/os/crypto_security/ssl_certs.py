"""SSL/TLS certificates and key configuration security auditing.

Audits SSL/TLS certificates and private key permissions.
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
class SslCertsResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class SslCertsModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> SslCertsResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        find_cmd = self.config.tool_bin("find", "find")
        cr_find = await self.context.runner.run(find_cmd, ["/etc/ssl/private", "-type", "f"], timeout_seconds=10)

        private_keys = []
        if cr_find.succeeded and cr_find.stdout.strip():
            private_keys = cr_find.stdout.strip().splitlines()

        stat_cmd = self.config.tool_bin("stat", "stat")
        open_keys = []
        for key_path in private_keys:
            cr_s = await self.context.runner.run(stat_cmd, ["-c", "%a %U", key_path], timeout_seconds=5)
            if cr_s.succeeded and cr_s.stdout.strip():
                parts = cr_s.stdout.strip().split()
                perms = parts[0] if len(parts) >= 1 else ""
                if perms and int(perms) > 640:
                    open_keys.append(f"{key_path} ({perms})")

        if open_keys:
            findings.append(make_finding(
                title="SSL/TLS private keys have insecure permissions",
                description="Private key files under /etc/ssl/private are readable by unauthorized local accounts, exposing secret cryptographic materials.",
                severity="high",
                category="permissions",
                source_stage="crypto_security",
                target=target_str,
                evidence="\n".join(open_keys),
                recommendation="Set restrictive permissions (600 or 640) on private key files.",
                confidence=0.95,
            ))

        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_openssl = await self.context.runner.run(cat_cmd, ["/etc/ssl/openssl.cnf"], timeout_seconds=5)

        if cr_openssl.succeeded and cr_openssl.stdout.strip():
            content = cr_openssl.stdout
            if "MinProtocol = TLSv1" in content or "MinProtocol = SSL" in content:
                findings.append(make_finding(
                    title="OpenSSL configured with legacy TLS/SSL protocol support",
                    description="OpenSSL system-wide configuration permits legacy protocols like TLS 1.0, TLS 1.1, or SSLv3, exposing clients to protocol downgrade attacks.",
                    severity="medium",
                    category="misconfiguration",
                    source_stage="crypto_security",
                    target=target_str,
                    evidence="MinProtocol configured to TLSv1 or lower",
                    recommendation="Set MinProtocol = TLSv1.2 or MinProtocol = TLSv1.3 in /etc/ssl/openssl.cnf.",
                    confidence=0.9,
                ))

        primary = cr_find or cr_openssl or self._empty_command_result()

        result = SslCertsResult(
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
            command="ssl_certs",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="ssl_certs",
        )
