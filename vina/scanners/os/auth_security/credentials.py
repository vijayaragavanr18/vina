"""Credential exposure detection.

Scans for exposed credentials including API keys, SSH private keys,
cloud provider credentials, tokens, and configuration files with
hardcoded secrets.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding, make_finding
from ....modules.common import ModuleContext

logger = logging.getLogger(__name__)

_CREDENTIAL_PATTERNS: list[tuple[str, str, str, str]] = [
    ("aws_access_key", r"(?i)aws_access_key_id\s*[=:]\s*['\"]?[A-Z0-9]{16,40}", "high", "AWS Access Key"),
    ("aws_secret_key", r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}", "critical", "AWS Secret Key"),
    ("azure_client_secret", r"(?i)AZURE_CLIENT_SECRET\s*[=:]\s*['\"]?\S+", "critical", "Azure Client Secret"),
    ("azure_connection", r"(?i)AZURE_CONNECTION_STRING\s*[=:]\s*['\"]?\S+", "high", "Azure Connection String"),
    ("gcp_creds", r"(?i)GOOGLE_APPLICATION_CREDENTIALS\s*[=:]\s*['\"]?\S+", "critical", "GCP Credentials"),
    ("gcp_api_key", r"(?i)GCP_API_KEY\s*[=:]\s*['\"]?\S+", "high", "GCP API Key"),
    ("db_password", r"(?i)DB_PASSWORD\s*[=:]\s*['\"]?\S+", "critical", "Database Password"),
    (
        "db_url_with_pwd",
        r"(?i)(mysql|postgres|mongo|redis)://\S+:\S+@\S+",
        "critical",
        "Database URL (contains password)",
    ),
    ("api_key", r"(?i)api[_-]?key\s*[=:]\s*['\"]?\S{8,}", "high", "API Key"),
    ("api_token", r"(?i)api[_-]?token\s*[=:]\s*['\"]?\S{8,}", "high", "API Token"),
    ("secret_key", r"(?i)secret[_-]?key\s*[=:]\s*['\"]?\S{8,}", "high", "Secret Key"),
    ("password_var", r"(?i)password\s*[=:]\s*['\"]?\S{4,}", "high", "Password in variable"),
    ("token_var", r"(?i)token\s*[=:]\s*['\"]?\S{8,}", "high", "Token in variable"),
    ("slack_token", r"(?i)xox[baprs]-[0-9a-zA-Z-]{10,}", "critical", "Slack Token"),
    ("github_token", r"(?i)ghp_[A-Za-z0-9]{36}", "critical", "GitHub Personal Access Token"),
    ("gitlab_token", r"(?i)glpat-[A-Za-z0-9_-]{20,}", "critical", "GitLab Personal Access Token"),
    ("jwt_token", r"(?i)eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "high", "JWT Token"),
    ("pem_key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "critical", "Private Key"),
    ("pgp_private", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "critical", "PGP Private Key Block"),
]

_CREDENTIAL_SCAN_PATHS = [
    "/root/.env",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.profile",
    "/root/.netrc",
    "/root/.ssh/config",
    "/root/.aws/credentials",
    "/root/.aws/config",
    "/root/.azure/credentials",
    "/root/.config/gcloud/credentials",
    "/root/.kube/config",
    "/root/.docker/config.json",
    "/home/",
    "/etc/environment",
    "/etc/profile",
    "/etc/profile.d/",
    "/var/www/",
    "/opt/",
    "/srv/",
]

_CREDENTIAL_FILE_PATTERNS = [
    "*.env",
    "*.env.*",
    ".env",
    ".env.*",
    "credentials",
    "credentials.json",
    "*.credentials",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "config.json",
    "*.config",
    "secrets.yml",
    "secrets.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".gitconfig",
    ".netrc",
    "*.netrc",
]

_IGNORE_PATHS = ["/proc/", "/sys/", "/dev/", "/run/"]


@dataclass(slots=True)
class CredentialMatch:
    path: str
    pattern_name: str
    description: str
    severity: str
    snippet: str = ""


@dataclass(slots=True)
class CredentialsResult:
    target: TargetInput
    command_result: CommandResult
    matches: list[CredentialMatch] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class CredentialsModule:
    """Scan for exposed credentials on the filesystem."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> CredentialsResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []
        matches: list[CredentialMatch] = []

        cr = await self.context.runner.run(
            self.config.tool_bin("find", "find"),
            [
                "/",
                "-type",
                "f",
                "(",
                "-name",
                "*.env",
                "-o",
                "-name",
                "*.pem",
                "-o",
                "-name",
                "*.key",
                "-o",
                "-name",
                "credentials",
                "-o",
                "-name",
                "config.json",
                "-o",
                "-name",
                ".netrc",
                "-o",
                "-name",
                "*.credentials",
                "-o",
                "-name",
                ".env.*",
                "-o",
                "-name",
                "secrets.yml",
                "-o",
                "-name",
                "secrets.yaml",
                ")",
                "-maxdepth",
                "5",
                "2>/dev/null",
            ],
            timeout_seconds=self.context.timeout_seconds,
        )

        if cr.missing_executable:
            warnings.append("find not available for credential scanning")
        elif cr.timed_out:
            warnings.append("credential file find timed out")

        target_str = target_input.normalized

        if cr.succeeded and cr.stdout.strip():
            file_paths = [line.strip() for line in cr.stdout.splitlines() if line.strip()]
            for fpath in file_paths:
                if any(fpath.startswith(p) for p in _IGNORE_PATHS):
                    continue
                read_cr = await self.context.runner.run(self.config.tool_bin("cat", "cat"), [fpath], timeout_seconds=10)
                if read_cr.succeeded and read_cr.stdout.strip():
                    content = read_cr.stdout
                    for name, pattern, severity, desc in _CREDENTIAL_PATTERNS:
                        for m in re.finditer(pattern, content):
                            snippet = m.group()[:120]
                            matches.append(
                                CredentialMatch(
                                    path=fpath, pattern_name=name, description=desc, severity=severity, snippet=snippet
                                )
                            )

        if not matches:
            warnings.append("No credential exposures found")

        for c_match in matches:
            findings.append(
                make_finding(
                    title=f"Credential exposure: {c_match.description}",
                    description=f"Found potential {c_match.description} in {c_match.path}.",
                    severity=c_match.severity,
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target_str,
                    evidence=c_match.snippet,
                    recommendation=f"Remove the credential from {c_match.path}. Use a secrets manager or environment variables with restricted access.",
                    confidence=0.7 if c_match.severity != "critical" else 0.85,
                )
            )

        primary = cr or self._empty_command_result()

        result = CredentialsResult(
            target=target_input,
            command_result=primary,
            matches=matches,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        return result

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="credentials",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="credentials",
        )


__all__ = ["CredentialMatch", "CredentialsModule", "CredentialsResult"]
