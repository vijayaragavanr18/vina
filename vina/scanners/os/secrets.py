"""OS-level secrets discovery stage.

Scans for sensitive files such as SSH keys, .env files, certificates,
private keys, and configuration files that may contain passwords or
API keys.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ...core.config import AppConfig
from ...core.runner import CommandResult, classify_command_error
from ...models.common import TargetInput
from ...models.findings import Finding, make_finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)

_KEY_FILE_PATTERNS = [
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ecdsa",
    "/root/.ssh/id_ed25519",
    "/root/.ssh/id_dsa",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/config",
]

_ENV_FILE_PATTERNS = [
    "/root/.env",
    "/root/.env.local",
    "/root/.env.production",
]

_CERT_FILE_PATTERNS = [
    "/etc/ssl/private/",
    "/etc/letsencrypt/live/",
]

_PASSWORD_PATTERNS = [
    re.compile(r"password\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"passwd\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"api_key\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"secret\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"token\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"aws_access_key_id\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"aws_secret_access_key\s*[=:]\s*\S+", re.IGNORECASE),
]

# Config files that commonly contain credentials
_CRED_CONFIG_FILES = [
    "/etc/mysql/my.cnf",
    "/etc/postgresql/",
    "/etc/nginx/",
    "/etc/apache2/",
    "/etc/httpd/",
    "/root/.my.cnf",
    "/root/.pgpass",
    "/root/.netrc",
]

# Generic patterns for finding sensitive files
_FIND_KEY_GLOB = ["*.pem", "*.key", "*.p12", "*.pfx", "*.ovpn"]


@dataclass(slots=True)
class SecretFile:
    path: str
    type: str
    permissions: str = ""
    size: int = 0
    content_snippet: str = ""
    contains_credential: bool = False


@dataclass(slots=True)
class SecretsResult:
    target: TargetInput
    command_result: CommandResult
    secret_files: list[SecretFile] = field(default_factory=list)
    key_files: list[str] = field(default_factory=list)
    env_files: list[str] = field(default_factory=list)
    cert_files: list[str] = field(default_factory=list)
    credential_files: list[str] = field(default_factory=list)
    total_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class SecretsModule:
    """Discover secrets and sensitive files on the local host."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> SecretsResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("ls_ssh", self.config.tool_bin("ls", "ls"), ["-la", "/root/.ssh/"]),
            ("cat_ssh_id_rsa", self.config.tool_bin("cat", "cat"), ["/root/.ssh/id_rsa"]),
            ("cat_ssh_authorized", self.config.tool_bin("cat", "cat"), ["/root/.ssh/authorized_keys"]),
            ("cat_ssh_config", self.config.tool_bin("cat", "cat"), ["/root/.ssh/config"]),
            ("find_pem", self.config.tool_bin("find", "find"), ["/", "-name", "*.pem", "-type", "f"]),
            ("find_key", self.config.tool_bin("find", "find"), ["/", "-name", "*.key", "-type", "f"]),
            ("ls_ssl", self.config.tool_bin("ls", "ls"), ["-la", "/etc/ssl/private/"]),
            ("cat_mycnf", self.config.tool_bin("cat", "cat"), ["/root/.my.cnf"]),
            ("cat_netrc", self.config.tool_bin("cat", "cat"), ["/root/.netrc"]),
            ("cat_pgpass", self.config.tool_bin("cat", "cat"), ["/root/.pgpass"]),
            ("find_env", self.config.tool_bin("find", "find"), ["/", "-name", ".env", "-type", "f"]),
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

        findings: list[Finding] = []
        target_str = target_input.normalized

        secret_files, key_files, env_files, cert_files, cred_files = self._analyze(results, findings, target_str)

        if not secret_files:
            warnings.append("No secrets or sensitive files could be found (access may be restricted)")

        primary = (
            results.get("find_pem") or results.get("find_key") or results.get("ls_ssh") or self._empty_command_result()
        )

        result = SecretsResult(
            target=target_input,
            command_result=primary,
            secret_files=secret_files,
            key_files=key_files,
            env_files=env_files,
            cert_files=cert_files,
            credential_files=cred_files,
            total_count=len(secret_files),
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _analyze(
        self, results: dict[str, CommandResult], findings: list[Finding], target_str: str
    ) -> tuple[list[SecretFile], list[str], list[str], list[str], list[str]]:
        secret_files: list[SecretFile] = []
        key_files: list[str] = []
        env_files: list[str] = []
        cert_files: list[str] = []
        cred_files: list[str] = []

        # SSH keys
        for key_path in _KEY_FILE_PATTERNS:
            name = f"cat_{key_path.replace('/', '_')}"
            cr = results.get(name) if name in results else None
            if cr is None:
                # Try by basename
                basename = key_path.split("/")[-1]
                if basename == "id_rsa":
                    cr = results.get("cat_ssh_id_rsa")
                elif basename == "authorized_keys":
                    cr = results.get("cat_ssh_authorized")
                elif basename == "config":
                    cr = results.get("cat_ssh_config")
            if cr is not None and cr.succeeded and cr.stdout.strip():
                secret_files.append(SecretFile(path=key_path, type="ssh-key", content_snippet=cr.stdout.strip()[:100]))
                key_files.append(key_path)
                findings.append(
                    make_finding(
                        title=f"SSH key found: {key_path}",
                        description=f"Private SSH key or configuration file found at {key_path}",
                        severity="high",
                        category="secret",
                        source_stage="secrets",
                        target=target_str,
                        evidence=key_path,
                        recommendation=f"Protect {key_path} with strict permissions (chmod 600) and ensure it is encrypted",
                    )
                )

        # .env files
        cr_env = results.get("find_env")
        if cr_env and cr_env.succeeded and cr_env.stdout.strip():
            for line in cr_env.stdout.splitlines():
                path = line.strip()
                if path:
                    env_files.append(path)
                    secret_files.append(SecretFile(path=path, type="env-file"))
                    findings.append(
                        make_finding(
                            title=f".env file found: {path}",
                            description=f"Environment file found at {path} which may contain secrets",
                            severity="high",
                            category="secret",
                            source_stage="secrets",
                            target=target_str,
                            evidence=path,
                            recommendation="Ensure .env files are not accessible by unauthorized users and are excluded from version control",
                        )
                    )

        # .pem and .key files from find
        for find_cmd, ftype in [("find_pem", "pem-cert"), ("find_key", "private-key")]:
            cr = results.get(find_cmd)
            if cr and cr.succeeded and cr.stdout.strip():
                for line in cr.stdout.splitlines():
                    path = line.strip()
                    if path and not any(p in path for p in ("/proc/", "/sys/", "/dev/", "/run/")):
                        secret_files.append(SecretFile(path=path, type=ftype))
                        if ftype == "private-key":
                            key_files.append(path)
                        else:
                            cert_files.append(path)
                        sev = "high" if ftype == "private-key" else "medium"
                        findings.append(
                            make_finding(
                                title=f"{ftype}: {path}",
                                description=f"Found {ftype} file at {path}",
                                severity=sev,
                                category="secret",
                                source_stage="secrets",
                                target=target_str,
                                evidence=path,
                                recommendation=f"Protect {path} with appropriate permissions",
                            )
                        )

        # Credential config files
        for cred_file in _CRED_CONFIG_FILES:
            name = f"cat_{cred_file.replace('/', '_')}"
            cr = results.get(name)
            if cr is None:
                name = f"cat_{cred_file.split('/')[-1].replace('.', '_')}"
                cr = results.get(name)
            if cr is not None and cr.succeeded and cr.stdout.strip():
                content = cr.stdout.strip()
                secret_files.append(
                    SecretFile(
                        path=cred_file,
                        type="credential-config",
                        content_snippet=content[:100],
                        contains_credential=True,
                    )
                )
                cred_files.append(cred_file)
                # Check for credentials in content
                matches = self._find_credentials(content)
                if matches:
                    findings.append(
                        make_finding(
                            title=f"Credentials in config: {cred_file}",
                            description=f"Configuration file {cred_file} contains potential credentials",
                            severity="critical",
                            category="secret",
                            source_stage="secrets",
                            target=target_str,
                            evidence=cred_file,
                            recommendation=f"Remove hardcoded credentials from {cred_file}",
                        )
                    )

        return secret_files, key_files, env_files, cert_files, cred_files

    @staticmethod
    def _find_credentials(content: str) -> list[str]:
        matches: list[str] = []
        for pattern in _PASSWORD_PATTERNS:
            found = pattern.findall(content)
            matches.extend(found[:5])
        return matches

    def _save_results(self, result: SecretsResult) -> Path:
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "secret_files": [asdict(s) for s in result.secret_files],
            "key_files": result.key_files,
            "env_files": result.env_files,
            "cert_files": result.cert_files,
            "credential_files": result.credential_files,
            "total_count": result.total_count,
            "warnings": result.warnings,
            "findings": [f.to_dict() for f in result.findings],
        }
        return self.context.store.save("os/secrets.json", payload)

    def _print_summary(self, result: SecretsResult) -> None:
        print("----------------------------------------")
        print("Secrets Discovery")
        print("----------------------------------------")
        print(f"Secret Files   : {result.total_count}")
        print(f"  SSH Keys     : {len(result.key_files)}")
        print(f"  .env Files   : {len(result.env_files)}")
        print(f"  Certificates : {len(result.cert_files)}")
        print(f"  Credentials  : {len(result.credential_files)}")
        print(f"Findings       : {len(result.findings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="secrets",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="secrets",
        )


__all__ = ["SecretFile", "SecretsModule", "SecretsResult"]
