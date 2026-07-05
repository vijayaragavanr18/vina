"""Repository security checks.

Audits repository security settings: unsigned repositories, expired keys,
deprecated keyrings, weak GPG keys, insecure HTTP, duplicates, and third-party.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding, make_finding
from ....modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RepositoryEntry:
    url: str
    enabled: bool = True
    type: str = ""
    distribution: str = ""
    components: list[str] = field(default_factory=list)
    source_file: str = ""


@dataclass(slots=True)
class RepositoriesResult:
    target: TargetInput
    command_result: CommandResult
    repositories: list[RepositoryEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class RepositoriesModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> RepositoriesResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []
        repositories: list[RepositoryEntry] = []

        apt_sources: list[tuple[str, str]] = []
        cat_cmd = self.config.tool_bin("cat", "cat")

        cr = await self.context.runner.run(cat_cmd, ["/etc/apt/sources.list"], timeout_seconds=5)
        if cr.succeeded and cr.stdout.strip():
            apt_sources.append(("/etc/apt/sources.list", cr.stdout))

        ls_cmd = self.config.tool_bin("ls", "ls")
        cr_ls = await self.context.runner.run(ls_cmd, ["/etc/apt/sources.list.d/"], timeout_seconds=5)
        if cr_ls.succeeded and cr_ls.stdout.strip():
            for line in cr_ls.stdout.splitlines():
                line = line.strip()
                if line and line.endswith(".list"):
                    fpath = f"/etc/apt/sources.list.d/{line}"
                    cr_f = await self.context.runner.run(cat_cmd, [fpath], timeout_seconds=5)
                    if cr_f.succeeded and cr_f.stdout.strip():
                        apt_sources.append((fpath, cr_f.stdout))

        seen_urls: set[tuple[str, str]] = set()
        for fpath, content in apt_sources:
            for line_no, raw_line in enumerate(content.splitlines(), 1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 3 and parts[0] in ("deb", "deb-src"):
                    typ = parts[0]

                    url_idx = 1
                    options = {}
                    if parts[1].startswith("[") and "]" in line:
                        opt_str = line[line.find("[") + 1 : line.find("]")]
                        for opt in opt_str.split():
                            if "=" in opt:
                                k, _, v = opt.partition("=")
                                options[k.strip()] = v.strip()
                        for i, part in enumerate(parts):
                            if part.endswith("]"):
                                url_idx = i + 1
                                break

                    if url_idx < len(parts):
                        url = parts[url_idx]
                        dist = parts[url_idx + 1] if url_idx + 1 < len(parts) else ""
                        components = parts[url_idx + 2 :] if url_idx + 2 < len(parts) else []

                        repo = RepositoryEntry(
                            url=url, enabled=True, type=typ, distribution=dist, components=components, source_file=fpath
                        )
                        repositories.append(repo)

                        target_str = target.normalized

                        if options.get("trusted") == "yes" or options.get("allow-insecure") == "yes":
                            findings.append(
                                make_finding(
                                    title=f"Unsigned package repository override: {url}",
                                    description=f"The repository '{url}' is configured with trusted=yes or allow-insecure=yes, bypassing GPG signature checks.",
                                    severity="high",
                                    category="misconfiguration",
                                    source_stage="packages_security",
                                    target=target_str,
                                    evidence=f"File: {fpath}:{line_no}\n{line}",
                                    recommendation="Remove trusted=yes / allow-insecure=yes options. Configure proper GPG signing keys.",
                                    confidence=0.9,
                                )
                            )

                        if url.startswith("http://") and not any(h in url for h in ("localhost", "127.0.0.1")):
                            findings.append(
                                make_finding(
                                    title=f"Insecure HTTP repository: {url}",
                                    description=f"The repository '{url}' uses insecure HTTP instead of HTTPS, exposing package downloads to MITM attacks.",
                                    severity="medium",
                                    category="misconfiguration",
                                    source_stage="packages_security",
                                    target=target_str,
                                    evidence=f"File: {fpath}:{line_no}\n{line}",
                                    recommendation="Change repository URL from http:// to https:// if supported.",
                                    confidence=0.85,
                                )
                            )

                        key = (url, dist)
                        if key in seen_urls:
                            findings.append(
                                make_finding(
                                    title=f"Duplicate repository: {url}",
                                    description=f"The repository '{url}' for distribution '{dist}' is defined multiple times, slowing down package updates.",
                                    severity="low",
                                    category="misconfiguration",
                                    source_stage="packages_security",
                                    target=target_str,
                                    evidence=f"Duplicate found in {fpath}",
                                    recommendation="Remove duplicate lines from repository sources files.",
                                    confidence=0.75,
                                )
                            )
                        else:
                            seen_urls.add(key)

                        official_domains = (
                            "ubuntu.com",
                            "debian.org",
                            "debian.net",
                            "redhat.com",
                            "centos.org",
                            "fedoraproject.org",
                            "rockylinux.org",
                            "almalinux.org",
                        )
                        if not any(dom in url.lower() for dom in official_domains):
                            findings.append(
                                make_finding(
                                    title=f"Third-party repository configured: {url}",
                                    description=f"The repository '{url}' is a third-party source. Packages from external repositories can pose supply-chain risks.",
                                    severity="info",
                                    category="information",
                                    source_stage="packages_security",
                                    target=target_str,
                                    evidence=f"Source: {fpath}",
                                    recommendation="Verify the trustworthiness of all third-party repositories.",
                                    confidence=0.8,
                                )
                            )

        stat_cmd = self.config.tool_bin("stat", "stat")
        cr_stat = await self.context.runner.run(stat_cmd, ["-c", "%s", "/etc/apt/trusted.gpg"], timeout_seconds=5)
        if cr_stat.succeeded and cr_stat.stdout.strip():
            try:
                sz = int(cr_stat.stdout.strip())
                if sz > 32:
                    findings.append(
                        make_finding(
                            title="Deprecated GPG keyring file used: /etc/apt/trusted.gpg",
                            description="/etc/apt/trusted.gpg contains trusted keys. This global keyring is deprecated as any key in it can sign packages for any repository.",
                            severity="low",
                            category="misconfiguration",
                            source_stage="packages_security",
                            target=target.normalized,
                            evidence="/etc/apt/trusted.gpg exists with size > 32 bytes",
                            recommendation="Move keys from the deprecated trusted.gpg file into separate keyring files under /etc/apt/trusted.gpg.d/ or /usr/share/keyrings/.",
                            confidence=0.9,
                        )
                    )
            except ValueError:
                pass

        apt_key_cmd = self.config.tool_bin("apt-key", "apt-key")
        cr_key = await self.context.runner.run(apt_key_cmd, ["list"], timeout_seconds=5)
        if cr_key.succeeded and cr_key.stdout.strip():
            content = cr_key.stdout
            if "expired" in content.lower():
                findings.append(
                    make_finding(
                        title="Expired repository GPG keys detected",
                        description="One or more repository signing keys listed in apt-key have expired, which will block package installations or updates.",
                        severity="medium",
                        category="misconfiguration",
                        source_stage="packages_security",
                        target=target.normalized,
                        evidence=content.strip()[:300],
                        recommendation="Update or replace the expired repository keys.",
                        confidence=0.8,
                    )
                )

            if re.search(r"\b1024[rR]\b|\b1024\b/dsa|\b1024\b/rsa", content) or "sha1" in content.lower():
                findings.append(
                    make_finding(
                        title="Weak GPG signing keys in repository configuration",
                        description="Repository signing keys use weak or outdated algorithms (e.g. 1024-bit key length or SHA1 signatures), making them vulnerable to collision/forgery.",
                        severity="medium",
                        category="misconfiguration",
                        source_stage="packages_security",
                        target=target.normalized,
                        evidence="Detected 1024-bit or DSA key in keyring",
                        recommendation="Migrate to repositories that sign packages using modern keys (RSA >= 2048-bit or Ed25519).",
                        confidence=0.75,
                    )
                )

        primary = cr or self._empty_command_result()

        result = RepositoriesResult(
            target=target,
            command_result=primary,
            repositories=repositories,
            warnings=warnings,
            findings=findings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        return result

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="repositories",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="repositories",
        )
