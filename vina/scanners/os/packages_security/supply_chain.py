"""Supply Chain security assessments.

Detects typosquatting indicators, suspicious repositories, local/manual packages,
manually installed binaries, and untrusted installers.
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
from .managers import SbomPackage

logger = logging.getLogger(__name__)

_POPULAR_PACKAGES = {
    "requests", "urllib3", "numpy", "pandas", "ansible", "cryptography",
    "jinja2", "pytest", "scipy", "docker", "boto3", "yaml", "pip",
    "lodash", "react", "express", "request", "chalk", "commander", "async",
    "debug", "axios", "typescript", "vue", "npm", "webpack",
    "cargo", "serde", "tokio", "rand", "syn", "quote", "libc", "log",
    "openssl", "openssh", "sudo", "systemd", "bash", "curl", "wget", "git"
}


def _levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


@dataclass(slots=True)
class SupplyChainResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class SupplyChainModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput, packages: list[SbomPackage]) -> SupplyChainResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        for pkg in packages:
            name_lower = pkg.name.lower()
            if name_lower in _POPULAR_PACKAGES:
                continue
            for pop_pkg in _POPULAR_PACKAGES:
                dist = _levenshtein_distance(name_lower, pop_pkg)
                if len(name_lower) > 3 and 0 < dist <= 2:
                    findings.append(make_finding(
                        title=f"Potential typosquatting package: {pkg.name}",
                        description=f"The package '{pkg.name}' (manager: {pkg.manager}) is very similar to popular package '{pop_pkg}'.",
                        severity="high",
                        category="vulnerability",
                        source_stage="packages_security",
                        target=target.normalized,
                        evidence=f"Installed: {pkg.name}={pkg.version} (similarity to {pop_pkg})",
                        recommendation=f"Verify if '{pkg.name}' is legitimate or a typosquatted malicious package.",
                        confidence=0.8,
                    ))
                    break

        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_sources = await self.context.runner.run(cat_cmd, ["/etc/apt/sources.list"], timeout_seconds=5)
        sources_content = cr_sources.stdout if cr_sources.succeeded else ""

        suspicious_tlds = (".xyz", ".club", ".info", ".ru", ".cn", "hopto.org", "no-ip.org", "dyndns.org")
        for line in sources_content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                for tld in suspicious_tlds:
                    if tld in line.lower():
                        findings.append(make_finding(
                            title="Suspicious repository TLD/domain detected",
                            description=f"A package repository uses a suspicious domain/TLD ({tld}): {line[:120]}",
                            severity="high",
                            category="misconfiguration",
                            source_stage="packages_security",
                            target=target.normalized,
                            evidence=line,
                            recommendation="Remove the suspicious repository from sources configuration.",
                            confidence=0.85,
                        ))
                        break

        ls_cmd = self.config.tool_bin("ls", "ls")
        cr_usr_local = await self.context.runner.run(ls_cmd, ["/usr/local/bin/"], timeout_seconds=5)
        if cr_usr_local.succeeded and cr_usr_local.stdout.strip():
            binaries = [b.strip() for b in cr_usr_local.stdout.splitlines() if b.strip()]
            untracked = []
            dpkg_query = self.config.tool_bin("dpkg", "dpkg")
            for b in binaries[:10]:
                fpath = f"/usr/local/bin/{b}"
                cr_check = await self.context.runner.run(dpkg_query, ["-S", fpath], timeout_seconds=3)
                if not cr_check.succeeded:
                    untracked.append(fpath)
            if untracked:
                findings.append(make_finding(
                    title=f"Manually installed binaries in system path ({len(untracked)} found)",
                    description="Binaries in /usr/local/bin are not tracked by the system package manager. These manually installed binaries do not receive automatic security updates.",
                    severity="low",
                    category="misconfiguration",
                    source_stage="packages_security",
                    target=target.normalized,
                    evidence="Untracked binaries:\n" + "\n".join(untracked[:5]),
                    recommendation="Ensure manually installed binaries are audited, updated regularly, or replaced with managed packages.",
                    confidence=0.9,
                ))

        history_files = ["/root/.bash_history", "/root/.zsh_history"]
        for hist in history_files:
            cr_hist = await self.context.runner.run(cat_cmd, [hist], timeout_seconds=5)
            if cr_hist.succeeded and cr_hist.stdout.strip():
                content = cr_hist.stdout
                matches = re.findall(r'(curl\s+.*?\|\s*(?:bash|sh|zsh))|(wget\s+.*?\|\s*(?:bash|sh|zsh))', content, re.IGNORECASE)
                if matches:
                    matched_lines = [m[0] or m[1] for m in matches[:5]]
                    findings.append(make_finding(
                        title="Untrusted shell installer command execution detected",
                        description="Execution of piped shell installer scripts (e.g. 'curl | bash') was found in user history. This pattern bypasses package manager safeguards.",
                        severity="medium",
                        category="misconfiguration",
                        source_stage="packages_security",
                        target=target.normalized,
                        evidence="Installer commands found:\n" + "\n".join(matched_lines),
                        recommendation="Avoid running installer scripts directly from the internet. Download, inspect, and execute locally, or prefer package repositories.",
                        confidence=0.85,
                    ))
                    break

        primary = cr_sources or cr_usr_local or self._empty_command_result()

        result = SupplyChainResult(
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
            command="supply_chain",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="supply_chain",
        )
