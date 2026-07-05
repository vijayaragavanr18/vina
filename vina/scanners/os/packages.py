"""OS-level package audit stage.

Lists installed packages via dpkg, checks apt sources,
flags held packages and identifies potentially outdated packages.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...models.findings import Finding, make_finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)

_SENSITIVE_PACKAGES = (
    "openssh-server", "openssh-client", "docker.io", "docker-ce",
    "containerd", "kubelet", "kubectl", "kubeadm",
    "mysql-server", "postgresql", "mongodb", "redis-server",
    "nginx", "apache2", "httpd", "vsftpd", "proftpd",
    "samba", "nfs-kernel-server", "bind9", "dnsmasq",
    "telnetd", "telnet", "rsh-server", "rsh-client",
    "xinetd", "inetd",
)

_VULNERABLE_PACKAGES = {
    "openssl": ("openssl version", "1.1.1"),
    "bash": ("bash --version", "4.4"),
    "sudo": ("sudo --version", "1.8.31"),
    "libc6": ("ldd --version", "2.31"),
}


@dataclass(slots=True)
class InstalledPackage:
    name: str
    version: str
    architecture: str = ""
    status: str = ""
    held: bool = False


@dataclass(slots=True)
class AptSourceEntry:
    source: str
    enabled: bool = True
    type: str = ""


@dataclass(slots=True)
class PackagesResult:
    target: TargetInput
    command_result: CommandResult
    packages: list[InstalledPackage] = field(default_factory=list)
    apt_sources: list[AptSourceEntry] = field(default_factory=list)
    held_packages: list[str] = field(default_factory=list)
    total_count: int = 0
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class PackagesModule:
    """Audit installed packages and package sources."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> PackagesResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("dpkg_l", self.config.tool_bin("dpkg", "dpkg"), ["-l"]),
            ("apt_sources", self.config.tool_bin("cat", "cat"), ["/etc/apt/sources.list"]),
            ("apt_sources_d", self.config.tool_bin("ls", "ls"), ["/etc/apt/sources.list.d/"]),
            ("apt_mark", self.config.tool_bin("apt", "apt"), ["mark", "showhold"]),
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
                stderr_snippet = cr.stderr.strip()[:120] if cr.stderr.strip() else ""
                msg = f"{name} exited with code {cr.returncode}"
                if stderr_snippet:
                    msg += f": {stderr_snippet}"
                warnings.append(msg)

        findings: list[Finding] = []
        target_str = target_input.normalized

        packages = self._parse_packages(results, warnings, findings, target_str)
        apt_sources = self._parse_apt_sources(results, warnings, findings, target_str)
        held_packages = self._parse_held(results, warnings)

        if not packages:
            warnings.append("No package information could be collected")

        primary = results.get("dpkg_l") or results.get("apt_sources") or self._empty_command_result()

        result = PackagesResult(
            target=target_input,
            command_result=primary,
            packages=packages,
            apt_sources=apt_sources,
            held_packages=held_packages,
            total_count=len(packages),
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _parse_packages(self, results: dict[str, CommandResult], warnings: list[str], findings: list[Finding], target_str: str) -> list[InstalledPackage]:
        packages: list[InstalledPackage] = []
        cr = results.get("dpkg_l")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return packages

        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Desired") or line.startswith("|") or line.startswith("+++"):
                continue
            parts = line.split()
            if len(parts) >= 3:
                status = parts[0] if parts[0] in ("ii", "hi", "rc", "un", "pn") else ""
                if status not in ("ii", "hi"):
                    continue
                name = parts[1]
                version = parts[2] if len(parts) > 2 else ""
                arch = parts[3] if len(parts) > 3 else ""
                held = status == "hi"

                packages.append(InstalledPackage(name=name, version=version, architecture=arch, status=status, held=held))

                if name in _SENSITIVE_PACKAGES:
                    findings.append(make_finding(
                        title=f"Installed: {name} ({version})",
                        description=f"Sensitive package '{name}' version {version} is installed",
                        severity="info",
                        category="package",
                        source_stage="packages",
                        target=target_str,
                        evidence=f"{name}={version} arch={arch}",
                    ))

        return packages

    @staticmethod
    def _parse_apt_sources(results: dict[str, CommandResult], warnings: list[str], findings: list[Finding], target_str: str) -> list[AptSourceEntry]:
        entries: list[AptSourceEntry] = []
        cr = results.get("apt_sources")
        if cr and cr.succeeded and cr.stdout.strip():
            for line in cr.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 3 and parts[0] in ("deb", "deb-src"):
                    enabled = True
                    typ = parts[0]
                    entry = AptSourceEntry(source=" ".join(parts[1:]), enabled=enabled, type=typ)
                    entries.append(entry)
                    if any(u in line.lower() for u in ("unstable", "experimental", "testing", "sid")):
                        findings.append(make_finding(
                            title=f"Potentially unstable apt source: {line[:80]}",
                            description=f"APT source references an unstable distribution: {line[:120]}",
                            severity="medium",
                            category="misconfiguration",
                            source_stage="packages",
                            target=target_str,
                            evidence=line[:200],
                            recommendation="Avoid using unstable/testing repositories in production",
                        ))

        # Also check sources.list.d directory listing
        cr_d = results.get("apt_sources_d")
        if cr_d and cr_d.succeeded and cr_d.stdout.strip():
            for line in cr_d.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("total"):
                    entries.append(AptSourceEntry(source=f"/etc/apt/sources.list.d/{line}", enabled=True, type="file"))

        return entries

    @staticmethod
    def _parse_held(results: dict[str, CommandResult], warnings: list[str]) -> list[str]:
        cr = results.get("apt_mark")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return []
        return [line.strip() for line in cr.stdout.splitlines() if line.strip()]

    def _save_results(self, result: PackagesResult) -> Path:
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "packages": [asdict(p) for p in result.packages],
            "apt_sources": [asdict(s) for s in result.apt_sources],
            "held_packages": result.held_packages,
            "total_count": result.total_count,
            "warnings": result.warnings,
            "findings": [f.to_dict() for f in result.findings],
        }
        return self.context.store.save("os/packages.json", payload)

    def _print_summary(self, result: PackagesResult) -> None:
        print("----------------------------------------")
        print("Package Audit")
        print("----------------------------------------")
        print(f"Packages      : {result.total_count}")
        print(f"Sources       : {len(result.apt_sources)}")
        print(f"Held          : {len(result.held_packages)}")
        print(f"Findings      : {len(result.findings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(command="packages", args=(), returncode=1, stdout="", stderr="", duration_seconds=0.0, timed_out=False, missing_executable=False, full_command="packages")


__all__ = ["PackagesModule", "InstalledPackage", "AptSourceEntry", "PackagesResult"]
