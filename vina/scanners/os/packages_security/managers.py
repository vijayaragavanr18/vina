"""Package Managers discovery and package parsing.

Audits installed package managers (apt, dpkg, rpm, dnf, yum, zypper,
snap, flatpak, pip, npm, cargo, gem, go) and retrieves installed packages.
"""

from __future__ import annotations

import json
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
class SbomPackage:
    name: str
    version: str
    manager: str
    architecture: str = ""
    vendor: str = ""
    installation_source: str = ""


@dataclass(slots=True)
class PackageManagersResult:
    target: TargetInput
    command_result: CommandResult
    packages: list[SbomPackage] = field(default_factory=list)
    managers_found: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class PackageManagersModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> PackageManagersResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []
        packages: list[SbomPackage] = []
        managers_found: list[str] = []

        commands = {
            "dpkg": (
                self.config.tool_bin("dpkg-query", "dpkg-query"),
                ["-W", "-f=${Package}\t${Version}\t${Architecture}\t${Maintainer}\n"],
            ),
            "rpm": (
                self.config.tool_bin("rpm", "rpm"),
                ["-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{ARCH}\t%{VENDOR}\n"],
            ),
            "snap": (self.config.tool_bin("snap", "snap"), ["list"]),
            "flatpak": (
                self.config.tool_bin("flatpak", "flatpak"),
                ["list", "--columns=application,version,arch,origin"],
            ),
            "pip": (self.config.tool_bin("pip", "pip"), ["list", "--format=json"]),
            "npm": (self.config.tool_bin("npm", "npm"), ["list", "-g", "--depth=0", "--json"]),
            "cargo": (self.config.tool_bin("cargo", "cargo"), ["install", "--list"]),
            "gem": (self.config.tool_bin("gem", "gem"), ["list", "--local"]),
            "go": (self.config.tool_bin("go", "go"), ["version"]),
        }

        results: dict[str, CommandResult] = {}
        for name, (executable, args) in commands.items():
            cr = await self.context.runner.run(executable, args, timeout_seconds=self.context.timeout_seconds)
            results[name] = cr

        dpkg_cr = results.get("dpkg")
        if dpkg_cr and dpkg_cr.succeeded and dpkg_cr.stdout.strip():
            managers_found.append("dpkg")
            for line in dpkg_cr.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1]
                    arch = parts[2] if len(parts) > 2 else ""
                    vendor = parts[3] if len(parts) > 3 else ""
                    packages.append(
                        SbomPackage(
                            name=name,
                            version=version,
                            manager="dpkg",
                            architecture=arch,
                            vendor=vendor,
                            installation_source="system",
                        )
                    )

        rpm_cr = results.get("rpm")
        if rpm_cr and rpm_cr.succeeded and rpm_cr.stdout.strip():
            managers_found.append("rpm")
            for line in rpm_cr.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1]
                    arch = parts[2] if len(parts) > 2 else ""
                    vendor = parts[3] if len(parts) > 3 else ""
                    packages.append(
                        SbomPackage(
                            name=name,
                            version=version,
                            manager="rpm",
                            architecture=arch,
                            vendor=vendor,
                            installation_source="system",
                        )
                    )

        snap_cr = results.get("snap")
        if snap_cr and snap_cr.succeeded and snap_cr.stdout.strip():
            managers_found.append("snap")
            for line in snap_cr.stdout.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2:
                    packages.append(
                        SbomPackage(
                            name=parts[0], version=parts[1], manager="snap", installation_source="canonical-snap-store"
                        )
                    )

        flat_cr = results.get("flatpak")
        if flat_cr and flat_cr.succeeded and flat_cr.stdout.strip():
            managers_found.append("flatpak")
            for line in flat_cr.stdout.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2:
                    packages.append(
                        SbomPackage(
                            name=parts[0],
                            version=parts[1],
                            manager="flatpak",
                            architecture=parts[2] if len(parts) > 2 else "",
                            installation_source=parts[3] if len(parts) > 3 else "flatpak-repo",
                        )
                    )

        pip_cr = results.get("pip")
        if pip_cr and pip_cr.succeeded and pip_cr.stdout.strip():
            managers_found.append("pip")
            try:
                data = json.loads(pip_cr.stdout)
                for item in data:
                    packages.append(
                        SbomPackage(
                            name=item.get("name", ""),
                            version=item.get("version", ""),
                            manager="pip",
                            installation_source="pypi",
                        )
                    )
            except json.JSONDecodeError:
                for line in pip_cr.stdout.splitlines()[2:]:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        packages.append(
                            SbomPackage(name=parts[0], version=parts[1], manager="pip", installation_source="pypi")
                        )

        npm_cr = results.get("npm")
        if npm_cr and npm_cr.succeeded and npm_cr.stdout.strip():
            managers_found.append("npm")
            try:
                data = json.loads(npm_cr.stdout)
                deps = data.get("dependencies", {})
                for name, dep_info in deps.items():
                    packages.append(
                        SbomPackage(
                            name=name,
                            version=dep_info.get("version", "unknown"),
                            manager="npm",
                            installation_source="npm-registry",
                        )
                    )
            except json.JSONDecodeError:
                pass

        cargo_cr = results.get("cargo")
        if cargo_cr and cargo_cr.succeeded and cargo_cr.stdout.strip():
            managers_found.append("cargo")
            for line in cargo_cr.stdout.splitlines():
                if line.strip().endswith(":"):
                    continue
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1].startswith("v"):
                    packages.append(
                        SbomPackage(
                            name=parts[0], version=parts[1][1:], manager="cargo", installation_source="crates.io"
                        )
                    )

        gem_cr = results.get("gem")
        if gem_cr and gem_cr.succeeded and gem_cr.stdout.strip():
            managers_found.append("gem")
            for line in gem_cr.stdout.splitlines():
                if "(" in line:
                    name, _, rest = line.partition(" ")
                    version = rest.strip("()").split(",")[0]
                    packages.append(
                        SbomPackage(
                            name=name.strip(), version=version.strip(), manager="gem", installation_source="rubygems"
                        )
                    )

        go_cr = results.get("go")
        if go_cr and go_cr.succeeded:
            managers_found.append("go")

        primary = next((cr for cr in results.values() if cr.succeeded), self._empty_command_result())

        target_str = target.normalized
        for mgr in managers_found:
            findings.append(
                make_finding(
                    title=f"Package manager active: {mgr}",
                    description=f"The package manager '{mgr}' is installed and active on the system.",
                    severity="info",
                    category="information",
                    source_stage="packages_security",
                    target=target_str,
                    evidence=f"Active package manager: {mgr}",
                    confidence=0.9,
                )
            )

        result = PackageManagersResult(
            target=target,
            command_result=primary,
            packages=packages,
            managers_found=managers_found,
            warnings=warnings,
            findings=findings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        return result

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="managers",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="managers",
        )
