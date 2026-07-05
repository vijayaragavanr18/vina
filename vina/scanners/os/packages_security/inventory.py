"""Software Bill of Materials (SBOM) and Inventory compiler.

Compiles a structured SBOM with package versions, vendor, architecture,
installation source, and performs package End-of-Life (EOL) checks.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding, make_finding
from ....modules.common import ModuleContext
from .managers import SbomPackage
from .repositories import RepositoryEntry

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class InventoryResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class InventoryModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(
        self,
        target: TargetInput,
        packages: list[SbomPackage],
        repositories: list[RepositoryEntry]
    ) -> InventoryResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        sbom_packages = []
        for pkg in packages:
            sbom_packages.append({
                "name": pkg.name,
                "version": pkg.version,
                "manager": pkg.manager,
                "architecture": pkg.architecture,
                "vendor": pkg.vendor,
                "installation_source": pkg.installation_source,
            })

            if pkg.name == "openssl" and pkg.version.startswith("1.1."):
                findings.append(make_finding(
                    title="End-of-Life (EOL) Software: OpenSSL 1.1.1",
                    description="OpenSSL 1.1.1 has reached its End of Life (EOL) and no longer receives security updates.",
                    severity="high",
                    category="vulnerability",
                    source_stage="packages_security",
                    target=target.normalized,
                    evidence=f"Installed version: {pkg.version}",
                    recommendation="Upgrade to OpenSSL 3.x.",
                    confidence=0.9,
                ))

            if pkg.name == "python3" and pkg.version:
                parts = pkg.version.split(".")
                if len(parts) >= 2:
                    try:
                        major = int(parts[0])
                        minor = int(parts[1])
                        if major == 3 and minor <= 8:
                            findings.append(make_finding(
                                title=f"End-of-Life (EOL) Software: Python {pkg.version}",
                                description=f"Python {pkg.version} has reached its End of Life (EOL) and no longer receives security updates.",
                                severity="medium",
                                category="vulnerability",
                                source_stage="packages_security",
                                target=target.normalized,
                                evidence=f"Installed version: {pkg.version}",
                                recommendation="Upgrade Python to version 3.9 or newer.",
                                confidence=0.85,
                            ))
                    except ValueError:
                        pass

        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_os = await self.context.runner.run(cat_cmd, ["/etc/os-release"], timeout_seconds=5)
        if cr_os.succeeded and cr_os.stdout.strip():
            content = cr_os.stdout
            if "ubuntu" in content.lower():
                for ver in ("14.04", "16.04", "18.04"):
                    if ver in content:
                        findings.append(make_finding(
                            title=f"End-of-Life (EOL) Operating System: Ubuntu {ver}",
                            description=f"The operating system Ubuntu {ver} is past its standard End of Life (EOL) date and does not receive public security updates.",
                            severity="critical",
                            category="vulnerability",
                            source_stage="packages_security",
                            target=target.normalized,
                            evidence=f"Ubuntu version {ver} detected",
                            recommendation="Upgrade the operating system to a supported LTS release (e.g. Ubuntu 22.04 LTS or 24.04 LTS).",
                            confidence=0.9,
                        ))

        payload: dict[str, Any] = {
            "target": target.normalized,
            "total_packages": len(packages),
            "packages": sbom_packages,
            "repositories": [
                {
                    "url": r.url,
                    "type": r.type,
                    "distribution": r.distribution,
                    "components": r.components,
                    "source_file": r.source_file
                }
                for r in repositories
            ]
        }
        self.context.store.save("os/sbom.json", payload)

        primary = cr_os or self._empty_command_result()

        result = InventoryResult(
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
            command="inventory",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="inventory",
        )
