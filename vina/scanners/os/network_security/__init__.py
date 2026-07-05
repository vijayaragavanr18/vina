"""Network Stack, Services, and Firewall Security Stage for VINA.

PS-04: Comprehensive network auditing. Orchestrated as a single
stage that delegates to modular sub-scanners.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding
from ....modules.common import ModuleContext
from .dns import DnsModule, DnsResult
from .firewall import FirewallModule, FirewallResult
from .listening_services import ListeningServicesModule, ListeningServicesResult
from .routing import RoutingModule, RoutingResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NetworkSecurityResult:
    """Aggregate result from all network-security sub-scanners."""

    target: TargetInput
    command_result: CommandResult
    firewall: FirewallResult | None = None
    routing: RoutingResult | None = None
    dns: DnsResult | None = None
    listening_services: ListeningServicesResult | None = None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class NetworkSecurityModule:
    """Orchestrate all network security audits."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> NetworkSecurityResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        firewall_mod = FirewallModule(self.config, self.context)
        firewall_res = await firewall_mod.run(target_input)
        findings.extend(firewall_res.findings)
        warnings.extend(firewall_res.warnings)

        routing_mod = RoutingModule(self.config, self.context)
        routing_res = await routing_mod.run(target_input)
        findings.extend(routing_res.findings)
        warnings.extend(routing_res.warnings)

        dns_mod = DnsModule(self.config, self.context)
        dns_res = await dns_mod.run(target_input)
        findings.extend(dns_res.findings)
        warnings.extend(dns_res.warnings)

        ls_mod = ListeningServicesModule(self.config, self.context)
        ls_res = await ls_mod.run(target_input)
        findings.extend(ls_res.findings)
        warnings.extend(ls_res.warnings)

        primary = (
            firewall_res.command_result
            or routing_res.command_result
            or dns_res.command_result
            or ls_res.command_result
            or self._empty_command_result()
        )

        result = NetworkSecurityResult(
            target=target_input,
            command_result=primary,
            firewall=firewall_res,
            routing=routing_res,
            dns=dns_res,
            listening_services=ls_res,
            findings=findings,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _save_results(self, result: NetworkSecurityResult) -> Path:
        payload: dict[str, Any] = {
            "target": result.target.normalized,
            "duration_seconds": result.execution_time_seconds,
            "findings": [f.to_dict() for f in result.findings],
            "warnings": result.warnings,
        }
        return self.context.store.save("os/network_security.json", payload)

    def _print_summary(self, result: NetworkSecurityResult) -> None:
        print("----------------------------------------")
        print("Network Security")
        print("----------------------------------------")
        print(f"Findings       : {len(result.findings)}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="network_security",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="network_security",
        )


__all__ = [
    "NetworkSecurityModule",
    "NetworkSecurityResult",
]
