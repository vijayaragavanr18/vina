"""Authentication, Access Control, and Privilege Management module for VINA.

PS-02: Comprehensive auth/security assessment.  Integrated as a single
``auth_security`` pipeline stage that delegates to specialised sub-scanners.
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
from .credentials import CredentialsModule, CredentialsResult
from .pam import PamModule, PamResult
from .password import PasswordModule, PasswordResult
from .polkit import PolkitModule, PolkitResult
from .privesc_enhanced import PrivescEnhancedModule, PrivescEnhancedResult
from .sessions import SessionsModule, SessionsResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AuthSecurityResult:
    """Aggregate result from all auth-security sub-scanners."""

    target: TargetInput
    command_result: CommandResult
    pam: PamResult | None = None
    password: PasswordResult | None = None
    credentials: CredentialsResult | None = None
    sessions: SessionsResult | None = None
    polkit: PolkitResult | None = None
    privesc_enhanced: PrivescEnhancedResult | None = None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0


class AuthSecurityModule:
    """Orchestrate all sub-scanners and collect their findings."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> AuthSecurityResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        pam_mod = PamModule(self.config, self.context)
        pam_res = await pam_mod.run(target_input)
        findings.extend(pam_res.findings)
        warnings.extend(pam_res.warnings)

        pwd_mod = PasswordModule(self.config, self.context)
        pwd_res = await pwd_mod.run(target_input)
        findings.extend(pwd_res.findings)
        warnings.extend(pwd_res.warnings)

        cred_mod = CredentialsModule(self.config, self.context)
        cred_res = await cred_mod.run(target_input)
        findings.extend(cred_res.findings)
        warnings.extend(cred_res.warnings)

        sess_mod = SessionsModule(self.config, self.context)
        sess_res = await sess_mod.run(target_input)
        findings.extend(sess_res.findings)
        warnings.extend(sess_res.warnings)

        polkit_mod = PolkitModule(self.config, self.context)
        polkit_res = await polkit_mod.run(target_input)
        findings.extend(polkit_res.findings)
        warnings.extend(polkit_res.warnings)

        pe_mod = PrivescEnhancedModule(self.config, self.context)
        pe_res = await pe_mod.run(target_input)
        findings.extend(pe_res.findings)
        warnings.extend(pe_res.warnings)

        primary = (
            pam_res.command_result
            or pwd_res.command_result
            or cred_res.command_result
            or sess_res.command_result
            or polkit_res.command_result
            or pe_res.command_result
            or self._empty_command_result()
        )

        result = AuthSecurityResult(
            target=target_input,
            command_result=primary,
            pam=pam_res,
            password=pwd_res,
            credentials=cred_res,
            sessions=sess_res,
            polkit=polkit_res,
            privesc_enhanced=pe_res,
            findings=findings,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _save_results(self, result: AuthSecurityResult) -> Path:
        payload: dict[str, Any] = {
            "target": result.target.normalized,
            "duration_seconds": result.execution_time_seconds,
            "findings": [f.to_dict() for f in result.findings],
            "warnings": result.warnings,
        }
        return self.context.store.save("os/auth_security.json", payload)

    def _print_summary(self, result: AuthSecurityResult) -> None:
        print("----------------------------------------")
        print("Auth Security")
        print("----------------------------------------")
        print(f"Findings       : {len(result.findings)}")
        if result.warnings:
            print(f"Warnings       : {len(result.warnings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="auth_security",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="auth_security",
        )


__all__ = [
    "AuthSecurityModule",
    "AuthSecurityResult",
]
