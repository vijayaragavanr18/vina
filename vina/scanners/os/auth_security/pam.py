"""PAM (Pluggable Authentication Modules) configuration audit.

Reads /etc/pam.d/ files and analyses password quality, lockout policy,
password history, and module configuration.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from ....core.config import AppConfig
from ....core.runner import CommandResult
from ....models.common import TargetInput
from ....models.findings import Finding, make_finding
from ....modules.common import ModuleContext

logger = logging.getLogger(__name__)

_PAM_DIRS = ["/etc/pam.d", "/usr/share/pam-configs"]


@dataclass(slots=True)
class PamRule:
    """A single PAM rule line."""

    service: str
    type: str
    control: str
    module: str
    args: str = ""
    line: int = 0


@dataclass(slots=True)
class PamResult:
    target: TargetInput
    command_result: CommandResult
    rules: list[PamRule] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class PamModule:
    """Audit PAM configuration."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> PamResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        results: dict[str, CommandResult] = {}

        for d in _PAM_DIRS:
            name = f"ls_{d.replace('/', '_')}"
            cr = await self.context.runner.run(
                self.config.tool_bin("ls", "ls"), ["-la", d], timeout_seconds=self.context.timeout_seconds
            )
            results[name] = cr

        for d in _PAM_DIRS:
            cr_ls = results.get(f"ls_{d.replace('/', '_')}")
            if cr_ls is None or not cr_ls.stdout.strip():
                continue
            files = [
                line.split()[-1]
                for line in cr_ls.stdout.splitlines()
                if line.strip() and not line.startswith("total") and not line.startswith("d")
            ]
            for fname in files:
                fpath = f"{d}/{fname}"
                cr = await self.context.runner.run(
                    self.config.tool_bin("cat", "cat"), [fpath], timeout_seconds=self.context.timeout_seconds
                )
                results[f"cat_{d}_{fname}"] = cr

        for d in _PAM_DIRS:
            cr_ls = results.get(f"ls_{d.replace('/', '_')}")
            if cr_ls is None or not cr_ls.stdout.strip():
                continue
            files = [
                line.split()[-1]
                for line in cr_ls.stdout.splitlines()
                if line.strip() and not line.startswith("total") and not line.startswith("d")
            ]
            for fname in files:
                fpath = f"{d}/{fname}"
                cat_cr = results.get(f"cat_{d}_{fname}")
                if cat_cr is None or not cat_cr.succeeded or not cat_cr.stdout.strip():
                    continue
                rules = self._parse_pam_file(fname, cat_cr.stdout)
                self._audit_pam(rules, findings, target_input.normalized)

        primary = next((cr for cr in results.values() if cr.succeeded), self._empty_command_result())

        result = PamResult(
            target=target_input,
            command_result=primary,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        return result

    @staticmethod
    def _parse_pam_file(service: str, content: str) -> list[PamRule]:
        rules: list[PamRule] = []
        for line_no, raw in enumerate(content.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            t = parts[0]
            control = parts[1]
            module = parts[2]
            args = " ".join(parts[3:]) if len(parts) > 3 else ""
            rules.append(PamRule(service=service, type=t, control=control, module=module, args=args, line=line_no))
        return rules

    @staticmethod
    def _parse_pam_pwquality_args(args: str) -> dict[str, str]:
        opts: dict[str, str] = {}
        for part in args.split():
            if "=" in part:
                k, _, v = part.partition("=")
                opts[k.strip()] = v.strip()
        return opts

    @staticmethod
    def _audit_pam(rules: list[PamRule], findings: list[Finding], target: str) -> None:
        has_pwquality = False
        has_faillock = False
        has_pwhistory = False
        has_unix = False
        pwquality_retry: str | None = None
        pwquality_minlen: str | None = None
        pwquality_dcredit: str | None = None
        pwquality_ucredit: str | None = None
        faillock_deny: str | None = None
        faillock_unlock_time: str | None = None
        pwhistory_remember: str | None = None
        unix_sha512 = False
        unix_yescrypt = False

        for r in rules:
            if r.module in ("pam_pwquality.so", "pam_cracklib.so"):
                has_pwquality = True
                opts = PamModule._parse_pam_pwquality_args(r.args)
                pwquality_retry = opts.get("retry")
                pwquality_minlen = opts.get("minlen")
                pwquality_dcredit = opts.get("dcredit")
                pwquality_ucredit = opts.get("ucredit")
            if r.module == "pam_faillock.so":
                has_faillock = True
                opts = PamModule._parse_pam_pwquality_args(r.args)
                faillock_deny = opts.get("deny")
                faillock_unlock_time = opts.get("unlock_time")
            if r.module == "pam_tally2.so":
                has_faillock = True
                opts = PamModule._parse_pam_pwquality_args(r.args)
                faillock_deny = faillock_deny or opts.get("deny")
                faillock_unlock_time = faillock_unlock_time or opts.get("unlock_time")
            if r.module == "pam_pwhistory.so":
                has_pwhistory = True
                opts = PamModule._parse_pam_pwquality_args(r.args)
                pwhistory_remember = opts.get("remember")
            if r.module == "pam_unix.so":
                has_unix = True
                unix_sha512 = "sha512" in r.args
                unix_yescrypt = "yescrypt" in r.args

        if not has_pwquality:
            findings.append(
                make_finding(
                    title="PAM password quality module not configured",
                    description="pam_pwquality.so or pam_cracklib.so is not configured in PAM. "
                    "Password complexity requirements are not enforced.",
                    severity="medium",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target,
                    evidence="No pam_pwquality or pam_cracklib module found in PAM configuration",
                    recommendation="Add 'password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1' to /etc/pam.d/common-password",
                    confidence=0.85,
                )
            )

        if has_pwquality and pwquality_minlen and int(pwquality_minlen) < 14:
            findings.append(
                make_finding(
                    title="PAM password minimum length too short",
                    description=f"pam_pwquality minlen is set to {pwquality_minlen}, which is below the "
                    "recommended minimum of 14 characters.",
                    severity="medium",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target,
                    evidence=f"pam_pwquality minlen={pwquality_minlen}",
                    recommendation="Set minlen=14 in pam_pwquality configuration",
                    confidence=0.8,
                )
            )

        if not has_faillock:
            findings.append(
                make_finding(
                    title="PAM account lockout not configured",
                    description="pam_faillock.so or pam_tally2.so is not configured. "
                    "There is no account lockout policy for failed login attempts.",
                    severity="medium",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target,
                    evidence="No pam_faillock or pam_tally2 module found",
                    recommendation="Add pam_faillock.so configuration to /etc/pam.d/common-auth "
                    "with deny=5 unlock_time=900",
                    confidence=0.85,
                )
            )

        if not has_pwhistory:
            findings.append(
                make_finding(
                    title="PAM password history not configured",
                    description="pam_pwhistory.so is not configured. Password reuse is not restricted.",
                    severity="low",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target,
                    evidence="No pam_pwhistory module found",
                    recommendation="Add 'password requisite pam_pwhistory.so remember=5' to /etc/pam.d/common-password",
                    confidence=0.7,
                )
            )

        if has_unix and not unix_sha512 and not unix_yescrypt:
            findings.append(
                make_finding(
                    title="PAM password hashing algorithm is weak",
                    description="pam_unix.so is configured without sha512 or yescrypt. Passwords may be hashed with a weak algorithm.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target,
                    evidence="pam_unix.so without sha512/yescrypt",
                    recommendation="Add sha512 to pam_unix.so arguments in /etc/pam.d/common-password",
                    confidence=0.85,
                )
            )

        if has_faillock and faillock_deny:
            try:
                if int(faillock_deny) > 5:
                    findings.append(
                        make_finding(
                            title="PAM account lockout attempts threshold is too high",
                            description=f"PAM account lockout deny parameter is set to {faillock_deny} (recommended: <= 5).",
                            severity="medium",
                            category="misconfiguration",
                            source_stage="auth_security",
                            target=target,
                            evidence=f"deny={faillock_deny}",
                            recommendation="Set deny=5 or fewer in pam_faillock.so configuration",
                            confidence=0.8,
                        )
                    )
            except ValueError:
                pass

        if has_faillock and faillock_unlock_time:
            try:
                if int(faillock_unlock_time) < 900:
                    findings.append(
                        make_finding(
                            title="PAM account lockout unlock time is too short",
                            description=f"PAM account lockout unlock_time parameter is set to {faillock_unlock_time} seconds (recommended: >= 900).",
                            severity="low",
                            category="misconfiguration",
                            source_stage="auth_security",
                            target=target,
                            evidence=f"unlock_time={faillock_unlock_time}",
                            recommendation="Set unlock_time=900 or more in pam_faillock.so configuration",
                            confidence=0.8,
                        )
                    )
            except ValueError:
                pass

        if has_pwhistory and pwhistory_remember:
            try:
                if int(pwhistory_remember) < 5:
                    findings.append(
                        make_finding(
                            title="PAM password history size is too small",
                            description=f"PAM password history remember parameter is set to {pwhistory_remember} (recommended: >= 5).",
                            severity="low",
                            category="misconfiguration",
                            source_stage="auth_security",
                            target=target,
                            evidence=f"remember={pwhistory_remember}",
                            recommendation="Set remember=5 or more in pam_pwhistory.so configuration",
                            confidence=0.8,
                        )
                    )
            except ValueError:
                pass

        if has_pwquality and pwquality_retry:
            try:
                if int(pwquality_retry) > 3:
                    findings.append(
                        make_finding(
                            title="PAM password quality retry limit is too high",
                            description=f"PAM password quality retry parameter is set to {pwquality_retry} (recommended: <= 3).",
                            severity="low",
                            category="misconfiguration",
                            source_stage="auth_security",
                            target=target,
                            evidence=f"retry={pwquality_retry}",
                            recommendation="Set retry=3 or fewer in pam_pwquality.so configuration",
                            confidence=0.8,
                        )
                    )
            except ValueError:
                pass

        if has_pwquality:
            for cred_name, cred_val in [("dcredit", pwquality_dcredit), ("ucredit", pwquality_ucredit)]:
                if cred_val is not None:
                    try:
                        if int(cred_val) >= 0:
                            findings.append(
                                make_finding(
                                    title=f"PAM password complexity requirement ({cred_name}) is weak",
                                    description=f"PAM password quality {cred_name} parameter is set to {cred_val} (recommended: <= -1 to enforce complexity).",
                                    severity="medium",
                                    category="misconfiguration",
                                    source_stage="auth_security",
                                    target=target,
                                    evidence=f"{cred_name}={cred_val}",
                                    recommendation=f"Set {cred_name}=-1 in pam_pwquality.so configuration",
                                    confidence=0.8,
                                )
                            )
                    except ValueError:
                        pass

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="pam",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="pam",
        )


__all__ = ["PamModule", "PamResult", "PamRule"]
