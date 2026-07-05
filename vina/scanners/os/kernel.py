"""OS-level kernel security audit stage.

Checks kernel version, loaded modules, ASLR status,
ptrace scope, and sysctl security settings.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...models.findings import Finding, make_finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SysctlSetting:
    key: str
    value: str
    secure: bool | None = None


@dataclass(slots=True)
class LoadedKernelModule:
    name: str
    size: str = ""
    used_by: str = ""


@dataclass(slots=True)
class KernelResult:
    target: TargetInput
    command_result: CommandResult
    kernel_version: str = ""
    kernel_release: str = ""
    loaded_modules: list[LoadedKernelModule] = field(default_factory=list)
    sysctl_settings: list[SysctlSetting] = field(default_factory=list)
    aslr_enabled: bool | None = None
    ptrace_scope: str = ""
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


_SECURITY_SYSCTLS = {
    "kernel.randomize_va_space": ("ASLR", "2", "kernel address space layout randomization is enabled"),
    "kernel.yama.ptrace_scope": (
        "ptrace",
        "1",
        "ptrace scope is restricted (non-root users cannot ptrace non-child processes)",
    ),
    "net.ipv4.conf.all.rp_filter": ("RP filter", "1", "reverse path filtering is enabled"),
    "net.ipv4.conf.default.rp_filter": ("RP filter", "1", "reverse path filtering is enabled"),
    "net.ipv4.tcp_syncookies": ("SYN cookies", "1", "TCP SYN cookies are enabled"),
    "net.ipv4.ip_forward": ("IP forwarding", "0", "IP forwarding is disabled"),
    "net.ipv6.conf.all.forwarding": ("IPv6 forwarding", "0", "IPv6 forwarding is disabled"),
    "net.ipv4.conf.all.accept_redirects": ("accept redirects", "0", "ICMP redirect acceptance is disabled"),
    "net.ipv4.conf.all.send_redirects": ("send redirects", "0", "ICMP redirect sending is disabled"),
    "kernel.kptr_restrict": ("kptr restrict", "1", "kernel pointer exposure is restricted"),
    "kernel.dmesg_restrict": ("dmesg restrict", "1", "kernel log access is restricted to root"),
}


class KernelModule:
    """Audit kernel security settings on the local host."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> KernelResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        sysctl_keys = list(_SECURITY_SYSCTLS.keys())

        commands: list[tuple[str, str, list[str]]] = [
            ("uname_r", self.config.tool_bin("uname", "uname"), ["-r"]),
            ("uname_s", self.config.tool_bin("uname", "uname"), ["-s"]),
            ("uname_m", self.config.tool_bin("uname", "uname"), ["-m"]),
            ("lsmod", self.config.tool_bin("lsmod", "lsmod"), []),
            ("sysctl_aslr", self.config.tool_bin("sysctl", "sysctl"), ["-n", "kernel.randomize_va_space"]),
            ("sysctl_ptrace", self.config.tool_bin("sysctl", "sysctl"), ["-n", "kernel.yama.ptrace_scope"]),
        ]
        # Add security sysctl queries
        for key in sysctl_keys:
            safe = key.replace(".", "_").replace("/", "_")
            commands.append((f"sysctl_{safe}", self.config.tool_bin("sysctl", "sysctl"), ["-n", key]))

        results: dict[str, CommandResult] = {}
        for name, executable, args in commands:
            cr = await self.context.runner.run(executable, args, timeout_seconds=self.context.timeout_seconds)
            results[name] = cr
            if cr.missing_executable:
                warnings.append(f"Missing executable: {executable}")
            if cr.timed_out:
                warnings.append(f"{name} timed out after {self.context.timeout_seconds}s")
            if cr.returncode not in (0, None) and not cr.timed_out and not cr.missing_executable:
                warnings.append(f"{name} exited with code {cr.returncode}")

        findings: list[Finding] = []
        target_str = target_input.normalized

        kernel_version = self._stdout_or_none(results.get("uname_s")) or ""
        kernel_release = self._stdout_or_none(results.get("uname_r")) or ""
        modules = self._parse_modules(results)
        sysctl_settings = self._parse_sysctl(results, findings, target_str)
        aslr_val = self._stdout_or_none(results.get("sysctl_aslr"))
        aslr_enabled = aslr_val == "2" if aslr_val else None
        ptrace_val = self._stdout_or_none(results.get("sysctl_ptrace")) or ""

        if kernel_release:
            findings.append(
                make_finding(
                    title=f"Kernel: {kernel_release}",
                    description=f"Running kernel version {kernel_release}",
                    severity="info",
                    category="system",
                    source_stage="kernel",
                    target=target_str,
                    evidence=f"kernel={kernel_release} arch={self._stdout_or_none(results.get('uname_m')) or ''}",
                )
            )

        if aslr_enabled is not None:
            if aslr_enabled:
                findings.append(
                    make_finding(
                        title="ASLR is enabled",
                        description="Kernel address space layout randomization is enabled (value=2, full randomization)",
                        severity="info",
                        category="security_control",
                        source_stage="kernel",
                        target=target_str,
                        evidence="kernel.randomize_va_space=2",
                    )
                )
            else:
                findings.append(
                    make_finding(
                        title="ASLR is disabled",
                        description="Kernel address space layout randomization is disabled",
                        severity="high",
                        category="misconfiguration",
                        source_stage="kernel",
                        target=target_str,
                        evidence=f"kernel.randomize_va_space={aslr_val}",
                        recommendation="Enable ASLR: sysctl -w kernel.randomize_va_space=2",
                    )
                )

        if modules:
            suspicious = [
                m.name for m in modules if any(x in m.name.lower() for x in ("tcpdump", "nfs", "cifs", "vbox", "vmw"))
            ]
            for mod_name in suspicious:
                findings.append(
                    make_finding(
                        title=f"Potentially sensitive kernel module: {mod_name}",
                        description=f"Kernel module '{mod_name}' is loaded",
                        severity="low",
                        category="kernel_module",
                        source_stage="kernel",
                        target=target_str,
                        evidence=mod_name,
                        recommendation="Verify this module is needed for the system's purpose",
                    )
                )

        primary = results.get("uname_r") or results.get("lsmod") or self._empty_command_result()

        result = KernelResult(
            target=target_input,
            command_result=primary,
            kernel_version=kernel_version,
            kernel_release=kernel_release,
            loaded_modules=modules,
            sysctl_settings=sysctl_settings,
            aslr_enabled=aslr_enabled,
            ptrace_scope=ptrace_val,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    @staticmethod
    def _parse_modules(results: dict[str, CommandResult]) -> list[LoadedKernelModule]:
        modules: list[LoadedKernelModule] = []
        cr = results.get("lsmod")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return modules
        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Module"):
                continue
            parts = line.split()
            if len(parts) >= 3:
                modules.append(LoadedKernelModule(name=parts[0], size=parts[1], used_by=parts[2]))
        return modules

    def _parse_sysctl(
        self, results: dict[str, CommandResult], findings: list[Finding], target_str: str
    ) -> list[SysctlSetting]:
        settings: list[SysctlSetting] = []
        for key, (label, expected, description) in _SECURITY_SYSCTLS.items():
            safe = key.replace(".", "_").replace("/", "_")
            cr = results.get(f"sysctl_{safe}")
            if cr is None or not cr.succeeded:
                continue
            value = cr.stdout.strip()
            secure = value == expected
            settings.append(SysctlSetting(key=key, value=value, secure=secure))
            if not secure:
                findings.append(
                    make_finding(
                        title=f"{label}: {key}={value} (expected {expected})",
                        description=description.replace("is", "should be").replace("are", "should be")
                        if not secure
                        else description,
                        severity="medium" if not secure else "info",
                        category="security_control",
                        source_stage="kernel",
                        target=target_str,
                        evidence=f"sysctl {key}={value}",
                        recommendation=f"Set sysctl {key}={expected}: sysctl -w {key}={expected}",
                    )
                )
        return settings

    @staticmethod
    def _stdout_or_none(cr: CommandResult | None) -> str | None:
        if cr is None or not cr.succeeded:
            return None
        text = cr.stdout.strip()
        return text if text else None

    def _save_results(self, result: KernelResult) -> Path:
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "kernel_version": result.kernel_version,
            "kernel_release": result.kernel_release,
            "loaded_modules": [asdict(m) for m in result.loaded_modules],
            "sysctl_settings": [asdict(s) for s in result.sysctl_settings],
            "aslr_enabled": result.aslr_enabled,
            "ptrace_scope": result.ptrace_scope,
            "warnings": result.warnings,
            "findings": [f.to_dict() for f in result.findings],
        }
        return self.context.store.save("os/kernel.json", payload)

    def _print_summary(self, result: KernelResult) -> None:
        print("----------------------------------------")
        print("Kernel Audit")
        print("----------------------------------------")
        print(f"Kernel        : {result.kernel_release or 'N/A'}")
        print(f"Modules       : {len(result.loaded_modules)}")
        print(
            f"ASLR          : {'enabled' if result.aslr_enabled else 'disabled' if result.aslr_enabled is False else 'unknown'}"
        )
        print(f"Findings      : {len(result.findings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="kernel",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="kernel",
        )


__all__ = ["KernelModule", "KernelResult", "LoadedKernelModule", "SysctlSetting"]
