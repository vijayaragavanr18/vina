"""Kernel hardening audit stage.

Checks sysctl security settings, Secure Boot, SELinux/AppArmor/seccomp
status, kernel module security, eBPF restrictions, namespace security,
and CPU vulnerability mitigations.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ...core.config import AppConfig
from ...core.runner import CommandResult
from ...models.common import TargetInput
from ...models.findings import Finding, make_finding
from ...modules.common import ModuleContext

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SysctlSecuritySetting:
    key: str
    value: str
    expected: str
    description: str
    secure: bool = False


@dataclass(slots=True)
class CpuMitigation:
    vulnerability: str
    status: str
    mitigated: bool | None = None


@dataclass(slots=True)
class KernelHardeningResult:
    target: TargetInput
    command_result: CommandResult
    sysctl_settings: list[SysctlSecuritySetting] = field(default_factory=list)
    secure_boot_active: bool | None = None
    selinux_enforcing: bool | None = None
    apparmor_enabled: bool | None = None
    seccomp_available: bool | None = None
    ebpf_restricted: bool | None = None
    user_ns_allowed: bool | None = None
    cpu_mitigations: list[CpuMitigation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


_SYSCTL_CHECKS: list[dict[str, str]] = [
    {"key": "kernel.randomize_va_space", "expected": "2", "label": "ASLR (full randomization)"},
    {"key": "kernel.kptr_restrict", "expected": "2", "label": "kernel pointer restriction"},
    {"key": "kernel.dmesg_restrict", "expected": "1", "label": "dmesg restriction"},
    {"key": "kernel.kexec_load_disabled", "expected": "1", "label": "kexec disabled"},
    {"key": "kernel.unprivileged_bpf_disabled", "expected": "1", "label": "unprivileged BPF disabled"},
    {"key": "net.core.bpf_jit_enable", "expected": "0", "label": "BPF JIT disabled"},
    {"key": "kernel.yama.ptrace_scope", "expected": "1", "label": "ptrace scope restricted"},
    {"key": "kernel.perf_event_paranoid", "expected": "3", "label": "perf events restricted"},
    {"key": "kernel.panic_on_oops", "expected": "1", "label": "panic on oops"},
    {"key": "user.max_user_namespaces", "expected": "0", "label": "user namespaces disabled"},
    {"key": "fs.protected_hardlinks", "expected": "1", "label": "hardlink protection"},
    {"key": "fs.protected_symlinks", "expected": "1", "label": "symlink protection"},
    {"key": "fs.suid_dumpable", "expected": "0", "label": "SUID dump disabled"},
    {"key": "kernel.core_uses_pid", "expected": "1", "label": "core dumps use PID"},
    {"key": "net.ipv4.ip_forward", "expected": "0", "label": "IPv4 forwarding disabled"},
    {"key": "net.ipv4.conf.all.send_redirects", "expected": "0", "label": "ICMP redirect sending disabled"},
    {"key": "net.ipv4.conf.default.send_redirects", "expected": "0", "label": "default ICMP redirect sending disabled"},
    {"key": "net.ipv4.conf.all.accept_redirects", "expected": "0", "label": "ICMP redirect acceptance disabled"},
    {"key": "net.ipv4.conf.all.secure_redirects", "expected": "0", "label": "secure ICMP redirects disabled"},
    {"key": "net.ipv4.conf.all.accept_source_route", "expected": "0", "label": "source route acceptance disabled"},
    {"key": "net.ipv6.conf.all.accept_redirects", "expected": "0", "label": "IPv6 redirect acceptance disabled"},
    {"key": "net.ipv4.conf.all.rp_filter", "expected": "1", "label": "reverse path filtering"},
    {"key": "net.ipv4.conf.default.rp_filter", "expected": "1", "label": "default reverse path filtering"},
    {"key": "net.ipv4.tcp_syncookies", "expected": "1", "label": "TCP SYN cookies"},
    {"key": "net.ipv4.conf.all.log_martians", "expected": "1", "label": "martian packet logging"},
]

_SUSPICIOUS_MODULES = [
    "bluetooth", "btusb", "firewire", "firewire_ohci", "firewire_sbp2",
    "pcan", "uvcvideo", "pcspkr", "snd_pcsp",
]

_MITIGATION_FILES = [
    "spectre_v1", "spectre_v2", "meltdown", "mds", "tsx_async_abort",
    "itlb_multihit", "mmio_stale_data", "retbleed", "srso",
    "gather_data_sampling", "l1tf", "srbds",
]


class KernelHardeningModule:
    """Audit kernel hardening controls on the local host."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> KernelHardeningResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []
        target_str = target_input.normalized

        commands = self._build_commands()
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

        sysctl_settings = self._check_sysctl(results, findings, target_str)
        secure_boot = self._check_secure_boot(results, findings, target_str)
        selinux = self._check_selinux(results, findings, target_str)
        apparmor = self._check_apparmor(results, findings, target_str)
        seccomp = self._check_seccomp(results, findings, target_str)
        ebpf = self._check_ebpf(results, findings, target_str, sysctl_settings)
        user_ns = self._check_user_namespaces(results, findings, target_str, sysctl_settings)
        mitigations = self._check_cpu_mitigations(results, findings, target_str)
        self._check_kernel_modules(results, findings, target_str)

        primary = results.get("uname_r") or self._empty_command_result()

        result = KernelHardeningResult(
            target=target_input,
            command_result=primary,
            sysctl_settings=sysctl_settings,
            secure_boot_active=secure_boot,
            selinux_enforcing=selinux,
            apparmor_enabled=apparmor,
            seccomp_available=seccomp,
            ebpf_restricted=ebpf,
            user_ns_allowed=user_ns,
            cpu_mitigations=mitigations,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    def _build_commands(self) -> list[tuple[str, str, list[str]]]:
        sysctl_keys = [c["key"] for c in _SYSCTL_CHECKS]
        commands: list[tuple[str, str, list[str]]] = [
            ("uname_r", self.config.tool_bin("uname", "uname"), ["-r"]),
        ]
        for key in sysctl_keys:
            safe = key.replace(".", "_").replace("/", "_")
            commands.append((f"sysctl_{safe}", self.config.tool_bin("sysctl", "sysctl"), ["-n", key]))
        commands.extend([
            ("mokutil", self.config.tool_bin("mokutil", "mokutil"), ["--sb-state"]),
            ("sestatus", self.config.tool_bin("sestatus", "sestatus"), []),
            ("getenforce", self.config.tool_bin("getenforce", "getenforce"), []),
            ("aa_status", self.config.tool_bin("aa-status", "aa-status"), []),
            ("apparmor_enabled", self.config.tool_bin("cat", "cat"), ["/sys/module/apparmor/parameters/enabled"]),
            ("lsmod", self.config.tool_bin("lsmod", "lsmod"), []),
        ])
        for vuln in _MITIGATION_FILES:
            path = f"/sys/devices/system/cpu/vulnerabilities/{vuln}"
            commands.append((f"mit_{vuln}", self.config.tool_bin("cat", "cat"), [path]))
        commands.append(
            ("boot_config", self.config.tool_bin("cat", "cat"), ["/proc/config.gz"])
        )
        return commands

    def _check_sysctl(
        self, results: dict[str, CommandResult], findings: list[Finding], target_str: str
    ) -> list[SysctlSecuritySetting]:
        settings: list[SysctlSecuritySetting] = []
        for check in _SYSCTL_CHECKS:
            key = check["key"]
            expected = check["expected"]
            label = check["label"]
            safe = key.replace(".", "_").replace("/", "_")
            cr = results.get(f"sysctl_{safe}")
            if cr is None or not cr.succeeded:
                continue
            value = cr.stdout.strip()
            secure = value == expected
            settings.append(SysctlSecuritySetting(key=key, value=value, expected=expected, description=label, secure=secure))
            if not secure:
                severity = "medium"
                rec = f"Set sysctl {key}={expected}: sysctl -w {key}={expected}"
                if key in ("kernel.randomize_va_space", "kernel.kptr_restrict", "kernel.dmesg_restrict") or key in ("kernel.kexec_load_disabled", "kernel.unprivileged_bpf_disabled"):
                    severity = "high"
                findings.append(
                    make_finding(
                        title=f"{label}: {key}={value} (expected {expected})",
                        description=f"Kernel security sysctl {key} is set to {value} instead of the recommended {expected}",
                        severity=severity,
                        category="misconfiguration",
                        source_stage="kernel_hardening",
                        target=target_str,
                        evidence=f"sysctl {key}={value}",
                        recommendation=rec,
                    )
                )
        return settings

    def _check_secure_boot(
        self, results: dict[str, CommandResult], findings: list[Finding], target_str: str
    ) -> bool | None:
        cr = results.get("mokutil")
        if cr is not None and cr.succeeded:
            output = cr.stdout.strip().lower()
            if "enabled" in output:
                findings.append(
                    make_finding(
                        title="Secure Boot is enabled",
                        description="UEFI Secure Boot is active, preventing unauthorized bootloaders and kernel modules from loading",
                        severity="info",
                        category="security_control",
                        source_stage="kernel_hardening",
                        target=target_str,
                        evidence=cr.stdout.strip(),
                    )
                )
                return True
            if "disabled" in output:
                findings.append(
                    make_finding(
                        title="Secure Boot is disabled",
                        description="UEFI Secure Boot is not active. This allows unsigned kernel modules and bootloaders to load",
                        severity="medium",
                        category="misconfiguration",
                        source_stage="kernel_hardening",
                        target=target_str,
                        evidence=cr.stdout.strip(),
                        recommendation="Enable Secure Boot in UEFI firmware settings",
                    )
                )
                return False
        return None

    def _check_selinux(
        self, results: dict[str, CommandResult], findings: list[Finding], target_str: str
    ) -> bool | None:
        cr = results.get("getenforce")
        if cr is not None and cr.succeeded:
            mode = cr.stdout.strip().lower()
            if mode == "enforcing":
                findings.append(
                    make_finding(
                        title="SELinux is enforcing",
                        description="SELinux mandatory access control is active and enforcing policy",
                        severity="info",
                        category="security_control",
                        source_stage="kernel_hardening",
                        target=target_str,
                        evidence=f"SELinux mode: {mode}",
                    )
                )
                return True
            if mode == "permissive":
                findings.append(
                    make_finding(
                        title="SELinux is in permissive mode",
                        description="SELinux is loaded but only logging violations, not enforcing policy",
                        severity="medium",
                        category="misconfiguration",
                        source_stage="kernel_hardening",
                        target=target_str,
                        evidence=f"SELinux mode: {mode}",
                        recommendation="Enable SELinux enforcing mode: setenforce 1 and update /etc/selinux/config",
                    )
                )
                return False
            if mode == "disabled":
                findings.append(
                    make_finding(
                        title="SELinux is disabled",
                        description="SELinux mandatory access control is completely disabled",
                        severity="high",
                        category="misconfiguration",
                        source_stage="kernel_hardening",
                        target=target_str,
                        evidence=f"SELinux mode: {mode}",
                        recommendation="Enable SELinux in kernel boot parameters and /etc/selinux/config",
                    )
                )
                return False
        return None

    def _check_apparmor(
        self, results: dict[str, CommandResult], findings: list[Finding], target_str: str
    ) -> bool | None:
        cr_enabled = results.get("apparmor_enabled")
        if cr_enabled is not None and cr_enabled.succeeded:
            enabled = cr_enabled.stdout.strip() == "Y"
            profiles = 0
            cr_status = results.get("aa_status")
            if cr_status is not None and cr_status.succeeded:
                for line in cr_status.stdout.splitlines():
                    if "profiles are loaded" in line or "profiles are in" in line:
                        import contextlib
                        with contextlib.suppress(ValueError, IndexError):
                            profiles = int(line.split()[0])
                        break
            if enabled:
                label = f"AppArmor is enabled with {profiles} profiles loaded" if profiles else "AppArmor is enabled"
                findings.append(
                    make_finding(
                        title="AppArmor is enabled",
                        description=label,
                        severity="info",
                        category="security_control",
                        source_stage="kernel_hardening",
                        target=target_str,
                        evidence=f"apparmor_enabled=Y profiles={profiles}",
                    )
                )
                return True
            findings.append(
                make_finding(
                    title="AppArmor is disabled",
                    description="AppArmor mandatory access control is not active",
                    severity="high",
                    category="misconfiguration",
                    source_stage="kernel_hardening",
                    target=target_str,
                    evidence="apparmor_enabled=N",
                    recommendation="Enable AppArmor: install apparmor-profiles and add 'apparmor=1 security=apparmor' to kernel cmdline",
                )
            )
            return False
        return None

    def _check_seccomp(
        self, results: dict[str, CommandResult], findings: list[Finding], target_str: str
    ) -> bool | None:
        cr = results.get("boot_config")
        if cr is not None and cr.succeeded:
            stdout = cr.stdout
            if isinstance(stdout, bytes) or self._looks_compressed(stdout):
                return None
            if "CONFIG_SECCOMP=y" in stdout and "CONFIG_SECCOMP_FILTER=y" in stdout:
                findings.append(
                    make_finding(
                        title="seccomp is available",
                        description="Kernel supports seccomp and seccomp-bpf syscall filtering",
                        severity="info",
                        category="security_control",
                        source_stage="kernel_hardening",
                        target=target_str,
                        evidence="CONFIG_SECCOMP=y CONFIG_SECCOMP_FILTER=y",
                    )
                )
                return True
            if "CONFIG_SECCOMP=y" in stdout:
                findings.append(
                    make_finding(
                        title="seccomp available without BPF filtering",
                        description="Kernel supports seccomp but seccomp-bpf (CONFIG_SECCOMP_FILTER) is not enabled",
                        severity="medium",
                        category="misconfiguration",
                        source_stage="kernel_hardening",
                        target=target_str,
                        evidence="CONFIG_SECCOMP=y CONFIG_SECCOMP_FILTER=n",
                        recommendation="Rebuild kernel with CONFIG_SECCOMP_FILTER=y for full seccomp support",
                    )
                )
                return True
            findings.append(
                make_finding(
                    title="seccomp is not available",
                    description="Kernel does not support seccomp syscall filtering",
                    severity="high",
                    category="misconfiguration",
                    source_stage="kernel_hardening",
                    target=target_str,
                    evidence="CONFIG_SECCOMP=n",
                    recommendation="Rebuild kernel with CONFIG_SECCOMP=y and CONFIG_SECCOMP_FILTER=y",
                )
            )
            return False
        return None

    @staticmethod
    def _looks_compressed(text: str) -> bool:
        return bool(text and not text[:1024].isprintable())

    def _check_ebpf(
        self, _results: dict[str, CommandResult], findings: list[Finding], target_str: str,
        sysctl_settings: list[SysctlSecuritySetting],
    ) -> bool | None:
        for s in sysctl_settings:
            if s.key == "kernel.unprivileged_bpf_disabled":
                restricted = s.value == "1"
                if restricted:
                    findings.append(
                        make_finding(
                            title="eBPF is restricted to privileged users",
                            description="Unprivileged BPF operations are disabled, preventing non-root eBPF-based attacks",
                            severity="info",
                            category="security_control",
                            source_stage="kernel_hardening",
                            target=target_str,
                            evidence="kernel.unprivileged_bpf_disabled=1",
                        )
                    )
                else:
                    findings.append(
                        make_finding(
                            title="eBPF is accessible to unprivileged users",
                            description="Unprivileged BPF operations are enabled, increasing kernel attack surface",
                            severity="high",
                            category="misconfiguration",
                            source_stage="kernel_hardening",
                            target=target_str,
                            evidence=f"kernel.unprivileged_bpf_disabled={s.value}",
                            recommendation="Set kernel.unprivileged_bpf_disabled=1: sysctl -w kernel.unprivileged_bpf_disabled=1",
                        )
                    )
                return restricted
        return None

    def _check_user_namespaces(
        self, _results: dict[str, CommandResult], findings: list[Finding], target_str: str,
        sysctl_settings: list[SysctlSecuritySetting],
    ) -> bool | None:
        for s in sysctl_settings:
            if s.key == "user.max_user_namespaces":
                allowed = s.value != "0"
                if allowed:
                    findings.append(
                        make_finding(
                            title="User namespaces are enabled",
                            description="User namespaces allow unprivileged users to create namespaces, expanding kernel attack surface",
                            severity="medium",
                            category="security_control",
                            source_stage="kernel_hardening",
                            target=target_str,
                            evidence=f"user.max_user_namespaces={s.value}",
                            recommendation="Consider setting user.max_user_namespaces=0 if container support is not needed",
                        )
                    )
                else:
                    findings.append(
                        make_finding(
                            title="User namespaces are disabled",
                            description="User namespaces are restricted, reducing kernel namespace attack surface",
                            severity="info",
                            category="security_control",
                            source_stage="kernel_hardening",
                            target=target_str,
                            evidence="user.max_user_namespaces=0",
                        )
                    )
                return allowed
        return None

    def _check_cpu_mitigations(
        self, results: dict[str, CommandResult], findings: list[Finding], target_str: str
    ) -> list[CpuMitigation]:
        mitigations: list[CpuMitigation] = []
        for vuln in _MITIGATION_FILES:
            cr = results.get(f"mit_{vuln}")
            if cr is None or not cr.succeeded:
                continue
            status = cr.stdout.strip()
            mitigated = None
            if "vulnerable" in status.lower():
                mitigated = False
            elif "mitigation" in status.lower() or "not affected" in status.lower():
                mitigated = True
            mitigations.append(CpuMitigation(vulnerability=vuln, status=status, mitigated=mitigated))
            if mitigated is False:
                severity = "high" if vuln in ("spectre_v2", "meltdown", "retbleed") else "medium"
                findings.append(
                    make_finding(
                        title=f"CPU vulnerable to {vuln}",
                        description=f"System is vulnerable to {vuln}: {status}",
                        severity=severity,
                        category="vulnerability",
                        source_stage="kernel_hardening",
                        target=target_str,
                        evidence=status,
                        recommendation=f"Update kernel/microcode and ensure mitigations=auto in kernel cmdline for {vuln}",
                    )
                )
        return mitigations

    def _check_kernel_modules(
        self, results: dict[str, CommandResult], findings: list[Finding], target_str: str
    ) -> None:
        cr = results.get("lsmod")
        if cr is None or not cr.succeeded:
            return
        loaded = set()
        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Module"):
                continue
            parts = line.split()
            if parts:
                loaded.add(parts[0].lower())
        for mod in _SUSPICIOUS_MODULES:
            if mod in loaded:
                findings.append(
                    make_finding(
                        title=f"Sensitive kernel module loaded: {mod}",
                        description=f"Kernel module '{mod}' is loaded. If not required, it increases kernel attack surface",
                        severity="low",
                        category="kernel_module",
                        source_stage="kernel_hardening",
                        target=target_str,
                        evidence=f"lsmod includes {mod}",
                        recommendation=f"Blacklist {mod}: echo 'blacklist {mod}' > /etc/modprobe.d/{mod}-blacklist.conf",
                    )
                )

    @staticmethod
    def _stdout_or_none(cr: CommandResult | None) -> str | None:
        if cr is None or not cr.succeeded:
            return None
        text = cr.stdout.strip()
        return text if text else None

    def _save_results(self, result: KernelHardeningResult) -> Path:
        payload: dict[str, Any] = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "sysctl_settings": [asdict(s) for s in result.sysctl_settings],
            "secure_boot_active": result.secure_boot_active,
            "selinux_enforcing": result.selinux_enforcing,
            "apparmor_enabled": result.apparmor_enabled,
            "seccomp_available": result.seccomp_available,
            "ebpf_restricted": result.ebpf_restricted,
            "user_ns_allowed": result.user_ns_allowed,
            "cpu_mitigations": [asdict(m) for m in result.cpu_mitigations],
            "warnings": result.warnings,
            "findings": [f.to_dict() for f in result.findings],
        }
        return self.context.store.save("os/kernel_hardening.json", payload)

    def _print_summary(self, result: KernelHardeningResult) -> None:
        print("----------------------------------------")
        print("Kernel Hardening Audit")
        print("----------------------------------------")
        sb = "enabled" if result.secure_boot_active else "disabled" if result.secure_boot_active is False else "unknown"
        se = "enforcing" if result.selinux_enforcing else "permissive/disabled" if result.selinux_enforcing is False else "unknown"
        aa = "enabled" if result.apparmor_enabled else "disabled" if result.apparmor_enabled is False else "unknown"
        print(f"Secure Boot   : {sb}")
        print(f"SELinux       : {se}")
        print(f"AppArmor      : {aa}")
        vuln_count = sum(1 for m in result.cpu_mitigations if m.mitigated is False)
        print(f"Vulnerable CPU: {vuln_count}")
        print(f"Findings      : {len(result.findings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="kernel_hardening",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="kernel_hardening",
        )


__all__ = [
    "CpuMitigation",
    "KernelHardeningModule",
    "KernelHardeningResult",
    "SysctlSecuritySetting",
]
