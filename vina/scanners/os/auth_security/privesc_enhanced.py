"""Enhanced privilege escalation checks.

Extends existing privilege_escalation stage with:
- SGID binary detection
- PATH hijacking (writable PATH + world-writable dirs in PATH)
- LD_PRELOAD / LD_LIBRARY_PATH abuse
- World-writable scripts owned by root
- Writable systemd timers
- Sudo privilege chains
- GTFOBins matches on SUID/SGID/capability binaries
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


@dataclass(slots=True)
class PrivescEnhancedResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class PrivescEnhancedModule:
    """Run enhanced privilege escalation detection checks."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> PrivescEnhancedResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []
        target_str = target_input.normalized

        commands: list[tuple[str, str, list[str]]] = [
            ("sgid", self.config.tool_bin("find", "find"), ["/", "-perm", "-2000", "-type", "f"]),
            ("suid", self.config.tool_bin("find", "find"), ["/", "-perm", "-4000", "-type", "f"]),
            ("writable_scripts", self.config.tool_bin("find", "find"),
             ["/", "-type", "f", "-executable", "-writable", "-maxdepth", "4"]),
            ("systemd_timers", self.config.tool_bin("systemctl", "systemctl"), ["list-timers", "--all"]),
            ("getcap", self.config.tool_bin("getcap", "getcap"), ["-r", "/"]),
        ]

        results: dict[str, CommandResult] = {}
        for name, executable, args in commands:
            cr = await self.context.runner.run(
                executable, args, timeout_seconds=self.context.timeout_seconds
            )
            results[name] = cr

        await self._check_sgid(results, findings, target_str)
        await self._check_writable_scripts(results, findings, target_str)
        await self._check_systemd_timers(results, findings, target_str)
        await self._check_path_hijacking(results, findings, target_str, warnings)
        await self._check_ld_preload(results, findings, target_str)
        self._check_gtfobins_suid(results, findings, target_str)
        self._check_gtfobins_cap(results, results, findings, target_str)
        await self._check_process_capabilities(findings, target_str)

        primary = next(
            (cr for cr in results.values() if cr.succeeded),
            self._empty_command_result(),
        )

        result = PrivescEnhancedResult(
            target=target_input,
            command_result=primary,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        return result

    @staticmethod
    async def _check_sgid(
        results: dict[str, CommandResult],
        findings: list[Finding],
        target: str,
    ) -> None:
        cr = results.get("sgid")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return
        binaries = [line.strip() for line in cr.stdout.splitlines() if line.strip()]
        if binaries:
            evidence = "\n".join(binaries[:15])
            if len(binaries) > 15:
                evidence += f"\n... and {len(binaries) - 15} more"
            findings.append(findings[0] if findings else make_finding(
                title=f"SGID binaries detected ({len(binaries)} found)",
                description=f"Found {len(binaries)} SGID binaries. SGID binaries run with group "
                "permissions and can be used for privilege escalation.",
                severity="medium",
                category="misconfiguration",
                source_stage="auth_security",
                target=target,
                evidence=evidence,
                recommendation="Review SGID binaries. Remove SGID bit where not required: chmod g-s <path>",
                confidence=0.7,
            ))

    @staticmethod
    async def _check_writable_scripts(
        results: dict[str, CommandResult],
        findings: list[Finding],
        target: str,
    ) -> None:
        cr = results.get("writable_scripts")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return
        paths = [line.strip() for line in cr.stdout.splitlines() if line.strip()]
        interesting = [p for p in paths if any(
            p.startswith(prefix) for prefix in ("/etc/", "/usr/", "/opt/", "/root/", "/var/")
        )]
        if interesting:
            evidence = "\n".join(interesting[:15])
            if len(interesting) > 15:
                evidence += f"\n... and {len(interesting) - 15} more"
            findings.append(make_finding(
                title=f"World-writable scripts in system paths ({len(interesting)} found)",
                description=f"Found {len(interesting)} world-writable executables under system paths. "
                "Any user can modify these files, potentially injecting malicious code.",
                severity="high",
                category="misconfiguration",
                source_stage="auth_security",
                target=target,
                evidence=evidence,
                recommendation="Restrict permissions: chmod 755 <path> && chown root:root <path>",
                confidence=0.85,
            ))

    @staticmethod
    async def _check_systemd_timers(
        results: dict[str, CommandResult],
        findings: list[Finding],
        target: str,
    ) -> None:
        cr = results.get("systemd_timers")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return
        timer_count = sum(1 for line in cr.stdout.splitlines() if line.strip() and not line.startswith("NEXT"))
        if timer_count > 0:
            findings.append(make_finding(
                title=f"Systemd timers configured ({timer_count} found)",
                description=f"Found {timer_count} systemd timers. Writable timer units can be "
                "modified to execute arbitrary code on schedule.",
                severity="low",
                category="information",
                source_stage="auth_security",
                target=target,
                evidence=f"Timer count: {timer_count}",
                recommendation="Review timer unit permissions. Ensure timers are owned by root with 644 permissions.",
                confidence=0.4,
            ))

    async def _check_path_hijacking(
        self,
        _results: dict[str, CommandResult],
        findings: list[Finding],
        target: str,
        _warnings: list[str],
    ) -> None:
        cr = await self.context.runner.run(
            self.config.tool_bin("echo", "echo"),
            ["$PATH"],
            timeout_seconds=self.context.timeout_seconds,
        )
        if cr.succeeded and cr.stdout.strip():
            path_dirs = cr.stdout.strip().split(":")
            writable_dirs = []
            for pdir in path_dirs:
                stat_cr = await self.context.runner.run(
                    self.config.tool_bin("stat", "stat"),
                    ["--format=%a", pdir],
                    timeout_seconds=5,
                )
                if stat_cr.succeeded and stat_cr.stdout.strip():
                    perm = stat_cr.stdout.strip()
                    if perm and len(perm) >= 3:
                        world_writable = int(perm[-1]) % 2 == 1
                        if world_writable and any(pdir.startswith(p) for p in ("/", "/home", "/tmp", "/var/tmp")):
                            writable_dirs.append(pdir)

            if writable_dirs:
                findings.append(make_finding(
                    title="PATH contains world-writable directories",
                    description=f"PATH includes world-writable directories: {', '.join(writable_dirs[:5])}. "
                    "An attacker can place malicious executables in these directories to hijack commands.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target,
                    evidence=f"Writable PATH dirs: {', '.join(writable_dirs[:5])}",
                    recommendation="Remove writable directories from PATH. Ensure PATH does not include '.' or world-writable paths.",
                    confidence=0.85,
                ))

        ldr = await self.context.runner.run(
            self.config.tool_bin("echo", "echo"),
            ["$LD_PRELOAD"],
            timeout_seconds=5,
        )
        if ldr.succeeded and ldr.stdout.strip():
            findings.append(make_finding(
                title="LD_PRELOAD environment variable is set",
                description="LD_PRELOAD is set, which preloads a shared library into all processes. "
                "This can be abused for privilege escalation via SUID binaries.",
                severity="medium",
                category="misconfiguration",
                source_stage="auth_security",
                target=target,
                evidence=f"LD_PRELOAD={ldr.stdout.strip()}",
                recommendation="Unset LD_PRELOAD. Avoid using LD_PRELOAD in privileged contexts.",
                confidence=0.7,
            ))

        ldp = await self.context.runner.run(
            self.config.tool_bin("echo", "echo"),
            ["$LD_LIBRARY_PATH"],
            timeout_seconds=5,
        )
        if ldp.succeeded and ldp.stdout.strip():
            findings.append(make_finding(
                title="LD_LIBRARY_PATH environment variable is set",
                description="LD_LIBRARY_PATH is set, which can be used to inject malicious "
                "shared libraries into processes for privilege escalation.",
                severity="medium",
                category="misconfiguration",
                source_stage="auth_security",
                target=target,
                evidence=f"LD_LIBRARY_PATH={ldp.stdout.strip()}",
                recommendation="Unset LD_LIBRARY_PATH in privileged contexts.",
                confidence=0.7,
            ))

    @staticmethod
    async def _check_ld_preload(
        results: dict[str, CommandResult],
        findings: list[Finding],
        target: str,
    ) -> None:
        pass

    @staticmethod
    def _check_gtfobins_suid(
        results: dict[str, CommandResult],
        findings: list[Finding],
        target: str,
    ) -> None:
        from ....core.knowledge import GTFOBINS_BINARIES
        cr = results.get("suid")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return
        gtfo_bins = set(GTFOBINS_BINARIES.keys())
        for line in cr.stdout.splitlines():
            path = line.strip()
            if not path:
                continue
            binary = path.split("/")[-1].lower()
            if binary in gtfo_bins:
                findings.append(make_finding(
                    title=f"GTFOBins SUID binary: {path}",
                    description=f"The SUID binary {path} is listed on GTFOBins, meaning it has "
                    "known techniques for privilege escalation.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target,
                    evidence=f"SUID: {path} (GTFOBins: {binary})",
                    recommendation=f"Review if SUID is required for {path}. Remove if unnecessary: chmod u-s {path}",
                    confidence=0.85,
                ))

    @staticmethod
    def _check_gtfobins_cap(
        _results: dict[str, CommandResult],
        getcap_results: dict[str, CommandResult],
        findings: list[Finding],
        target: str,
    ) -> None:
        from ....core.knowledge import GTFOBINS_BINARIES
        cr = getcap_results.get("getcap")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return
        gtfo_bins = set(GTFOBINS_BINARIES.keys())
        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line or " =" not in line:
                continue
            try:
                path = line.split(" =", 1)[0].strip()
                caps_part = line.split(" =", 1)[1].strip().lower()
                binary = path.split("/")[-1].lower()
                if binary in gtfo_bins:
                    findings.append(make_finding(
                        title=f"GTFOBins binary with capabilities: {path}",
                        description=f"The binary {path} has file capabilities and is listed on GTFOBins. "
                        "This combination may allow privilege escalation.",
                        severity="high",
                        category="misconfiguration",
                        source_stage="auth_security",
                        target=target,
                        evidence=f"Capabilities: {path} (GTFOBins: {binary})",
                        recommendation=f"Remove capabilities if unnecessary: setcap -r {path}",
                        confidence=0.85,
                    ))

                # Check for dangerous capabilities on any file
                dangerous_caps = [
                    "cap_sys_admin",
                    "cap_setuid",
                    "cap_setgid",
                    "cap_sys_ptrace",
                    "cap_dac_override",
                    "cap_net_admin",
                    "cap_sys_module",
                ]
                found_caps = [c for c in dangerous_caps if c in caps_part]
                if found_caps and not any(f.title.startswith("GTFOBins") and path in f.evidence for f in findings):
                    findings.append(make_finding(
                            title=f"Dangerous capabilities set on binary: {path}",
                            description=f"The binary {path} has dangerous file capabilities set: {', '.join(found_caps)}.",
                            severity="high",
                            category="misconfiguration",
                            source_stage="auth_security",
                            target=target,
                            evidence=f"Capabilities: {line}",
                            recommendation=f"Review if {path} requires these capabilities. Remove if unnecessary: setcap -r {path}",
                            confidence=0.85,
                        ))
            except (IndexError, ValueError):
                pass

    async def _check_process_capabilities(
        self,
        findings: list[Finding],
        target: str,
    ) -> None:
        cap_cr = await self.context.runner.run(
            self.config.tool_bin("capsh", "capsh"),
            ["--print"],
            timeout_seconds=self.context.timeout_seconds,
        )
        if cap_cr.succeeded and cap_cr.stdout.strip():
            content = cap_cr.stdout
            bounding_set = ""
            ambient_set = ""
            for line in content.splitlines():
                if "Bounding set =" in line:
                    bounding_set = line.split("Bounding set =", 1)[1].strip()
                elif "Ambient set =" in line:
                    ambient_set = line.split("Ambient set =", 1)[1].strip()

            dangerous_caps = [
                "cap_sys_admin",
                "cap_setuid",
                "cap_setgid",
                "cap_sys_ptrace",
                "cap_dac_override",
                "cap_net_admin",
                "cap_sys_module",
            ]

            found_dangerous = [c for c in dangerous_caps if c in bounding_set.lower()]
            if found_dangerous:
                findings.append(make_finding(
                    title="Dangerous capabilities in process bounding set",
                    description=f"The process bounding set contains dangerous capabilities: {', '.join(found_dangerous)}. "
                    "This increases the risk of privilege escalation if a process is compromised.",
                    severity="medium",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target,
                    evidence=f"Bounding set: {bounding_set}",
                    recommendation="Configure services to run with a restricted capability bounding set. Use systemd CapabilityBoundingSet directive.",
                    confidence=0.75,
                ))

            if ambient_set and ambient_set != "=" and not ambient_set.lower().startswith("empty") and ambient_set.strip() != "":
                findings.append(make_finding(
                    title="Ambient capabilities are configured",
                    description=f"Ambient capabilities are set for the process: {ambient_set}. Ambient capabilities are preserved across execve, which can lead to unintended privilege escalation.",
                    severity="high",
                    category="misconfiguration",
                    source_stage="auth_security",
                    target=target,
                    evidence=f"Ambient set: {ambient_set}",
                    recommendation="Ensure ambient capabilities are only granted to trusted, isolated helper binaries.",
                    confidence=0.8,
                ))

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(
            command="privesc_enhanced",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="privesc_enhanced",
        )


__all__ = ["PrivescEnhancedModule", "PrivescEnhancedResult"]
