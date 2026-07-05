"""Mount options and network filesystem security auditing.

Audits /etc/fstab mount options (noexec, nosuid, nodev), NFS exports (no_root_squash),
and Samba/SMB public share configurations.
"""

from __future__ import annotations

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
class MountsResult:
    target: TargetInput
    command_result: CommandResult
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0


class MountsModule:
    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> MountsResult:
        started_at = time.perf_counter()
        warnings: list[str] = []
        findings: list[Finding] = []

        target_str = target.normalized

        cat_cmd = self.config.tool_bin("cat", "cat")
        cr_mounts = await self.context.runner.run(cat_cmd, ["/proc/mounts"], timeout_seconds=5)

        if cr_mounts.succeeded and cr_mounts.stdout.strip():
            lines = cr_mounts.stdout.strip().splitlines()
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    mp = parts[1]
                    opts = parts[3].split(",")

                    if mp == "/tmp":
                        missing = []
                        if "noexec" not in opts:
                            missing.append("noexec")
                        if "nodev" not in opts:
                            missing.append("nodev")
                        if "nosuid" not in opts:
                            missing.append("nosuid")
                        if missing:
                            findings.append(make_finding(
                                title=f"Insecure mount options on /tmp: missing {', '.join(missing)}",
                                description="The /tmp directory partition is mounted without critical restrictive mount options. Without noexec, nodev, or nosuid, users can run malicious binaries, access raw devices, or run SUID binaries directly from /tmp.",
                                severity="medium",
                                category="misconfiguration",
                                source_stage="storage_security",
                                target=target_str,
                                evidence=f"Mount options on /tmp: {parts[3]}",
                                recommendation="Update /etc/fstab to mount /tmp with 'defaults,noexec,nodev,nosuid'.",
                                confidence=0.9,
                            ))

                    elif mp == "/dev/shm":
                        missing = []
                        if "noexec" not in opts:
                            missing.append("noexec")
                        if "nodev" not in opts:
                            missing.append("nodev")
                        if "nosuid" not in opts:
                            missing.append("nosuid")
                        if missing:
                            findings.append(make_finding(
                                title=f"Insecure mount options on /dev/shm: missing {', '.join(missing)}",
                                description="The shared memory directory /dev/shm is mounted with loose options, allowing binary execution or SUID escalation.",
                                severity="medium",
                                category="misconfiguration",
                                source_stage="storage_security",
                                target=target_str,
                                evidence=f"Mount options on /dev/shm: {parts[3]}",
                                recommendation="Update /etc/fstab to mount /dev/shm with 'defaults,noexec,nodev,nosuid'.",
                                confidence=0.9,
                            ))

        exports_file = "/etc/exports"
        cr_nfs = await self.context.runner.run(cat_cmd, [exports_file], timeout_seconds=5)

        if cr_nfs.succeeded and cr_nfs.stdout.strip():
            lines = cr_nfs.stdout.strip().splitlines()
            insecure_exports = []
            for line in lines:
                if line.strip() and not line.strip().startswith("#") and "no_root_squash" in line:
                    insecure_exports.append(line.strip())

            if insecure_exports:
                findings.append(make_finding(
                    title="NFS exports configured with no_root_squash",
                    description="One or more NFS exports are configured with 'no_root_squash'. This configuration allows root users on NFS clients to read and write files on the server as root, leading to potential privilege escalation.",
                    severity="high",
                    category="vulnerability",
                    source_stage="storage_security",
                    target=target_str,
                    evidence="\n".join(insecure_exports),
                    recommendation="Remove 'no_root_squash' or change it to 'root_squash' in /etc/exports.",
                    confidence=0.95,
                ))

        smb_conf = "/etc/samba/smb.conf"
        cr_smb = await self.context.runner.run(cat_cmd, [smb_conf], timeout_seconds=5)

        if cr_smb.succeeded and cr_smb.stdout.strip():
            content = cr_smb.stdout
            if "guest ok = yes" in content.lower() or "public = yes" in content.lower():
                findings.append(make_finding(
                    title="Samba public/guest share access enabled",
                    description="The Samba configuration file allows unauthenticated guest access to shared resources, exposing files to anonymous network users.",
                    severity="medium",
                    category="misconfiguration",
                    source_stage="storage_security",
                    target=target_str,
                    evidence="guest ok = yes or public = yes configured in smb.conf",
                    recommendation="Disable guest access by setting 'guest ok = no' and 'public = no' on sensitive Samba shares.",
                    confidence=0.9,
                ))

        primary = cr_mounts or cr_nfs or self._empty_command_result()

        result = MountsResult(
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
            command="mounts",
            args=(),
            returncode=1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            missing_executable=False,
            full_command="mounts",
        )
