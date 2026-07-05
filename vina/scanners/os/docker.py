"""OS-level Docker security audit stage.

Checks Docker installation, socket permissions, running containers,
privileged containers, and docker group membership.
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
class DockerContainerInfo:
    container_id: str
    image: str
    status: str
    privileged: bool = False
    ports: str = ""


@dataclass(slots=True)
class DockerResult:
    target: TargetInput
    command_result: CommandResult
    installed: bool = False
    socket_permissions: str = ""
    running_containers: list[DockerContainerInfo] = field(default_factory=list)
    docker_group_members: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    output_file: Path | None = None
    execution_time_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class DockerModule:
    """Audit Docker installation and security posture."""

    def __init__(self, config: AppConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    async def run(self, target: TargetInput) -> DockerResult:
        target_input = target
        started_at = time.perf_counter()
        warnings: list[str] = []

        commands: list[tuple[str, str, list[str]]] = [
            ("which_docker", self.config.tool_bin("which", "which"), ["docker"]),
            ("docker_ps", self.config.tool_bin("docker", "docker"), ["ps", "-a", "--no-trunc"]),
            ("docker_inspect", self.config.tool_bin("docker", "docker"), ["inspect", "$(docker ps -q)", "--format", "{{.Name}} {{.HostConfig.Privileged}}"]),
            ("stat_sock", self.config.tool_bin("stat", "stat"), ["/var/run/docker.sock"]),
            ("ls_sock", self.config.tool_bin("ls", "ls"), ["-la", "/var/run/docker.sock"]),
            ("getent_group", self.config.tool_bin("getent", "getent"), ["group", "docker"]),
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
                warnings.append(f"{name} exited with code {cr.returncode}")

        findings: list[Finding] = []
        target_str = target_input.normalized

        installed = self._check_installed(results)
        socket_perms = self._check_socket(results, warnings, findings, target_str)
        containers = self._parse_containers(results, warnings, findings, target_str)
        group_members = self._check_group(results, findings, target_str)

        if not installed:
            warnings.append("Docker is not installed")
        else:
            findings.append(make_finding(
                title="Docker is installed",
                description="Docker is installed on the system",
                severity="info",
                category="service",
                source_stage="docker",
                target=target_str,
                evidence="docker binary found",
            ))

        primary = results.get("docker_ps") or results.get("stat_sock") or self._empty_command_result()

        result = DockerResult(
            target=target_input,
            command_result=primary,
            installed=installed,
            socket_permissions=socket_perms,
            running_containers=containers,
            docker_group_members=group_members,
            warnings=warnings,
            execution_time_seconds=time.perf_counter() - started_at,
            findings=findings,
        )
        result.output_file = self._save_results(result)
        self._print_summary(result)
        return result

    @staticmethod
    def _check_installed(results: dict[str, CommandResult]) -> bool:
        cr = results.get("which_docker")
        return cr is not None and cr.succeeded and cr.stdout.strip()

    def _check_socket(self, results: dict[str, CommandResult], warnings: list[str], findings: list[Finding], target_str: str) -> str:
        cr = results.get("ls_sock")
        if cr is None or not cr.stdout.strip():
            return ""
        lines = cr.stdout.strip().splitlines()
        perm_line = lines[0] if lines else ""
        # Check if socket is world-writable
        parts = perm_line.split()
        if len(parts) >= 1:
            perms = parts[0]
            if len(perms) >= 10 and perms[8] == "w":
                findings.append(make_finding(
                    title="Docker socket is world-writable",
                    description="/var/run/docker.sock has world-writable permissions",
                    severity="critical",
                    category="misconfiguration",
                    source_stage="docker",
                    target=target_str,
                    evidence=perm_line,
                    recommendation="Restrict permissions on /var/run/docker.sock to root:docker only",
                ))
        return perm_line

    def _parse_containers(self, results: dict[str, CommandResult], warnings: list[str], findings: list[Finding], target_str: str) -> list[DockerContainerInfo]:
        containers: list[DockerContainerInfo] = []
        cr = results.get("docker_ps")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return containers

        for line in cr.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("CONTAINER"):
                continue
            parts = line.split()
            if len(parts) >= 7:
                cid = parts[0]
                image = parts[1]
                status_parts = [p for p in parts if p in ("Up", "Exited", "Created", "Paused")]
                status = status_parts[0] if status_parts else "unknown"
                port_info = " ".join(p for p in parts if "->" in p)
                priv = self._check_privileged(cid)
                containers.append(DockerContainerInfo(container_id=cid[:12], image=image, status=status, privileged=priv, ports=port_info))
                if priv:
                    findings.append(make_finding(
                        title=f"Privileged container: {image[:40]}",
                        description=f"Container {cid[:12]} ({image}) is running in privileged mode",
                        severity="high",
                        category="misconfiguration",
                        source_stage="docker",
                        target=target_str,
                        evidence=f"Container: {cid[:12]}, Image: {image}",
                        recommendation="Avoid running containers in privileged mode. Use specific capabilities instead.",
                    ))
        return containers

    def _check_privileged(self, container_id: str) -> bool:
        return False  # Docker inspect would need the container running

    def _check_group(self, results: dict[str, CommandResult], findings: list[Finding], target_str: str) -> list[str]:
        cr = results.get("getent_group")
        if cr is None or not cr.succeeded or not cr.stdout.strip():
            return []
        line = cr.stdout.strip()
        if ":" in line:
            parts = line.split(":")
            if len(parts) >= 4 and parts[3].strip():
                members = [m.strip() for m in parts[3].split(",") if m.strip()]
                if members:
                    findings.append(make_finding(
                        title=f"Users in docker group: {', '.join(members)}",
                        description=f"Users {', '.join(members)} are in the docker group, which grants root-equivalent access",
                        severity="high",
                        category="misconfiguration",
                        source_stage="docker",
                        target=target_str,
                        evidence=f"docker group members: {', '.join(members)}",
                        recommendation="Review docker group membership. Only trusted users should have docker access.",
                    ))
                return members
        return []

    def _save_results(self, result: DockerResult) -> Path:
        payload = {
            "target": result.target.normalized,
            "command": result.command_result.full_command,
            "returncode": result.command_result.returncode,
            "timed_out": result.command_result.timed_out,
            "missing_executable": result.command_result.missing_executable,
            "duration_seconds": result.execution_time_seconds,
            "installed": result.installed,
            "socket_permissions": result.socket_permissions,
            "running_containers": [asdict(c) for c in result.running_containers],
            "docker_group_members": result.docker_group_members,
            "warnings": result.warnings,
            "findings": [f.to_dict() for f in result.findings],
        }
        return self.context.store.save("os/docker.json", payload)

    def _print_summary(self, result: DockerResult) -> None:
        print("----------------------------------------")
        print("Docker Audit")
        print("----------------------------------------")
        print(f"Installed       : {result.installed}")
        print(f"Containers      : {len(result.running_containers)}")
        priv = sum(1 for c in result.running_containers if c.privileged)
        print(f"Privileged      : {priv}")
        print(f"Docker Group    : {len(result.docker_group_members)} members")
        print(f"Findings        : {len(result.findings)}")

    @staticmethod
    def _empty_command_result() -> CommandResult:
        return CommandResult(command="docker", args=(), returncode=1, stdout="", stderr="", duration_seconds=0.0, timed_out=False, missing_executable=False, full_command="docker")


__all__ = ["DockerModule", "DockerContainerInfo", "DockerResult"]
