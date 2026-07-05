"""Reusable test fixtures and mock objects for deterministic testing.

Provides mock implementations of VINA core services so that tests and
benchmarks can run without real subprocess execution or network access.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models.findings import Finding, FindingCategory, Severity, make_finding
from ..models.stages import StageResult, StageState


def make_mock_finding(
    title: str = "Mock Finding",
    severity: str = Severity.INFO,
    category: str = FindingCategory.OTHER,
    source_stage: str = "mock",
    target: str = "localhost",
    evidence: str = "mock evidence",
    description: str = "A mock finding for testing",
    recommendation: str = "No action needed",
    host: str = "127.0.0.1",
    port: int | None = None,
    confidence: float | None = 0.9,
    tags: list[str] | None = None,
) -> Finding:
    """Create a Finding with sensible defaults for testing."""
    return make_finding(
        title=title,
        severity=severity,
        category=category,
        source_stage=source_stage,
        target=target,
        evidence=evidence,
        description=description,
        recommendation=recommendation,
        host=host,
        port=port,
        confidence=confidence,
        tags=tags or [],
    )


def make_mock_stage_result(
    name: str = "mock_stage",
    status: StageState = StageState.SUCCESS,
    record_count: int = 0,
    duration: float = 0.5,
    warnings: list[str] | None = None,
    timed_out: bool = False,
    executable_missing: bool = False,
) -> StageResult:
    """Create a StageResult with sensible defaults for testing."""
    return StageResult(
        name=name,
        status=status,
        command=f"{name} --test",
        exit_code=0,
        duration=duration,
        record_count=record_count,
        warnings=warnings or [],
        timed_out=timed_out,
        executable_missing=executable_missing,
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=datetime.now(timezone.utc).isoformat(),
    )


class MockCommandRunner:
    """A mock AsyncCommandRunner that returns canned CommandResults.

    Useful for testing pipeline stages without executing real commands.
    """

    def __init__(self) -> None:
        self._results: dict[str, Any] = {}
        self._default_result: Any | None = None
        self.executed_commands: list[tuple[str, tuple[str, ...]]] = []

    def set_result(
        self,
        command: str,
        result: Any,
    ) -> None:
        """Set the canned result for *command*."""
        self._results[command] = result

    def set_default_result(self, result: Any) -> None:
        """Fallback result when no specific command is registered."""
        self._default_result = result

    async def run(
        self,
        command: str,
        args: tuple[str, ...] | None = None,
        **kwargs: Any,
    ) -> Any:
        self.executed_commands.append((command, tuple(args or ())))
        if command in self._results:
            return self._results[command]
        if self._default_result is not None:
            return self._default_result
        from ..core.runner import CommandResult
        return CommandResult(
            command=command,
            args=tuple(args or ()),
            stdout="",
            stderr="",
            returncode=0,
            duration_seconds=0.01,
        )


@dataclass
class MockPipelineContext:
    """Aggregated context for mock pipeline runs.

    Provides easy access to all mock services and collected results.
    """

    findings: list[Finding] = field(default_factory=list)
    stage_results: list[StageResult] = field(default_factory=list)
    output_dir: Path = field(default_factory=lambda: Path("/tmp/vina-test-output"))
    command_runner: MockCommandRunner = field(default_factory=MockCommandRunner)


class MockFindingFactory:
    """Factory for generating batches of mock findings for benchmark scenarios."""

    @staticmethod
    def suid_findings(count: int = 3, target: str = "localhost") -> list[Finding]:
        return [
            make_mock_finding(
                title=f"SUID binary: /usr/bin/binary{i}",
                severity=Severity.MEDIUM,
                category=FindingCategory.MISCONFIGURATION,
                source_stage="filesystem",
                target=target,
                evidence=f"-rwsr-xr-x root root /usr/bin/binary{i}",
                recommendation="Review SUID permissions",
            )
            for i in range(count)
        ]

    @staticmethod
    def passwordless_sudo(target: str = "localhost") -> list[Finding]:
        return [
            make_mock_finding(
                title="NOPASSWD sudo entry found",
                severity=Severity.HIGH,
                category=FindingCategory.MISCONFIGURATION,
                source_stage="sudo",
                target=target,
                evidence="user ALL=(ALL) NOPASSWD:ALL",
                recommendation="Require password for sudo access",
            )
        ]

    @staticmethod
    def docker_socket(target: str = "localhost") -> list[Finding]:
        return [
            make_mock_finding(
                title="Docker socket mounted",
                severity=Severity.CRITICAL,
                category=FindingCategory.MISCONFIGURATION,
                source_stage="docker",
                target=target,
                evidence="/var/run/docker.sock",
                recommendation="Do not mount the Docker socket inside containers",
                tags=["docker", "container-escape"],
            )
        ]

    @staticmethod
    def writable_cron(target: str = "localhost") -> list[Finding]:
        return [
            make_mock_finding(
                title="Writable files in /etc/cron.d",
                severity=Severity.HIGH,
                category=FindingCategory.MISCONFIGURATION,
                source_stage="cron",
                target=target,
                evidence="-rw-rw-rw- root root /etc/cron.d/example",
                recommendation="Restrict permissions on cron directories",
            )
        ]

    @staticmethod
    def ssh_keys(target: str = "localhost") -> list[Finding]:
        return [
            make_mock_finding(
                title="SSH private key found: id_rsa",
                severity=Severity.CRITICAL,
                category=FindingCategory.VULNERABILITY,
                source_stage="secrets",
                target=target,
                evidence="-----BEGIN OPENSSH PRIVATE KEY-----",
                recommendation="Rotate the exposed SSH key immediately",
                tags=["ssh", "secret", "key"],
            )
        ]

    @staticmethod
    def vulnerable_package(
        target: str = "localhost",
        package: str = "openssl",
        version: str = "1.1.1",
        cve: str = "CVE-2024-0001",
    ) -> list[Finding]:
        return [
            make_mock_finding(
                title=f"{package}:{version}",
                severity=Severity.INFO,
                category=FindingCategory.OTHER,
                source_stage="packages",
                target=target,
                evidence=f"{package}={version}",
                tags=[package, "package"],
            )
        ]

    @staticmethod
    def exposed_service(target: str = "localhost") -> list[Finding]:
        return [
            make_mock_finding(
                title="Service: sshd running on port 22",
                severity=Severity.INFO,
                category=FindingCategory.SERVICE,
                source_stage="services",
                target=target,
                evidence="sshd: /usr/sbin/sshd -D",
                port=22,
            ),
            make_mock_finding(
                title="Service: apache2 running on port 80",
                severity=Severity.INFO,
                category=FindingCategory.SERVICE,
                source_stage="services",
                target=target,
                evidence="/usr/sbin/apache2 -k start",
                port=80,
            ),
        ]


__all__ = [
    "MockCommandRunner",
    "MockFindingFactory",
    "MockPipelineContext",
    "make_mock_finding",
    "make_mock_stage_result",
]
