"""Tests for PS-10: Containerisation, Virtualisation, and Namespace Security."""

from __future__ import annotations

import unittest
from dataclasses import fields
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from vina.core.config import AppConfig
from vina.core.runner import CommandResult
from vina.models.common import TargetInput
from vina.modules.common import ModuleContext
from vina.scanners.os.container_security import ContainerSecurityModule, ContainerSecurityResult
from vina.scanners.os.container_security.namespaces import NamespacesModule
from vina.scanners.os.container_security.runtimes import RuntimesModule
from vina.scanners.os.container_security.virtualization import VirtualizationModule


class ContainerSecurityPackageTests(unittest.TestCase):
    """Test that container_security package and modules can be imported."""

    def test_import_package(self) -> None:
        self.assertTrue(ContainerSecurityModule)
        self.assertTrue(RuntimesModule)
        self.assertTrue(NamespacesModule)
        self.assertTrue(VirtualizationModule)

    def test_result_schemas(self) -> None:
        result_fields = {f.name for f in fields(ContainerSecurityResult)}
        self.assertIn("target", result_fields)
        self.assertIn("runtimes", result_fields)
        self.assertIn("namespaces", result_fields)
        self.assertIn("virtualization", result_fields)
        self.assertIn("findings", result_fields)
        self.assertIn("warnings", result_fields)


class ContainerSecurityModuleTests(unittest.IsolatedAsyncioTestCase):
    """Test ContainerSecurityModule and sub-scanners with mocked runners."""

    def setUp(self) -> None:
        self.config = AppConfig()
        self.runner = AsyncMock()
        self.store = MagicMock()
        self.context = ModuleContext(
            runner=self.runner,
            store=self.store,
            timeout_seconds=10,
        )
        self.target = TargetInput.from_raw("localhost")

    async def test_runtimes_scanner_docker_no_userns(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "pgrep" in executable and "dockerd" in args:
                return CommandResult(
                    command=executable, args=tuple(args), returncode=0,
                    stdout="1234\n", stderr="", duration_seconds=0.1,
                    timed_out=False, missing_executable=False,
                )
            elif "cat" in executable and "daemon.json" in args[0]:
                return CommandResult(
                    command=executable, args=tuple(args), returncode=0,
                    stdout='{"log-driver": "json-file"}\n', stderr="",
                    duration_seconds=0.1, timed_out=False, missing_executable=False,
                )
            return CommandResult(
                command=executable, args=tuple(args), returncode=1,
                stdout="", stderr="", duration_seconds=0.01,
                timed_out=False, missing_executable=False,
            )

        self.runner.run.side_effect = run_mock
        mod = RuntimesModule(self.config, self.context)
        res = await mod.run(self.target)
        self.assertTrue(any("Docker user namespace remapping is disabled" in f.title for f in res.findings))

    async def test_namespaces_scanner_no_lsm(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "cat" in executable and "apparmor" in args[0]:
                return CommandResult(
                    command=executable, args=tuple(args), returncode=0,
                    stdout="N\n", stderr="", duration_seconds=0.1,
                    timed_out=False, missing_executable=False,
                )
            elif "sestatus" in executable:
                return CommandResult(
                    command=executable, args=tuple(args), returncode=1,
                    stdout="", stderr="", duration_seconds=0.1,
                    timed_out=False, missing_executable=True,
                )
            elif "cat" in executable and "seccomp" in args[0]:
                return CommandResult(
                    command=executable, args=tuple(args), returncode=1,
                    stdout="", stderr="", duration_seconds=0.1,
                    timed_out=False, missing_executable=False,
                )
            return CommandResult(
                command=executable, args=tuple(args), returncode=1,
                stdout="", stderr="", duration_seconds=0.01,
                timed_out=False, missing_executable=False,
            )

        self.runner.run.side_effect = run_mock
        mod = NamespacesModule(self.config, self.context)
        res = await mod.run(self.target)
        self.assertTrue(any("No active Linux Security Module" in f.title for f in res.findings))
        self.assertTrue(any("seccomp" in f.title for f in res.findings))

    async def test_virtualization_scanner_kvm(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "lsmod" in executable:
                return CommandResult(
                    command=executable, args=tuple(args), returncode=0,
                    stdout="kvm_intel  300000  2\nkvm  800000  1 kvm_intel\n",
                    stderr="", duration_seconds=0.1,
                    timed_out=False, missing_executable=False,
                )
            return CommandResult(
                command=executable, args=tuple(args), returncode=1,
                stdout="", stderr="", duration_seconds=0.01,
                timed_out=False, missing_executable=False,
            )

        self.runner.run.side_effect = run_mock
        mod = VirtualizationModule(self.config, self.context)
        res = await mod.run(self.target)
        self.assertTrue(any("Virtualization hypervisor modules active" in f.title for f in res.findings))


if __name__ == "__main__":
    unittest.main()
