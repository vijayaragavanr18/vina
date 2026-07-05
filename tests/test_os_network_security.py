"""Tests for PS-04: Network Stack, Services, and Firewall Security."""

from __future__ import annotations

import unittest
from dataclasses import fields
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from vina.core.config import AppConfig
from vina.core.runner import CommandResult
from vina.models.common import TargetInput
from vina.modules.common import ModuleContext
from vina.scanners.os.network_security import NetworkSecurityModule, NetworkSecurityResult
from vina.scanners.os.network_security.dns import DnsModule
from vina.scanners.os.network_security.firewall import FirewallModule
from vina.scanners.os.network_security.listening_services import ListeningServicesModule
from vina.scanners.os.network_security.routing import RoutingModule


class NetworkSecurityPackageTests(unittest.TestCase):
    """Test that network_security package and modules can be imported."""

    def test_import_package(self) -> None:
        self.assertTrue(NetworkSecurityModule)
        self.assertTrue(FirewallModule)
        self.assertTrue(RoutingModule)
        self.assertTrue(DnsModule)
        self.assertTrue(ListeningServicesModule)

    def test_result_schemas(self) -> None:
        result_fields = {f.name for f in fields(NetworkSecurityResult)}
        self.assertIn("target", result_fields)
        self.assertIn("firewall", result_fields)
        self.assertIn("routing", result_fields)
        self.assertIn("dns", result_fields)
        self.assertIn("listening_services", result_fields)
        self.assertIn("findings", result_fields)
        self.assertIn("warnings", result_fields)


class NetworkSecurityModuleTests(unittest.IsolatedAsyncioTestCase):
    """Test NetworkSecurityModule and sub-scanners with mocked runners."""

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

    async def test_firewall_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "ufw" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="Status: inactive\n",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            return CommandResult(
                command=executable,
                args=tuple(args),
                returncode=1,
                stdout="",
                stderr="",
                duration_seconds=0.01,
                timed_out=False,
                missing_executable=False,
            )

        self.runner.run.side_effect = run_mock

        mod = FirewallModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Firewall is disabled or has no rules" in f.title for f in res.findings))

    async def test_routing_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "sysctl" in executable:
                stdout_data = (
                    "net.ipv4.ip_forward = 1\n"
                    "net.ipv4.tcp_syncookies = 0\n"
                    "net.ipv4.conf.all.rp_filter = 0\n"
                )
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout=stdout_data,
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            return CommandResult(
                command=executable,
                args=tuple(args),
                returncode=127,
                stdout="",
                stderr="",
                duration_seconds=0.01,
                timed_out=False,
                missing_executable=True,
            )

        self.runner.run.side_effect = run_mock

        mod = RoutingModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("net.ipv4.ip_forward is misconfigured" in f.title for f in res.findings))
        self.assertTrue(any("net.ipv4.tcp_syncookies is misconfigured" in f.title for f in res.findings))
        self.assertTrue(any("net.ipv4.conf.all.rp_filter is misconfigured" in f.title for f in res.findings))

    async def test_dns_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "cat" in executable and "/etc/resolv.conf" in args:
                stdout_data = (
                    "nameserver 8.8.8.8\n"
                    "nameserver 1.1.1.1\n"
                )
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout=stdout_data,
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            return CommandResult(
                command=executable,
                args=tuple(args),
                returncode=127,
                stdout="",
                stderr="",
                duration_seconds=0.01,
                timed_out=False,
                missing_executable=True,
            )

        self.runner.run.side_effect = run_mock

        mod = DnsModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Insecure public DNS resolvers configured" in f.title for f in res.findings))
        self.assertTrue(any("DNSSEC validation or EDNS0 options not enforced" in f.title for f in res.findings))

    async def test_listening_services_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "ss" in executable:
                stdout_data = (
                    "tcp   LISTEN 0      128          0.0.0.0:3306       0.0.0.0:*      users:((\"mysqld\",pid=1234,fd=10))\n"
                    "tcp   LISTEN 0      128             :::22              :::*      users:((\"sshd\",pid=5678,fd=3))\n"
                )
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout=stdout_data,
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            return CommandResult(
                command=executable,
                args=tuple(args),
                returncode=127,
                stdout="",
                stderr="",
                duration_seconds=0.01,
                timed_out=False,
                missing_executable=True,
            )

        self.runner.run.side_effect = run_mock

        mod = ListeningServicesModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Exposed database service: MySQL (port 3306)" in f.title for f in res.findings))
        self.assertTrue(any("Exposed remote service: SSH (port 22)" in f.title for f in res.findings))


if __name__ == "__main__":
    unittest.main()
