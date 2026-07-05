"""Tests for PS-08: Logging, Auditing, and Monitoring Security."""

from __future__ import annotations

import unittest
from dataclasses import fields
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from vina.core.config import AppConfig
from vina.core.runner import CommandResult
from vina.models.common import TargetInput
from vina.modules.common import ModuleContext
from vina.scanners.os.monitoring_security import MonitoringSecurityModule, MonitoringSecurityResult
from vina.scanners.os.monitoring_security.agents import AgentsModule
from vina.scanners.os.monitoring_security.auditing import AuditingModule
from vina.scanners.os.monitoring_security.syslog import SyslogModule
from vina.scanners.os.monitoring_security.time_sync import TimeSyncModule


class MonitoringSecurityPackageTests(unittest.TestCase):
    """Test that monitoring_security package and modules can be imported."""

    def test_import_package(self) -> None:
        self.assertTrue(MonitoringSecurityModule)
        self.assertTrue(AuditingModule)
        self.assertTrue(SyslogModule)
        self.assertTrue(TimeSyncModule)
        self.assertTrue(AgentsModule)

    def test_result_schemas(self) -> None:
        result_fields = {f.name for f in fields(MonitoringSecurityResult)}
        self.assertIn("target", result_fields)
        self.assertIn("auditing", result_fields)
        self.assertIn("syslog", result_fields)
        self.assertIn("time_sync", result_fields)
        self.assertIn("agents", result_fields)
        self.assertIn("findings", result_fields)
        self.assertIn("warnings", result_fields)


class MonitoringSecurityModuleTests(unittest.IsolatedAsyncioTestCase):
    """Test MonitoringSecurityModule and sub-scanners with mocked runners."""

    def setUp(self) -> None:
        self.config = AppConfig()
        self.runner = AsyncMock()
        self.store = MagicMock()
        self.context = ModuleContext(runner=self.runner, store=self.store, timeout_seconds=10)
        self.target = TargetInput.from_raw("localhost")

    async def test_auditing_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "pgrep" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="999\n",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "auditctl" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="-w /etc/shadow -p wa\n",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "cat" in executable and "journald.conf" in args[0]:
                stdout_data = "Storage=volatile\n"
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
                returncode=1,
                stdout="",
                stderr="",
                duration_seconds=0.01,
                timed_out=False,
                missing_executable=False,
            )

        self.runner.run.side_effect = run_mock

        mod = AuditingModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Audit rules do not track process execution" in f.title for f in res.findings))
        self.assertTrue(any("Systemd journald storage is not persistent" in f.title for f in res.findings))

    async def test_syslog_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "cat" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="auth.* /var/log/auth.log\n",
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

        mod = SyslogModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Syslog remote log forwarding is not configured" in f.title for f in res.findings))
        self.assertTrue(any("Logrotate compression is disabled" in f.title for f in res.findings))

    async def test_time_sync_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "timedatectl" in executable:
                stdout_data = "System clock synchronized: no\nNTP service: inactive\n"
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
                returncode=1,
                stdout="",
                stderr="",
                duration_seconds=0.01,
                timed_out=False,
                missing_executable=False,
            )

        self.runner.run.side_effect = run_mock

        mod = TimeSyncModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("System time synchronization is inactive" in f.title for f in res.findings))

    async def test_agents_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "pgrep" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=1,
                    stdout="",
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

        mod = AgentsModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("fail2ban brute-force protection is not running" in f.title for f in res.findings))
        self.assertTrue(any("No active Host Intrusion Detection System" in f.title for f in res.findings))


if __name__ == "__main__":
    unittest.main()
