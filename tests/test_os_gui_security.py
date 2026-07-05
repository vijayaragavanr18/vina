"""Tests for PS-06: Desktop Environment and GUI Layer Security."""

from __future__ import annotations

import unittest
from dataclasses import fields
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from vina.core.config import AppConfig
from vina.core.runner import CommandResult
from vina.models.common import TargetInput
from vina.modules.common import ModuleContext
from vina.scanners.os.gui_security import GuiSecurityModule, GuiSecurityResult
from vina.scanners.os.gui_security.browsers import BrowsersModule
from vina.scanners.os.gui_security.desktop import DesktopModule
from vina.scanners.os.gui_security.polkit import PolkitModule
from vina.scanners.os.gui_security.remote_desktop import RemoteDesktopModule


class GuiSecurityPackageTests(unittest.TestCase):
    """Test that gui_security package and modules can be imported."""

    def test_import_package(self) -> None:
        self.assertTrue(GuiSecurityModule)
        self.assertTrue(DesktopModule)
        self.assertTrue(RemoteDesktopModule)
        self.assertTrue(BrowsersModule)
        self.assertTrue(PolkitModule)

    def test_result_schemas(self) -> None:
        result_fields = {f.name for f in fields(GuiSecurityResult)}
        self.assertIn("target", result_fields)
        self.assertIn("desktop", result_fields)
        self.assertIn("remote_desktop", result_fields)
        self.assertIn("browsers", result_fields)
        self.assertIn("polkit", result_fields)
        self.assertIn("findings", result_fields)
        self.assertIn("warnings", result_fields)


class GuiSecurityModuleTests(unittest.IsolatedAsyncioTestCase):
    """Test GuiSecurityModule and sub-scanners with mocked runners."""

    def setUp(self) -> None:
        self.config = AppConfig()
        self.runner = AsyncMock()
        self.store = MagicMock()
        self.context = ModuleContext(runner=self.runner, store=self.store, timeout_seconds=10)
        self.target = TargetInput.from_raw("localhost")

    async def test_desktop_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "cat" in executable:
                stdout_data = "[daemon]\n" "AutomaticLoginEnable=true\n" "AutomaticLogin=user1\n"
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
            elif "find" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "pgrep" in executable:
                if "wayland" in args:
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
                    returncode=0,
                    stdout="1234\n",
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

        mod = DesktopModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("GDM automatic login enabled" in f.title for f in res.findings))
        self.assertTrue(any("Legacy X11 windowing system active" in f.title for f in res.findings))

    async def test_remote_desktop_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "pgrep" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="5678\n",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "cat" in executable and "/etc/xrdp/xrdp.ini" in args:
                stdout_data = "security_layer=rdp\n" "crypt_level=low\n"
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

        mod = RemoteDesktopModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Active VNC server session detected" in f.title for f in res.findings))
        self.assertTrue(any("Insecure security layer configured in xrdp" in f.title for f in res.findings))
        self.assertTrue(any("Weak encryption level configured in xrdp" in f.title for f in res.findings))

    async def test_browsers_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "cat" in executable and "policies.json" in args[0]:
                stdout_data = '{"policies": {"DisableSecurityBypasses": false}}'
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

        mod = BrowsersModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Firefox security bypasses are allowed in policy" in f.title for f in res.findings))

    async def test_polkit_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "stat" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="755 guest guest\n",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "find" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="/etc/polkit-1/rules.d/99-test.rules\n",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "cat" in executable:
                stdout_data = (
                    "polkit.addRule(function(action, subject) {\n"
                    '  if (action.id == "org.freedesktop.policykit.exec") {\n'
                    "    return polkit.Result.YES;\n"
                    "  }\n"
                    "});\n"
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
                returncode=1,
                stdout="",
                stderr="",
                duration_seconds=0.01,
                timed_out=False,
                missing_executable=False,
            )

        self.runner.run.side_effect = run_mock

        mod = PolkitModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("pkexec binary is not owned by root" in f.title for f in res.findings))
        self.assertTrue(any("Polkit rule allows passwordless privilege escalation" in f.title for f in res.findings))


if __name__ == "__main__":
    unittest.main()
