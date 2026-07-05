"""Tests for PS-05: Boot Process, GRUB, and Secure Boot Security."""

from __future__ import annotations

import unittest
from dataclasses import fields
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from vina.core.config import AppConfig
from vina.core.runner import CommandResult
from vina.models.common import TargetInput
from vina.modules.common import ModuleContext
from vina.scanners.os.boot_security import BootSecurityModule, BootSecurityResult
from vina.scanners.os.boot_security.boot_files import BootFilesModule
from vina.scanners.os.boot_security.grub import GrubModule
from vina.scanners.os.boot_security.kernel_params import KernelParamsModule
from vina.scanners.os.boot_security.secure_boot import SecureBootModule


class BootSecurityPackageTests(unittest.TestCase):
    """Test that boot_security package and modules can be imported."""

    def test_import_package(self) -> None:
        self.assertTrue(BootSecurityModule)
        self.assertTrue(GrubModule)
        self.assertTrue(SecureBootModule)
        self.assertTrue(KernelParamsModule)
        self.assertTrue(BootFilesModule)

    def test_result_schemas(self) -> None:
        result_fields = {f.name for f in fields(BootSecurityResult)}
        self.assertIn("target", result_fields)
        self.assertIn("grub", result_fields)
        self.assertIn("secure_boot", result_fields)
        self.assertIn("kernel_params", result_fields)
        self.assertIn("boot_files", result_fields)
        self.assertIn("findings", result_fields)
        self.assertIn("warnings", result_fields)


class BootSecurityModuleTests(unittest.IsolatedAsyncioTestCase):
    """Test BootSecurityModule and sub-scanners with mocked runners."""

    def setUp(self) -> None:
        self.config = AppConfig()
        self.runner = AsyncMock()
        self.store = MagicMock()
        self.context = ModuleContext(runner=self.runner, store=self.store, timeout_seconds=10)
        self.target = TargetInput.from_raw("localhost")

    async def test_grub_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "stat" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="755 root root\n",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "cat" in executable:
                stdout_data = "menuentry 'Ubuntu' --unrestricted {\n" "  linux /vmlinuz root=/dev/sda1\n" "}\n"
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

        mod = GrubModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("GRUB configuration file permissions are too open" in f.title for f in res.findings))
        self.assertTrue(any("GRUB bootloader is not password protected" in f.title for f in res.findings))

    async def test_secure_boot_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "mokutil" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="SecureBoot disabled\n",
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

        mod = SecureBootModule(self.config, self.context)
        res = await mod.run(self.target)

        has_sb_finding = any(
            "System booted in Legacy BIOS mode" in f.title or "UEFI Secure Boot is disabled" in f.title
            for f in res.findings
        )
        self.assertTrue(has_sb_finding)

    async def test_kernel_params_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "cat" in executable and "/proc/cmdline" in args:
                stdout_data = "BOOT_IMAGE=/vmlinuz init=/bin/sh mitigations=off apparmor=0\n"
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

        mod = KernelParamsModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Vulnerable kernel boot parameter: init=/bin/sh" in f.title for f in res.findings))
        self.assertTrue(any("Kernel speculative execution mitigations are disabled" in f.title for f in res.findings))
        self.assertTrue(any("AppArmor disabled in kernel boot parameters" in f.title for f in res.findings))

    async def test_boot_files_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "find" in executable and "/boot" in args:
                if "! -user root" in " ".join(args):
                    stdout_data = "/boot/vmlinuz-bad guest\n"
                elif "-perm -002" in " ".join(args):
                    stdout_data = "/boot/grub/grub.cfg\n"
                else:
                    stdout_data = ""
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

        mod = BootFilesModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Boot files not owned by root" in f.title for f in res.findings))
        self.assertTrue(any("World-writable files detected in /boot" in f.title for f in res.findings))


if __name__ == "__main__":
    unittest.main()
