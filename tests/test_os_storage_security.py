"""Tests for PS-07: File System, Permissions, and Storage Security."""

from __future__ import annotations

import unittest
from dataclasses import fields
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from vina.core.config import AppConfig
from vina.core.runner import CommandResult
from vina.models.common import TargetInput
from vina.modules.common import ModuleContext
from vina.scanners.os.storage_security import StorageSecurityModule, StorageSecurityResult
from vina.scanners.os.storage_security.encryption import EncryptionModule
from vina.scanners.os.storage_security.integrity import IntegrityModule
from vina.scanners.os.storage_security.mounts import MountsModule
from vina.scanners.os.storage_security.permissions import PermissionsModule


class StorageSecurityPackageTests(unittest.TestCase):
    """Test that storage_security package and modules can be imported."""

    def test_import_package(self) -> None:
        self.assertTrue(StorageSecurityModule)
        self.assertTrue(PermissionsModule)
        self.assertTrue(MountsModule)
        self.assertTrue(EncryptionModule)
        self.assertTrue(IntegrityModule)

    def test_result_schemas(self) -> None:
        result_fields = {f.name for f in fields(StorageSecurityResult)}
        self.assertIn("target", result_fields)
        self.assertIn("permissions", result_fields)
        self.assertIn("mounts", result_fields)
        self.assertIn("encryption", result_fields)
        self.assertIn("integrity", result_fields)
        self.assertIn("findings", result_fields)
        self.assertIn("warnings", result_fields)


class StorageSecurityModuleTests(unittest.IsolatedAsyncioTestCase):
    """Test StorageSecurityModule and sub-scanners with mocked runners."""

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

    async def test_permissions_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "stat" in executable:
                stdout_data = "666 root shadow\n" if "/etc/shadow" in args else "600 root root\n"
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
                    stdout="/usr/bin/test-suid\n",
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

        mod = PermissionsModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("shadow permissions are too open" in f.title for f in res.findings))
        self.assertTrue(any("SUID/SGID files detected" in f.title for f in res.findings))

    async def test_mounts_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "cat" in executable and "/proc/mounts" in args:
                stdout_data = (
                    "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
                    "tmpfs /tmp tmpfs rw,relatime 0 0\n"
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
            elif "cat" in executable and "/etc/exports" in args:
                stdout_data = "/shared 192.168.1.0/24(rw,sync,no_root_squash)\n"
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

        mod = MountsModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Insecure mount options on /tmp" in f.title for f in res.findings))
        self.assertTrue(any("NFS exports configured with no_root_squash" in f.title for f in res.findings))

    async def test_encryption_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "lsblk" in executable:
                stdout_data = "sda disk\n"
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
            elif "cat" in executable and "/proc/swaps" in args:
                stdout_data = (
                    "Filename\tType\tSize\tUsed\tPriority\n"
                    "/dev/sda2\tpartition\t2097148\t0\t-2\n"
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

        mod = EncryptionModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("System lacks full-disk encryption" in f.title for f in res.findings))
        self.assertTrue(any("Unencrypted swap space configured" in f.title for f in res.findings))

    async def test_integrity_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "which" in executable:
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
            elif "lsattr" in executable:
                stdout_data = "----i-------- /etc/passwd\n"
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

        mod = IntegrityModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("File Integrity Monitoring (FIM) not configured" in f.title for f in res.findings))
        self.assertTrue(any("Immutable system configuration files detected" in f.title for f in res.findings))


if __name__ == "__main__":
    unittest.main()
