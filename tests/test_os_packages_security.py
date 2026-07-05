"""Tests for PS-03: Package Management and Software Supply Chain Security."""

from __future__ import annotations

import unittest
from dataclasses import fields
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from vina.core.config import AppConfig
from vina.core.runner import CommandResult
from vina.models.common import TargetInput
from vina.modules.common import ModuleContext
from vina.scanners.os.packages_security import PackagesSecurityModule, PackagesSecurityResult
from vina.scanners.os.packages_security.integrity import IntegrityModule, IntegrityResult
from vina.scanners.os.packages_security.inventory import InventoryModule, InventoryResult
from vina.scanners.os.packages_security.managers import PackageManagersModule, PackageManagersResult, SbomPackage
from vina.scanners.os.packages_security.repositories import RepositoriesModule, RepositoriesResult
from vina.scanners.os.packages_security.supply_chain import SupplyChainModule, SupplyChainResult, _levenshtein_distance


class PackagesSecurityPackageTests(unittest.TestCase):
    """Test that packages_security package and modules can be imported."""

    def test_import_package(self) -> None:
        self.assertTrue(PackagesSecurityModule)
        self.assertTrue(PackagesSecurityResult)

    def test_import_submodules(self) -> None:
        self.assertTrue(PackageManagersModule)
        self.assertTrue(PackageManagersResult)
        self.assertTrue(RepositoriesModule)
        self.assertTrue(RepositoriesResult)
        self.assertTrue(IntegrityModule)
        self.assertTrue(IntegrityResult)
        self.assertTrue(SupplyChainModule)
        self.assertTrue(SupplyChainResult)
        self.assertTrue(InventoryModule)
        self.assertTrue(InventoryResult)


class PackagesSecurityResultTests(unittest.TestCase):
    """Test that PackagesSecurityResult has the expected fields."""

    def test_result_fields(self) -> None:
        fnames = {f.name for f in fields(PackagesSecurityResult)}
        self.assertIn("findings", fnames)
        self.assertIn("command_result", fnames)
        self.assertIn("warnings", fnames)
        self.assertIn("output_file", fnames)
        self.assertIn("managers", fnames)
        self.assertIn("repositories", fnames)
        self.assertIn("integrity", fnames)
        self.assertIn("supply_chain", fnames)
        self.assertIn("inventory", fnames)


class LevenshteinDistanceTests(unittest.TestCase):
    """Test Levenshtein distance calculations for typosquatting."""

    def test_levenshtein_distance(self) -> None:
        self.assertEqual(_levenshtein_distance("requests", "requests"), 0)
        self.assertEqual(_levenshtein_distance("reqeusts", "requests"), 2)
        self.assertEqual(_levenshtein_distance("pythn", "python"), 1)
        self.assertEqual(_levenshtein_distance("pythnn", "python"), 1)
        self.assertEqual(_levenshtein_distance("abc", ""), 3)


class PackagesSecurityModuleTests(unittest.IsolatedAsyncioTestCase):
    """Test PackagesSecurityModule and sub-scanners with mocked runners."""

    def setUp(self) -> None:
        self.config = AppConfig()
        self.runner = AsyncMock()
        self.store = MagicMock()
        self.context = ModuleContext(runner=self.runner, store=self.store, timeout_seconds=10)
        self.target = TargetInput.from_raw("localhost")

    async def test_package_managers_scanner(self) -> None:
        # Mock successful dpkg-query and pip list json
        dpkg_output = "openssl\t1.1.1f-1ubuntu2\tamd64\tUbuntu Developers\n"
        pip_output = '[{"name": "reqeusts", "version": "2.25.1"}]'

        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "dpkg-query" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout=dpkg_output,
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "pip" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout=pip_output,
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
                stderr="command not found",
                duration_seconds=0.01,
                timed_out=False,
                missing_executable=True,
            )

        self.runner.run.side_effect = run_mock

        mod = PackageManagersModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any(p.name == "openssl" for p in res.packages))
        self.assertTrue(any(p.name == "reqeusts" for p in res.packages))
        self.assertIn("dpkg", res.managers_found)

    async def test_repositories_scanner(self) -> None:
        sources_list = (
            "deb http://archive.ubuntu.com/ubuntu focal main\n"
            "deb [trusted=yes] http://malicious.xyz/repo focal main\n"
        )

        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "cat" in executable and "/etc/apt/sources.list" in args:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout=sources_list,
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "apt-key" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="pub   1024D/437D05B5 2004-09-12 [expired: 2024-09-12]",
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

        mod = RepositoriesModule(self.config, self.context)
        res = await mod.run(self.target)

        # Check for HTTP, override (trusted=yes), expired keys, duplicate, and weak GPG key findings
        self.assertTrue(any("Insecure HTTP repository" in f.title for f in res.findings))
        self.assertTrue(any("Unsigned package repository override" in f.title for f in res.findings))
        self.assertTrue(any("Expired repository GPG keys" in f.title for f in res.findings))

    async def test_integrity_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "apt-mark" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="bash\n",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "debsums" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=1,
                    stdout="/bin/ls\n",
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

        mod = IntegrityModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Held packages" in f.title for f in res.findings))
        self.assertTrue(any("Modified package files" in f.title for f in res.findings))

    async def test_supply_chain_scanner(self) -> None:
        pkgs = [
            SbomPackage(name="reqeusts", version="2.25.1", manager="pip"),
            SbomPackage(name="numpy", version="1.20.0", manager="pip"),
        ]

        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "ls" in executable and "/usr/local/bin/" in args:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="malicious-bin\n",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "dpkg" in executable and "-S" in args:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=1,
                    stdout="",
                    stderr="dpkg-query: no path found matching pattern /usr/local/bin/malicious-bin",
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

        mod = SupplyChainModule(self.config, self.context)
        res = await mod.run(self.target, pkgs)

        # Typosquatting for 'reqeusts' matching 'requests', manually installed binary 'malicious-bin'
        self.assertTrue(any("Potential typosquatting package" in f.title for f in res.findings))
        self.assertTrue(any("Manually installed binaries in system path" in f.title for f in res.findings))


if __name__ == "__main__":
    unittest.main()
