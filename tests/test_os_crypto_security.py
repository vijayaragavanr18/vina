"""Tests for PS-09: Cryptographic Implementation and Configuration."""

from __future__ import annotations

import unittest
from dataclasses import fields
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from vina.core.config import AppConfig
from vina.core.runner import CommandResult
from vina.models.common import TargetInput
from vina.modules.common import ModuleContext
from vina.scanners.os.crypto_security import CryptoSecurityModule, CryptoSecurityResult
from vina.scanners.os.crypto_security.kernel_crypto import KernelCryptoModule
from vina.scanners.os.crypto_security.ssh_ciphers import SshCiphersModule
from vina.scanners.os.crypto_security.ssl_certs import SslCertsModule


class CryptoSecurityPackageTests(unittest.TestCase):
    """Test that crypto_security package and modules can be imported."""

    def test_import_package(self) -> None:
        self.assertTrue(CryptoSecurityModule)
        self.assertTrue(SslCertsModule)
        self.assertTrue(SshCiphersModule)
        self.assertTrue(KernelCryptoModule)

    def test_result_schemas(self) -> None:
        result_fields = {f.name for f in fields(CryptoSecurityResult)}
        self.assertIn("target", result_fields)
        self.assertIn("ssl_certs", result_fields)
        self.assertIn("ssh_ciphers", result_fields)
        self.assertIn("kernel_crypto", result_fields)
        self.assertIn("findings", result_fields)
        self.assertIn("warnings", result_fields)


class CryptoSecurityModuleTests(unittest.IsolatedAsyncioTestCase):
    """Test CryptoSecurityModule and sub-scanners with mocked runners."""

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

    async def test_ssl_certs_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "find" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="/etc/ssl/private/key.pem\n",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "stat" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="666 root root\n",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "cat" in executable and "openssl.cnf" in args[0]:
                stdout_data = "MinProtocol = TLSv1\n"
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

        mod = SslCertsModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("SSL/TLS private keys have insecure permissions" in f.title for f in res.findings))
        self.assertTrue(any("OpenSSL configured with legacy TLS/SSL" in f.title for f in res.findings))

    async def test_ssh_ciphers_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "cat" in executable:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="Ciphers aes128-cbc,3des-cbc\nMacs hmac-md5,hmac-sha1\n",
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

        mod = SshCiphersModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Insecure SSH Ciphers enabled" in f.title for f in res.findings))
        self.assertTrue(any("Insecure SSH MAC algorithms enabled" in f.title for f in res.findings))

    async def test_kernel_crypto_scanner(self) -> None:
        def run_mock(executable: str, args: list[str], **_kwargs: Any) -> CommandResult:
            if "cat" in executable and "fips_enabled" in args[0]:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="0\n",
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                    missing_executable=False,
                )
            elif "cat" in executable and "entropy_avail" in args[0]:
                return CommandResult(
                    command=executable,
                    args=tuple(args),
                    returncode=0,
                    stdout="128\n",
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

        mod = KernelCryptoModule(self.config, self.context)
        res = await mod.run(self.target)

        self.assertTrue(any("Kernel FIPS mode is disabled" in f.title for f in res.findings))
        self.assertTrue(any("Low available kernel entropy" in f.title for f in res.findings))


if __name__ == "__main__":
    unittest.main()
