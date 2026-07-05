"""Tests for the OS scanner modules."""

from __future__ import annotations

import unittest
from dataclasses import fields
from pathlib import Path

from vina.models.common import TargetInput


def _target() -> TargetInput:
    return TargetInput.from_raw("localhost")


class SshModuleTests(unittest.TestCase):
    def test_import(self) -> None:
        from vina.scanners.os.ssh import SshModule, SshSetting, SshKeyEntry, SshResult
        self.assertTrue(SshModule)
        self.assertTrue(SshSetting)
        self.assertTrue(SshKeyEntry)
        self.assertTrue(SshResult)

    def test_result_dataclass_fields(self) -> None:
        from vina.scanners.os.ssh import SshResult
        fnames = {f.name for f in fields(SshResult)}
        self.assertIn("findings", fnames)
        self.assertIn("command_result", fnames)
        self.assertIn("warnings", fnames)
        self.assertIn("execution_time_seconds", fnames)

    def test_setting_dataclass(self) -> None:
        from vina.scanners.os.ssh import SshSetting
        s = SshSetting(key="PermitRootLogin", value="yes", source_file="/etc/ssh/sshd_config")
        self.assertEqual(s.key, "PermitRootLogin")
        self.assertEqual(s.value, "yes")


class CronModuleTests(unittest.TestCase):
    def test_import(self) -> None:
        from vina.scanners.os.cron import CronModule, CronEntry, CronDirEntry, CronResult
        self.assertTrue(CronModule)
        self.assertTrue(CronEntry)
        self.assertTrue(CronDirEntry)
        self.assertTrue(CronResult)

    def test_result_has_findings(self) -> None:
        from vina.scanners.os.cron import CronResult
        fnames = {f.name for f in fields(CronResult)}
        self.assertIn("findings", fnames)

    def test_entry_creation(self) -> None:
        from vina.scanners.os.cron import CronEntry
        e = CronEntry(schedule="0 5 * * *", command="/usr/bin/backup.sh", user="root", source="/etc/crontab")
        self.assertEqual(e.user, "root")
        self.assertEqual(e.command, "/usr/bin/backup.sh")
        self.assertEqual(e.schedule, "0 5 * * *")


class SystemdModuleTests(unittest.TestCase):
    def test_import(self) -> None:
        from vina.scanners.os.systemd import SystemdModule, SystemdServiceEntry, TimerEntry, SystemdResult
        self.assertTrue(SystemdModule)
        self.assertTrue(SystemdServiceEntry)
        self.assertTrue(TimerEntry)
        self.assertTrue(SystemdResult)

    def test_result_has_findings(self) -> None:
        from vina.scanners.os.systemd import SystemdResult
        fnames = {f.name for f in fields(SystemdResult)}
        self.assertIn("findings", fnames)

    def test_service_entry(self) -> None:
        from vina.scanners.os.systemd import SystemdServiceEntry
        s = SystemdServiceEntry(unit="ssh.service", state="enabled")
        self.assertEqual(s.unit, "ssh.service")
        self.assertEqual(s.state, "enabled")


class DockerModuleTests(unittest.TestCase):
    def test_import(self) -> None:
        from vina.scanners.os.docker import DockerModule, DockerContainerInfo, DockerResult
        self.assertTrue(DockerModule)
        self.assertTrue(DockerContainerInfo)
        self.assertTrue(DockerResult)

    def test_result_has_findings(self) -> None:
        from vina.scanners.os.docker import DockerResult
        fnames = {f.name for f in fields(DockerResult)}
        self.assertIn("findings", fnames)

    def test_container_info(self) -> None:
        from vina.scanners.os.docker import DockerContainerInfo
        c = DockerContainerInfo(container_id="abc123", image="nginx:latest", status="Up", privileged=True)
        self.assertEqual(c.container_id, "abc123")
        self.assertTrue(c.privileged)


class KernelModuleTests(unittest.TestCase):
    def test_import(self) -> None:
        from vina.scanners.os.kernel import KernelModule, LoadedKernelModule, SysctlSetting, KernelResult
        self.assertTrue(KernelModule)
        self.assertTrue(LoadedKernelModule)
        self.assertTrue(SysctlSetting)
        self.assertTrue(KernelResult)

    def test_result_has_findings(self) -> None:
        from vina.scanners.os.kernel import KernelResult
        fnames = {f.name for f in fields(KernelResult)}
        self.assertIn("findings", fnames)

    def test_sysctl_setting(self) -> None:
        from vina.scanners.os.kernel import SysctlSetting
        s = SysctlSetting(key="kernel.randomize_va_space", value="2", secure=True)
        self.assertEqual(s.key, "kernel.randomize_va_space")
        self.assertTrue(s.secure)

    def test_no_name_conflict(self) -> None:
        from vina.scanners.os.kernel import KernelModule, LoadedKernelModule
        km = LoadedKernelModule(name="tcpdump", size="50000", used_by="0")
        self.assertEqual(km.name, "tcpdump")
        self.assertIsNot(KernelModule, LoadedKernelModule)


class EnvironmentModuleTests(unittest.TestCase):
    def test_import(self) -> None:
        from vina.scanners.os.environment import EnvironmentModule, EnvVariable, PathEntry, EnvironmentResult
        self.assertTrue(EnvironmentModule)
        self.assertTrue(EnvVariable)
        self.assertTrue(PathEntry)
        self.assertTrue(EnvironmentResult)

    def test_result_has_findings(self) -> None:
        from vina.scanners.os.environment import EnvironmentResult
        fnames = {f.name for f in fields(EnvironmentResult)}
        self.assertIn("findings", fnames)

    def test_env_variable_sensitive(self) -> None:
        from vina.scanners.os.environment import EnvVariable
        v = EnvVariable(key="AWS_SECRET_ACCESS_KEY", value="secret123", sensitive=True)
        self.assertTrue(v.sensitive)


class ProcessesModuleTests(unittest.TestCase):
    def test_import(self) -> None:
        from vina.scanners.os.processes import ProcessesModule, ProcessInfo, ProcessesResult
        self.assertTrue(ProcessesModule)
        self.assertTrue(ProcessInfo)
        self.assertTrue(ProcessesResult)

    def test_result_has_findings(self) -> None:
        from vina.scanners.os.processes import ProcessesResult
        fnames = {f.name for f in fields(ProcessesResult)}
        self.assertIn("findings", fnames)

    def test_process_info(self) -> None:
        from vina.scanners.os.processes import ProcessInfo
        p = ProcessInfo(pid=1234, user="root", command="/usr/bin/sshd", running_as_root=True)
        self.assertEqual(p.pid, 1234)
        self.assertTrue(p.running_as_root)


class PackagesModuleTests(unittest.TestCase):
    def test_import(self) -> None:
        from vina.scanners.os.packages import PackagesModule, InstalledPackage, AptSourceEntry, PackagesResult
        self.assertTrue(PackagesModule)
        self.assertTrue(InstalledPackage)
        self.assertTrue(AptSourceEntry)
        self.assertTrue(PackagesResult)

    def test_result_has_findings(self) -> None:
        from vina.scanners.os.packages import PackagesResult
        fnames = {f.name for f in fields(PackagesResult)}
        self.assertIn("findings", fnames)

    def test_installed_package(self) -> None:
        from vina.scanners.os.packages import InstalledPackage
        p = InstalledPackage(name="openssh-server", version="1:8.9p1-3", held=False)
        self.assertEqual(p.name, "openssh-server")
        self.assertFalse(p.held)


class LogsModuleTests(unittest.TestCase):
    def test_import(self) -> None:
        from vina.scanners.os.logs import LogsModule, LogEntry, LogStatistics, LogsResult
        self.assertTrue(LogsModule)
        self.assertTrue(LogEntry)
        self.assertTrue(LogStatistics)
        self.assertTrue(LogsResult)

    def test_result_has_findings(self) -> None:
        from vina.scanners.os.logs import LogsResult
        fnames = {f.name for f in fields(LogsResult)}
        self.assertIn("findings", fnames)

    def test_log_statistics(self) -> None:
        from vina.scanners.os.logs import LogStatistics
        s = LogStatistics(failed_logins=5, sudo_events=10, root_logins=1)
        self.assertEqual(s.failed_logins, 5)
        self.assertEqual(s.root_logins, 1)

    def test_log_entry(self) -> None:
        from vina.scanners.os.logs import LogEntry
        e = LogEntry(timestamp="Jan 1 12:00:00", source="auth_log", message="Failed password for root from 10.0.0.1", event_type="failed_login")
        self.assertEqual(e.event_type, "failed_login")
        self.assertEqual(e.ip, "")


class SecretsModuleTests(unittest.TestCase):
    def test_import(self) -> None:
        from vina.scanners.os.secrets import SecretsModule, SecretFile, SecretsResult
        self.assertTrue(SecretsModule)
        self.assertTrue(SecretFile)
        self.assertTrue(SecretsResult)

    def test_result_has_findings(self) -> None:
        from vina.scanners.os.secrets import SecretsResult
        fnames = {f.name for f in fields(SecretsResult)}
        self.assertIn("findings", fnames)

    def test_secret_file(self) -> None:
        from vina.scanners.os.secrets import SecretFile
        s = SecretFile(path="/root/.ssh/id_rsa", type="ssh-key")
        self.assertEqual(s.path, "/root/.ssh/id_rsa")
        self.assertEqual(s.type, "ssh-key")


class OsPipelineRefactorTests(unittest.TestCase):
    def test_import_pipeline(self) -> None:
        from vina.scanners.os.os_pipeline import OSPipeline, OSPipelineResult
        self.assertTrue(OSPipeline)
        self.assertTrue(OSPipelineResult)

    def test_pipeline_result_fields(self) -> None:
        from vina.scanners.os.os_pipeline import OSPipelineResult
        fnames = {f.name for f in fields(OSPipelineResult)}
        self.assertIn("stage_results", fnames)
        self.assertIn("summary", fnames)

    def test_stage_deps_coverage(self) -> None:
        from vina.scanners.os.os_pipeline import _STAGE_DEPS
        expected_stages = {
            "host_recon", "system_info", "ssh", "kernel", "environment",
            "packages", "services", "users", "filesystem", "network",
            "processes", "cron", "systemd", "docker", "logs", "secrets",
            "capabilities", "sudo", "privilege_escalation",
        }
        self.assertEqual(set(_STAGE_DEPS.keys()), expected_stages)


if __name__ == "__main__":
    unittest.main()
