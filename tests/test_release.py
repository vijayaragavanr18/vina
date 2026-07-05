"""Tests for VINA release engineering system."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vina._version import __version__, VERSION_INFO, version_str, version_tuple


# =========================================================================
#  Version module
# =========================================================================


class TestVersion:
    def test_version_string(self):
        assert isinstance(__version__, str)
        parts = __version__.split(".")
        assert len(parts) == 3

    def test_version_info(self):
        assert VERSION_INFO["major"] == 0
        assert VERSION_INFO["minor"] == 1
        assert VERSION_INFO["patch"] == 0

    def test_version_str(self):
        assert version_str() == __version__

    def test_version_tuple(self):
        t = version_tuple()
        assert isinstance(t, tuple)
        assert len(t) == 3
        assert all(isinstance(x, int) for x in t)

    def test_vina_init_exports(self):
        import vina
        assert hasattr(vina, "__version__")
        assert hasattr(vina, "version_str")
        assert hasattr(vina, "version_tuple")
        assert vina.__version__ == __version__


# =========================================================================
#  CLI commands: version / doctor
# =========================================================================


class TestVersionCommand:
    @staticmethod
    def _command_names():
        from vina.cli import app
        return {cmd.callback.__name__ for cmd in app.registered_commands}

    def test_version_command_registered(self):
        assert "version" in self._command_names()

    def test_doctor_command_registered(self):
        assert "doctor" in self._command_names()


class TestDoctor:
    def test_doctor_checks_python_version(self):
        import sys
        major, minor = sys.version_info[:2]
        assert (major, minor) >= (3, 12), f"Python {major}.{minor} < 3.12"

    def test_doctor_writable_dirs(self):
        dirs = [
            Path.home() / ".vina" / "cache",
            Path.home() / ".vina" / "feeds",
            Path.home() / ".vina" / "plugins",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
            test_file = d / ".write_test"
            test_file.write_text("ok")
            assert test_file.exists()
            test_file.unlink()

    def test_doctor_imports(self):
        """All modules referenced by doctor should be importable."""
        from vina.core.config import AppConfig
        from vina.core.dependency import DependencyChecker
        from vina.core.feed_manager import FeedManager
        from vina.core.vuln_intel import get_default_db
        from vina.plugins.registry import get_registry
        assert AppConfig
        assert DependencyChecker
        assert FeedManager
        assert get_default_db
        assert get_registry


# =========================================================================
#  pyproject.toml
# =========================================================================


class TestPyproject:
    def test_pyproject_exists(self):
        root = Path(__file__).parent.parent
        assert (root / "pyproject.toml").exists()

    def test_extras_defined(self):
        import tomllib
        root = Path(__file__).parent.parent
        data = tomllib.loads((root / "pyproject.toml").read_text())
        optional = data["project"]["optional-dependencies"]
        assert "dev" in optional
        assert "testing" in optional
        assert "plugins" in optional
        assert "docs" in optional
        assert "release" in optional
        assert "full" in optional

    def test_scripts_defined(self):
        import tomllib
        root = Path(__file__).parent.parent
        data = tomllib.loads((root / "pyproject.toml").read_text())
        assert data["project"]["scripts"]["vina"] == "vina.cli:app"


# =========================================================================
#  Docker files
# =========================================================================


class TestDockerFiles:
    def test_dockerfile_exists(self):
        root = Path(__file__).parent.parent
        assert (root / "Dockerfile").exists()

    def test_dockerfile_dev_exists(self):
        root = Path(__file__).parent.parent
        assert (root / "Dockerfile.dev").exists()

    def test_docker_compose_exists(self):
        root = Path(__file__).parent.parent
        assert (root / "docker-compose.yml").exists()

    def test_dockerfile_has_nonroot_user(self):
        root = Path(__file__).parent.parent
        content = (root / "Dockerfile").read_text()
        assert "useradd" in content or "USER" in content
        assert "USER vina" in content

    def test_dockerfile_has_volumes(self):
        root = Path(__file__).parent.parent
        content = (root / "Dockerfile").read_text()
        assert "VOLUME" in content

    def test_dockerfile_entrypoint(self):
        root = Path(__file__).parent.parent
        content = (root / "Dockerfile").read_text()
        assert "ENTRYPOINT" in content

    def test_compose_has_services(self):
        import yaml
        root = Path(__file__).parent.parent
        data = yaml.safe_load((root / "docker-compose.yml").read_text())
        assert "services" in data
        assert "vina" in data["services"]
        assert "vina-dev" in data["services"]


# =========================================================================
#  CI/CD workflows
# =========================================================================


class TestCIWorkflows:
    def test_ci_workflow_exists(self):
        root = Path(__file__).parent.parent
        wf = root / ".github" / "workflows" / "ci.yml"
        assert wf.exists(), f"CI workflow not found at {wf}"

    def test_release_workflow_exists(self):
        root = Path(__file__).parent.parent
        wf = root / ".github" / "workflows" / "release.yml"
        assert wf.exists(), f"Release workflow not found at {wf}"

    def test_ci_has_lint_job(self):
        import yaml
        root = Path(__file__).parent.parent
        data = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
        assert "lint" in data["jobs"]

    def test_ci_has_typecheck_job(self):
        import yaml
        root = Path(__file__).parent.parent
        data = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
        assert "typecheck" in data["jobs"]

    def test_ci_has_security_job(self):
        import yaml
        root = Path(__file__).parent.parent
        data = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
        assert "security" in data["jobs"]

    def test_ci_has_unit_job(self):
        import yaml
        root = Path(__file__).parent.parent
        data = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
        assert "unit" in data["jobs"]

    def test_ci_has_integration_job(self):
        import yaml
        root = Path(__file__).parent.parent
        data = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
        assert "integration" in data["jobs"]

    def test_ci_has_benchmark_job(self):
        import yaml
        root = Path(__file__).parent.parent
        data = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
        assert "benchmark" in data["jobs"]

    def test_ci_has_build_job(self):
        import yaml
        root = Path(__file__).parent.parent
        data = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
        assert "build" in data["jobs"]

    def test_ci_has_quality_gate(self):
        import yaml
        root = Path(__file__).parent.parent
        data = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
        assert "qualify" in data["jobs"]

    def test_release_has_docker_job(self):
        import yaml
        root = Path(__file__).parent.parent
        data = yaml.safe_load((root / ".github/workflows/release.yml").read_text())
        assert "docker" in data["jobs"]

    def test_release_has_release_job(self):
        import yaml
        root = Path(__file__).parent.parent
        data = yaml.safe_load((root / ".github/workflows/release.yml").read_text())
        assert "release" in data["jobs"]


# =========================================================================
#  Configuration files
# =========================================================================


class TestConfigFiles:
    def test_pre_commit_config_exists(self):
        root = Path(__file__).parent.parent
        assert (root / ".pre-commit-config.yaml").exists()

    def test_gitignore_exists(self):
        root = Path(__file__).parent.parent
        assert (root / ".gitignore").exists()

    def test_gitignore_has_dist(self):
        root = Path(__file__).parent.parent
        content = (root / ".gitignore").read_text()
        assert "dist/" in content

    def test_pyproject_has_ruff_config(self):
        import tomllib
        root = Path(__file__).parent.parent
        data = tomllib.loads((root / "pyproject.toml").read_text())
        assert "tool" in data
        assert "ruff" in data["tool"]

    def test_pyproject_has_black_config(self):
        import tomllib
        root = Path(__file__).parent.parent
        data = tomllib.loads((root / "pyproject.toml").read_text())
        assert "black" in data["tool"]

    def test_pyproject_has_mypy_config(self):
        import tomllib
        root = Path(__file__).parent.parent
        data = tomllib.loads((root / "pyproject.toml").read_text())
        assert "mypy" in data["tool"]

    def test_pyproject_has_bandit_config(self):
        import tomllib
        root = Path(__file__).parent.parent
        data = tomllib.loads((root / "pyproject.toml").read_text())
        assert "bandit" in data["tool"]

    def test_pyproject_has_pytest_config(self):
        import tomllib
        root = Path(__file__).parent.parent
        data = tomllib.loads((root / "pyproject.toml").read_text())
        assert "pytest" in data["tool"]

    def test_pyproject_has_coverage_config(self):
        import tomllib
        root = Path(__file__).parent.parent
        data = tomllib.loads((root / "pyproject.toml").read_text())
        assert "coverage" in data["tool"]

    def test_pyproject_has_entry_point_group(self):
        import tomllib
        root = Path(__file__).parent.parent
        data = tomllib.loads((root / "pyproject.toml").read_text())
        assert "project" in data
        assert "entry-points" in data["project"]
        assert "vina.plugins" in data["project"]["entry-points"]


# =========================================================================
#  Documentation
# =========================================================================


class TestDocumentation:
    def test_developer_guide_exists(self):
        root = Path(__file__).parent.parent
        assert (root / "docs" / "DEVELOPER_GUIDE.md").exists()

    def test_plugin_author_guide_exists(self):
        root = Path(__file__).parent.parent
        assert (root / "docs" / "PLUGIN_AUTHOR_GUIDE.md").exists()

    def test_architecture_guide_exists(self):
        root = Path(__file__).parent.parent
        assert (root / "docs" / "ARCHITECTURE_GUIDE.md").exists()

    def test_contributing_guide_exists(self):
        root = Path(__file__).parent.parent
        assert (root / "docs" / "CONTRIBUTING.md").exists()

    def test_release_guide_exists(self):
        root = Path(__file__).parent.parent
        assert (root / "docs" / "RELEASE_GUIDE.md").exists()


# =========================================================================
#  Release script
# =========================================================================


class TestReleaseScript:
    def test_script_exists(self):
        root = Path(__file__).parent.parent
        script = root / "scripts" / "release.sh"
        assert script.exists()

    def test_script_is_executable(self):
        root = Path(__file__).parent.parent
        script = root / "scripts" / "release.sh"
        assert script.stat().st_mode & 0o111, "Script is not executable"


# =========================================================================
#  Benchmark CLI commands
# =========================================================================


class TestBenchmarkCommands:
    @staticmethod
    def _command_names():
        from vina.cli import app
        return {cmd.callback.__name__ for cmd in app.registered_commands}

    def test_benchmark_list_registered(self):
        assert "benchmark_list" in self._command_names()

    def test_benchmark_run_registered(self):
        assert "benchmark_run" in self._command_names()

    def test_benchmark_compare_registered(self):
        assert "benchmark_compare" in self._command_names()

    def test_benchmark_report_registered(self):
        assert "benchmark_report" in self._command_names()


# =========================================================================
#  Plugin CLI commands
# =========================================================================


class TestPluginCommands:
    @staticmethod
    def _command_names():
        from vina.cli import app
        return {cmd.callback.__name__ for cmd in app.registered_commands}

    def test_plugin_list_registered(self):
        assert "plugin_list" in self._command_names()

    def test_plugin_info_registered(self):
        assert "plugin_info" in self._command_names()

    def test_plugin_enable_registered(self):
        assert "plugin_enable" in self._command_names()

    def test_plugin_disable_registered(self):
        assert "plugin_disable" in self._command_names()

    def test_plugin_doctor_registered(self):
        assert "plugin_doctor" in self._command_names()


# =========================================================================
#  CLI scan commands
# =========================================================================


class TestScanCommands:
    @staticmethod
    def _command_names():
        from vina.cli import app
        return {cmd.callback.__name__ for cmd in app.registered_commands}

    def test_scan_registered(self):
        assert "scan" in self._command_names()

    def test_scan_os_registered(self):
        assert "scan_os" in self._command_names()

    def test_scan_web_registered(self):
        assert "scan_web" in self._command_names()

    def test_report_registered(self):
        assert "report" in self._command_names()

    def test_update_db_registered(self):
        assert "update_db" in self._command_names()
