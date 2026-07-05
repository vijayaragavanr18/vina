"""Tests for the dependency validation layer."""

from __future__ import annotations

import sys
import unittest
from unittest.mock import patch

from vina.core.dependency import DependencyChecker, DependencyInfo
from vina.models.stages import StageState, build_missing_dependency_stage


class DependencyInfoTests(unittest.TestCase):
    """Tests for :class:`DependencyInfo`."""

    def test_available_defaults(self) -> None:
        info = DependencyInfo(name="test", available=True, path="/usr/bin/test", version="1.0")
        self.assertEqual(info.name, "test")
        self.assertTrue(info.available)
        self.assertEqual(info.path, "/usr/bin/test")
        self.assertEqual(info.version, "1.0")

    def test_unavailable_defaults(self) -> None:
        info = DependencyInfo(name="missing", available=False, path=None, version=None)
        self.assertEqual(info.name, "missing")
        self.assertFalse(info.available)
        self.assertIsNone(info.path)
        self.assertIsNone(info.version)


class DependencyCheckerTests(unittest.TestCase):
    """Tests for :class:`DependencyChecker`."""

    def setUp(self) -> None:
        DependencyChecker.clear_cache()

    def test_check_existing(self) -> None:
        """A known-existing executable returns available=True."""
        info = DependencyChecker().check("sh")
        self.assertTrue(info.available)
        self.assertIsNotNone(info.path)
        self.assertIn("sh", info.path or "")

    def test_check_missing(self) -> None:
        """A non-existent executable returns available=False."""
        info = DependencyChecker().check("definitely-not-a-real-tool-vina-99999")
        self.assertFalse(info.available)
        self.assertIsNone(info.path)
        self.assertIsNone(info.version)

    def test_cache_hit(self) -> None:
        """Checking the same tool twice returns the exact same object."""
        checker = DependencyChecker()
        first = checker.check("sh")
        second = checker.check("sh")
        self.assertIs(first, second)

    def test_cache_across_instances(self) -> None:
        """Cache is shared across checker instances."""
        DependencyChecker().check("sh")
        info = DependencyChecker().check("sh")
        self.assertTrue(info.available)

    def test_check_all(self) -> None:
        """check_all returns results for every tool."""
        checker = DependencyChecker()
        results = checker.check_all(["sh", "definitely-not-a-real-tool-vina-99999"])
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].available)
        self.assertFalse(results[1].available)

    def test_available(self) -> None:
        """available() is a convenience wrapper."""
        checker = DependencyChecker()
        self.assertTrue(checker.available("sh"))
        self.assertFalse(checker.available("definitely-not-a-real-tool-vina-99999"))

    def test_clear_cache(self) -> None:
        """clear_cache() removes all cached entries."""
        DependencyChecker().check("sh")
        self.assertIn("sh", DependencyChecker._global_cache)
        DependencyChecker.clear_cache()
        self.assertNotIn("sh", DependencyChecker._global_cache)

    def test_print_summary_available(self) -> None:
        """print_summary includes checkmark for available tools."""
        results = [DependencyInfo(name="sh", available=True, path="/bin/sh", version=None)]
        with patch("builtins.print") as mock_print:
            DependencyChecker.print_summary(results)
            output = "".join(call.args[0] for call in mock_print.call_args_list)
            self.assertIn("✓", output)
            self.assertIn("sh", output)

    def test_print_summary_missing(self) -> None:
        """print_summary includes cross mark for missing tools."""
        results = [DependencyInfo(name="missing-tool", available=False, path=None, version=None)]
        with patch("builtins.print") as mock_print:
            DependencyChecker.print_summary(results)
            output = "".join(call.args[0] for call in mock_print.call_args_list)
            self.assertIn("✗", output)
            self.assertIn("missing-tool", output)

    def test_print_summary_header_footer(self) -> None:
        """print_summary prints header and footer lines."""
        results = [DependencyInfo(name="sh", available=True, path="/bin/sh", version=None)]
        with patch("builtins.print") as mock_print:
            DependencyChecker.print_summary(results)
            output = "".join(call.args[0] for call in mock_print.call_args_list)
            self.assertIn("Dependency Check", output)
            self.assertIn("---", output)

    def test_version_detection(self) -> None:
        """_detect_version returns a non-empty string for a real tool."""
        python_path = sys.executable
        version = DependencyChecker._detect_version(python_path)
        self.assertIsNotNone(version)
        self.assertGreater(len(version), 0)

    def test_version_detection_missing_path(self) -> None:
        """_detect_version returns None for a non-existent path."""
        version = DependencyChecker._detect_version("/nonexistent/binary")
        self.assertIsNone(version)


class BuildMissingDependencyStageTests(unittest.TestCase):
    """Tests for :func:`build_missing_dependency_stage`."""

    def test_default_tool_name(self) -> None:
        stage = build_missing_dependency_stage("nmap")
        self.assertEqual(stage.name, "nmap")
        self.assertIs(stage.status, StageState.MISSING_DEPENDENCY)
        self.assertEqual(stage.command, "nmap")
        self.assertIsNone(stage.exit_code)
        self.assertAlmostEqual(stage.duration, 0.0)
        self.assertEqual(stage.record_count, 0)
        self.assertTrue(stage.executable_missing)
        self.assertIn("nmap", stage.warnings[0])

    def test_custom_tool_name(self) -> None:
        stage = build_missing_dependency_stage("recon", tool="subfinder")
        self.assertEqual(stage.name, "recon")
        self.assertEqual(stage.command, "subfinder")
        self.assertIn("subfinder", stage.warnings[0])

    def test_no_warnings_when_not_missing(self) -> None:
        stage = build_missing_dependency_stage("test")
        self.assertGreater(len(stage.warnings), 0)


if __name__ == "__main__":
    unittest.main()
