"""Tests for stage state management."""

from __future__ import annotations

import unittest

from vina.core.runner import CommandResult
from vina.models.stages import (
    StageResult,
    StageState,
    build_skipped_stage,
    build_stage_result,
    determine_stage_status,
    summary_for_stages,
)


def _cr(
    *,
    returncode: int | None = 0,
    timed_out: bool = False,
    missing_executable: bool = False,
    stdout: str = "output",
    stderr: str = "",
) -> CommandResult:
    return CommandResult(
        command="test-tool",
        args=("--flag",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=1.5,
        timed_out=timed_out,
        missing_executable=missing_executable,
        full_command="test-tool --flag",
        started_at="2025-01-01T00:00:00+00:00",
        finished_at="2025-01-01T00:00:01+00:00",
    )


class DetermineStageStatusTests(unittest.TestCase):
    """Tests for :func:`determine_stage_status`."""

    def test_success_with_output(self) -> None:
        self.assertEqual(determine_stage_status(_cr(returncode=0), record_count=5), StageState.SUCCESS)

    def test_success_with_nonzero_exit_and_output(self) -> None:
        """A non-zero exit code does not cause failure when output exists."""
        self.assertEqual(determine_stage_status(_cr(returncode=1), record_count=3), StageState.SUCCESS)

    def test_empty_no_output(self) -> None:
        """Exit 0 with no records -> EMPTY."""
        self.assertEqual(determine_stage_status(_cr(returncode=0, stdout=""), record_count=0), StageState.EMPTY)

    def test_failed_no_output(self) -> None:
        """Non-zero exit with no records -> FAILED."""
        self.assertEqual(determine_stage_status(_cr(returncode=2, stdout=""), record_count=0), StageState.FAILED)

    def test_missing_dependency(self) -> None:
        """Missing executable -> MISSING_DEPENDENCY regardless of records."""
        self.assertEqual(
            determine_stage_status(_cr(missing_executable=True), record_count=0), StageState.MISSING_DEPENDENCY
        )

    def test_missing_dependency_with_records(self) -> None:
        self.assertEqual(
            determine_stage_status(_cr(missing_executable=True), record_count=5), StageState.MISSING_DEPENDENCY
        )

    def test_timeout_no_records(self) -> None:
        self.assertEqual(determine_stage_status(_cr(timed_out=True, stdout=""), record_count=0), StageState.TIMEOUT)

    def test_timeout_with_records(self) -> None:
        """Timed out but with useful data -> SUCCESS."""
        self.assertEqual(determine_stage_status(_cr(timed_out=True), record_count=2), StageState.SUCCESS)

    def test_failed_none_returncode(self) -> None:
        """None returncode (e.g., spawn failure) with no records -> FAILED."""
        self.assertEqual(determine_stage_status(_cr(returncode=None, stdout=""), record_count=0), StageState.FAILED)


class BuildStageResultTests(unittest.TestCase):
    """Tests for :func:`build_stage_result`."""

    def test_build_success(self) -> None:
        cr = _cr(returncode=0)
        stage = build_stage_result("subfinder", cr, record_count=10)
        self.assertEqual(stage.name, "subfinder")
        self.assertIs(stage.status, StageState.SUCCESS)
        self.assertEqual(stage.command, "test-tool --flag")
        self.assertEqual(stage.exit_code, 0)
        self.assertAlmostEqual(stage.duration, 1.5)
        self.assertEqual(stage.record_count, 10)
        self.assertFalse(stage.timed_out)
        self.assertFalse(stage.executable_missing)
        self.assertEqual(stage.warnings, [])

    def test_build_with_warnings(self) -> None:
        cr = _cr(returncode=1)
        stage = build_stage_result("httpx", cr, record_count=3, warnings=["partial data", "timeout"])
        self.assertEqual(stage.warnings, ["partial data", "timeout"])
        self.assertIs(stage.status, StageState.SUCCESS)

    def test_build_missing_executable(self) -> None:
        cr = _cr(missing_executable=True)
        stage = build_stage_result("nmap", cr, record_count=0)
        self.assertIs(stage.status, StageState.MISSING_DEPENDENCY)
        self.assertTrue(stage.executable_missing)

    def test_build_timeout_no_records(self) -> None:
        cr = _cr(timed_out=True, stdout="")
        stage = build_stage_result("naabu", cr, record_count=0)
        self.assertIs(stage.status, StageState.TIMEOUT)
        self.assertTrue(stage.timed_out)

    def test_build_timeout_with_records(self) -> None:
        cr = _cr(timed_out=True)
        stage = build_stage_result("nuclei", cr, record_count=5)
        self.assertIs(stage.status, StageState.SUCCESS)

    def test_build_extra_duration(self) -> None:
        cr = _cr()
        stage = build_stage_result("katana", cr, record_count=1, extra_duration=3.0)
        self.assertAlmostEqual(stage.duration, 3.0)


class BuildSkippedStageTests(unittest.TestCase):
    """Tests for :func:`build_skipped_stage`."""

    def test_skipped_stage(self) -> None:
        stage = build_skipped_stage("httpx")
        self.assertEqual(stage.name, "httpx")
        self.assertIs(stage.status, StageState.SKIPPED)
        self.assertEqual(stage.command, "")
        self.assertIsNone(stage.exit_code)
        self.assertAlmostEqual(stage.duration, 0.0)
        self.assertEqual(stage.record_count, 0)
        self.assertFalse(stage.timed_out)
        self.assertFalse(stage.executable_missing)


class StageStateEnumTests(unittest.TestCase):
    """Tests for :class:`StageState`."""

    def test_values(self) -> None:
        self.assertEqual(StageState.SUCCESS.value, "success")
        self.assertEqual(StageState.FAILED.value, "failed")
        self.assertEqual(StageState.SKIPPED.value, "skipped")
        self.assertEqual(StageState.EMPTY.value, "empty")
        self.assertEqual(StageState.TIMEOUT.value, "timeout")
        self.assertEqual(StageState.MISSING_DEPENDENCY.value, "missing_dependency")

    def test_str(self) -> None:
        self.assertEqual(str(StageState.SUCCESS), "success")
        self.assertEqual(str(StageState.MISSING_DEPENDENCY), "missing_dependency")


class StageResultDataclassTests(unittest.TestCase):
    """Tests for :class:`StageResult` construction and defaults."""

    def test_defaults(self) -> None:
        stage = StageResult(
            name="test", status=StageState.SUCCESS, command="cmd", exit_code=0, duration=1.0, record_count=0
        )
        self.assertEqual(stage.warnings, [])
        self.assertFalse(stage.timed_out)
        self.assertFalse(stage.executable_missing)
        self.assertEqual(stage.started_at, "")
        self.assertEqual(stage.finished_at, "")

    def test_full_construction(self) -> None:
        stage = StageResult(
            name="recon",
            status=StageState.TIMEOUT,
            command="tool --flag",
            exit_code=None,
            duration=30.0,
            record_count=0,
            warnings=["timed out"],
            timed_out=True,
            executable_missing=False,
            started_at="2025-01-01T00:00:00+00:00",
            finished_at="2025-01-01T00:00:30+00:00",
        )
        self.assertEqual(stage.name, "recon")
        self.assertIs(stage.status, StageState.TIMEOUT)
        self.assertIsNone(stage.exit_code)
        self.assertAlmostEqual(stage.duration, 30.0)
        self.assertEqual(stage.record_count, 0)
        self.assertEqual(stage.warnings, ["timed out"])
        self.assertTrue(stage.timed_out)
        self.assertFalse(stage.executable_missing)

    def test_slots(self) -> None:
        """Verify that the dataclass uses __slots__."""
        stage = StageResult(
            name="test", status=StageState.SUCCESS, command="", exit_code=0, duration=0.0, record_count=0
        )
        with self.assertRaises(AttributeError):
            stage.nonexistent = 1  # type: ignore[attr-defined]


class SummaryForStagesTests(unittest.TestCase):
    """Tests for :func:`summary_for_stages`."""

    def test_summary_output(self) -> None:
        stages = [
            StageResult(
                name="subfinder", status=StageState.SUCCESS, command="", exit_code=0, duration=1.0, record_count=5
            ),
            StageResult(name="httpx", status=StageState.EMPTY, command="", exit_code=0, duration=0.5, record_count=0),
            StageResult(
                name="naabu", status=StageState.SKIPPED, command="", exit_code=None, duration=0.0, record_count=0
            ),
            StageResult(
                name="nuclei", status=StageState.TIMEOUT, command="", exit_code=None, duration=30.0, record_count=0
            ),
            StageResult(
                name="nmap",
                status=StageState.MISSING_DEPENDENCY,
                command="",
                exit_code=None,
                duration=0.0,
                record_count=0,
            ),
        ]
        summary = summary_for_stages("Web Pipeline", "example.com", stages, 31.5)
        self.assertIn("VINA Web Pipeline", summary)
        self.assertIn("Target:          example.com", summary)
        self.assertIn("subfinder", summary)
        self.assertIn("success", summary)
        self.assertIn("empty", summary)
        self.assertIn("skipped", summary)
        self.assertIn("timeout", summary)
        self.assertIn("missing_dependency", summary)
        self.assertIn("Total Duration:  31.50s", summary)
        self.assertTrue(summary.startswith("="))
        self.assertTrue(summary.endswith("="))


if __name__ == "__main__":
    unittest.main()
