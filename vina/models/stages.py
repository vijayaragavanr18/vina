"""Stage state management for pipeline execution.

Defines the formal stage state enum, the structured StageResult
dataclass that pipelines return for each stage, and helper functions
for status determination and standardized logging.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from ..core.runner import CommandResult


class StageState(StrEnum):
    """Explicit stage execution states."""

    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    EMPTY = "empty"
    TIMEOUT = "timeout"
    MISSING_DEPENDENCY = "missing_dependency"


@dataclass(slots=True)
class StageResult:
    """Execution metadata for one pipeline stage.

    Attributes:
        name: Human-readable stage name.
        status: Execution state from :class:`StageState`.
        command: Full command string that was executed.
        exit_code: Process exit code, or ``None`` if not applicable.
        duration: Wall-clock seconds the stage took.
        record_count: Number of records/artifacts produced.
        warnings: Warning messages accumulated during the stage.
        timed_out: Whether the command timed out.
        executable_missing: Whether the executable was not found.
        started_at: ISO-8601 timestamp when the stage started.
        finished_at: ISO-8601 timestamp when the stage finished.
        queued_at: ISO-8601 timestamp when the stage was queued.
    """

    name: str
    status: StageState
    command: str
    exit_code: int | None
    duration: float
    record_count: int
    warnings: list[str] = field(default_factory=list)
    timed_out: bool = False
    executable_missing: bool = False
    started_at: str = ""
    finished_at: str = ""
    queued_at: str = ""


# ------------------------------------------------------------------
# Status determination
# ------------------------------------------------------------------


def determine_stage_status(cr: CommandResult, record_count: int) -> StageState:
    """Determine the appropriate stage state from execution results.

    Rules:
    * Executable not found -> ``MISSING_DEPENDENCY``.
    * Timed out with no records -> ``TIMEOUT``.
    * Timed out with useful records -> ``SUCCESS`` (partial data).
    * Records produced (regardless of exit code) -> ``SUCCESS``.
    * Exit code 0, no records -> ``EMPTY``.
    * Non-zero exit, no records -> ``FAILED``.
    """

    if cr.missing_executable:
        return StageState.MISSING_DEPENDENCY

    if cr.timed_out:
        return StageState.SUCCESS if record_count > 0 else StageState.TIMEOUT

    if record_count > 0:
        return StageState.SUCCESS

    if cr.returncode == 0:
        return StageState.EMPTY

    return StageState.FAILED


# ------------------------------------------------------------------
# Standardised logging
# ------------------------------------------------------------------


def log_stage_result(stage: StageResult) -> None:
    """Print a standardised stage summary block to the console."""
    exit_code_str = " N/A" if stage.exit_code is None else f" {stage.exit_code}"
    lines = [
        "-" * 40,
        f"Stage:    {stage.name}",
        f"Command:  {stage.command}",
        f"Status:   {stage.status.value}",
        f"Duration: {stage.duration:.2f}s",
        f"Exit Code:{exit_code_str}",
        f"Records:  {stage.record_count}",
    ]
    if stage.warnings:
        joined = "; ".join(stage.warnings)
        lines.append(f"Warnings: {joined}")
    lines.append("-" * 40)
    print("\n".join(lines))


# ------------------------------------------------------------------
# Helpers for building stage results
# ------------------------------------------------------------------


def build_stage_result(
    name: str,
    command_result: CommandResult,
    record_count: int,
    warnings: Sequence[str] | None = None,
    extra_duration: float | None = None,
) -> StageResult:
    """Build a :class:`StageResult` from a :class:`CommandResult`.

    Parameters
    ----------
    name:
        Human-readable stage name.
    command_result:
        The result returned by :class:`AsyncCommandRunner`.
    record_count:
        Number of records produced by the stage.
    warnings:
        Optional warning list (defaults to empty).
    extra_duration:
        Optional override for duration. When not provided, uses
        ``command_result.duration_seconds``.
    """
    status = determine_stage_status(command_result, record_count)
    duration = extra_duration if extra_duration is not None else command_result.duration_seconds
    return StageResult(
        name=name,
        status=status,
        command=command_result.full_command,
        exit_code=command_result.returncode,
        duration=duration,
        record_count=record_count,
        warnings=list(warnings) if warnings is not None else [],
        timed_out=command_result.timed_out,
        executable_missing=command_result.missing_executable,
        started_at=command_result.started_at,
        finished_at=command_result.finished_at,
    )


def build_skipped_stage(name: str) -> StageResult:
    """Build a skipped :class:`StageResult` (no command was run)."""
    return StageResult(name=name, status=StageState.SKIPPED, command="", exit_code=None, duration=0.0, record_count=0)


def build_missing_dependency_stage(name: str, tool: str = "") -> StageResult:
    """Build a :class:`StageResult` for a missing external dependency.

    Parameters
    ----------
    name:
        Human-readable stage name.
    tool:
        The logical tool name that was missing.  Defaults to *name*.
    """
    missing = tool or name
    return StageResult(
        name=name,
        status=StageState.MISSING_DEPENDENCY,
        command=missing,
        exit_code=None,
        duration=0.0,
        record_count=0,
        warnings=[f"Missing executable: {missing}"],
        executable_missing=True,
    )


def summary_for_stages(
    pipeline_name: str, target_display: str, stage_results: list[StageResult], total_duration: float
) -> str:
    """Build a concise summary string from a list of stage results."""
    lines = ["=" * 41, f"VINA {pipeline_name}", "=" * 41, f"Target:          {target_display}"]
    for sr in stage_results:
        lines.append(f"  {sr.name:<18} {sr.status.value:<18} {sr.record_count}")
    lines.append(f"Total Duration:  {total_duration:.2f}s")
    lines.append("=" * 41)
    return "\n".join(lines)


__all__ = [
    "StageResult",
    "StageState",
    "build_missing_dependency_stage",
    "build_skipped_stage",
    "build_stage_result",
    "determine_stage_status",
    "log_stage_result",
    "summary_for_stages",
]
