"""Asynchronous pipeline scheduler with dependency-aware stage execution.

Provides a generic scheduler that executes pipeline stages respecting
a dependency graph, with configurable concurrency limits, retry logic,
and detailed timing instrumentation.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from ..models.stages import StageResult, StageState

logger = logging.getLogger(__name__)


def _utc_now_iso8601() -> str:
    return datetime.now(UTC).isoformat()


# Patterns in warning/error messages that indicate a transient failure
# eligible for automatic retry.
_TRANSIENT_PATTERNS: tuple[str, ...] = (
    "timeout",
    "timed out",
    "connection reset",
    "connection refused",
    "network unreachable",
    "dns",
    "temporary",
    "econnreset",
    "econnrefused",
    "ehostunreach",
    "enotfound",
    "remote end closed",
    "broken pipe",
    "reset by peer",
    "connection aborted",
    "econnaborted",
    "etimedout",
    "no route to host",
    "ehostdown",
    "network is down",
)


@dataclass(slots=True)
class RetryConfig:
    """Retry policy for a pipeline stage.

    Attributes:
        max_retries: Maximum number of retry attempts (default 2).
        retry_delay_seconds: Base delay between retries in seconds (default 2).
        exponential_backoff: When True, delay doubles after each attempt.
    """

    max_retries: int = 2
    retry_delay_seconds: float = 2.0
    exponential_backoff: bool = True


@dataclass(slots=True)
class StageDef:
    """Definition of a single pipeline stage for the scheduler.

    Attributes:
        name: Unique stage name used for dependency references.
        deps: Names of stages that must complete before this one runs.
        coro: Async callable that returns a :class:`StageResult`.
        retry: Optional retry policy.  ``None`` means no retries.
        print_retry: Whether to print retry progress messages.
    """

    name: str
    deps: list[str]
    coro: Callable[[], Awaitable[StageResult]]
    retry: RetryConfig | None = None
    print_retry: bool = True


@dataclass(slots=True)
class SchedulerResult:
    """Aggregate result returned by the scheduler.

    Attributes:
        stage_results: Completed stage results in insertion order.
        total_duration: Wall-clock seconds the entire schedule took.
        sequential_duration: Sum of all individual stage durations (what
            the pipeline would take if run completely sequentially).
    """

    stage_results: list[StageResult]
    total_duration: float
    sequential_duration: float


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _is_retryable(stage: StageResult) -> bool:
    """Return True when the stage failed due to a transient condition.

    Stages are considered retryable when they timed out or when their
    warning messages match known transient-error patterns.

    Permanent failures (executable missing, skipped, success, empty)
    are never retried.
    """
    if stage.status == StageState.TIMEOUT:
        return True

    if stage.status not in (StageState.FAILED,):
        return False

    if stage.executable_missing:
        return False

    for msg in stage.warnings:
        lower = msg.lower()
        for pattern in _TRANSIENT_PATTERNS:
            if pattern in lower:
                return True
    return False


# ------------------------------------------------------------------
# Scheduler
# ------------------------------------------------------------------


class PipelineScheduler:
    """Execute a set of :class:`StageDef` stages with dependency awareness.

    Stages whose dependencies have all completed become eligible for
    execution.  Up to ``max_parallel`` stages run concurrently.

    When a stage has a :class:`RetryConfig`, transient failures are
    automatically retried with optional exponential backoff.

    Timing is recorded for each stage:
    * **queued** — moment all dependencies were satisfied.
    * **started** — moment the stage acquired a concurrency slot.
    * **finished** — moment the stage completed (after any retries).
    """

    def __init__(self, max_parallel: int = 4) -> None:
        self.max_parallel = max_parallel

    async def run(self, stages: list[StageDef]) -> SchedulerResult:
        """Execute all stages according to their dependency graph.

        Parameters
        ----------
        stages:
            List of stage definitions.  Each stage's ``deps`` refers to
            the ``name`` of other stages in this list.

        Returns
        -------
        SchedulerResult
            Completed stage results, total wall duration, and sequential
            duration estimate.
        """
        stage_map: dict[str, StageDef] = {s.name: s for s in stages}
        completed: dict[str, StageResult] = {}
        done_events: dict[str, asyncio.Event] = {s.name: asyncio.Event() for s in stages}
        results: list[StageResult] = []
        lock = asyncio.Lock()
        sem = asyncio.Semaphore(self.max_parallel)

        if not stages:
            return SchedulerResult(stage_results=[], total_duration=0.0, sequential_duration=0.0)

        # Validate dependency graph.
        for sd in stages:
            for dep in sd.deps:
                if dep not in stage_map:
                    msg = f"Stage {sd.name!r} depends on unknown stage {dep!r}"
                    logger.error(msg)
                    raise ValueError(msg)

        async def _run_one(name: str) -> None:
            sd = stage_map[name]

            # Wait for every dependency to finish.
            for dep in sd.deps:
                await done_events[dep].wait()

            queued_at = _utc_now_iso8601()

            async with sem:
                started_at = _utc_now_iso8601()
                stage = await self._run_with_retry(sd)
                finished_at = _utc_now_iso8601()

                stage.queued_at = queued_at
                stage.started_at = started_at
                stage.finished_at = finished_at

                async with lock:
                    completed[name] = stage
                    done_events[name].set()
                    results.append(stage)

        started_perf = datetime.now(UTC)
        await asyncio.gather(*[_run_one(s.name) for s in stages])
        finished_perf = datetime.now(UTC)

        total_duration = (finished_perf - started_perf).total_seconds()
        sequential_duration = sum(s.duration for s in results)

        return SchedulerResult(
            stage_results=results,
            total_duration=total_duration,
            sequential_duration=sequential_duration,
        )

    # ------------------------------------------------------------------
    # Retry logic
    # ------------------------------------------------------------------

    async def _run_with_retry(self, sd: StageDef) -> StageResult:
        """Execute *sd.coro* with optional retry logic."""
        retry = sd.retry
        if retry is None:
            return await self._run_once(sd)

        attempt = 0
        while True:
            stage = await self._run_once(sd)

            if not _is_retryable(stage) or attempt >= retry.max_retries:
                return stage

            attempt += 1
            if sd.print_retry:
                print(f"Retry {attempt}/{retry.max_retries}...")

            delay = retry.retry_delay_seconds
            if retry.exponential_backoff:
                delay *= 2 ** (attempt - 1)
            await asyncio.sleep(delay)

    @staticmethod
    async def _run_once(sd: StageDef) -> StageResult:
        """Invoke a stage coroutine, catching unhandled exceptions."""
        try:
            return await sd.coro()
        except Exception as exc:
            logger.exception("Stage %s raised an unhandled exception: %s", sd.name, exc)
            return StageResult(
                name=sd.name,
                status=StageState.FAILED,
                command="",
                exit_code=None,
                duration=0.0,
                record_count=0,
                warnings=[f"Unhandled exception: {exc}"],
            )


__all__ = [
    "PipelineScheduler",
    "RetryConfig",
    "SchedulerResult",
    "StageDef",
]
