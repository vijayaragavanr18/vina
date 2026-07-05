"""Tests for the asynchronous pipeline scheduler."""

from __future__ import annotations

import asyncio
import unittest

from vina.core.scheduler import PipelineScheduler, RetryConfig, SchedulerResult, StageDef
from vina.models.stages import StageResult, StageState


def _fake_stage(name: str, duration: float = 0.01, status: StageState = StageState.SUCCESS, record_count: int = 1) -> StageResult:
    return StageResult(
        name=name,
        status=status,
        command=f"tool-{name}",
        exit_code=0,
        duration=duration,
        record_count=record_count,
    )


class PipelineSchedulerTests(unittest.IsolatedAsyncioTestCase):
    """Tests for :class:`PipelineScheduler`."""

    async def test_empty_stages(self) -> None:
        result = await PipelineScheduler().run([])
        self.assertIsInstance(result, SchedulerResult)
        self.assertEqual(result.stage_results, [])
        self.assertAlmostEqual(result.total_duration, 0.0)
        self.assertAlmostEqual(result.sequential_duration, 0.0)

    async def test_single_stage(self) -> None:
        async def stage() -> StageResult:
            return _fake_stage("alpha", 0.01, record_count=3)

        stages = [StageDef("alpha", [], stage)]
        result = await PipelineScheduler().run(stages)
        self.assertEqual(len(result.stage_results), 1)
        self.assertEqual(result.stage_results[0].name, "alpha")
        self.assertEqual(result.stage_results[0].record_count, 3)
        self.assertGreater(result.total_duration, 0)
        self.assertAlmostEqual(result.sequential_duration, 0.01, places=2)

    async def test_sequential_deps(self) -> None:
        """A -> B -> C should run in order."""
        order: list[str] = []

        async def a() -> StageResult:
            await asyncio.sleep(0.01)
            order.append("a")
            return _fake_stage("a")

        async def b() -> StageResult:
            order.append("b")
            return _fake_stage("b")

        async def c() -> StageResult:
            order.append("c")
            return _fake_stage("c")

        stages = [
            StageDef("a", [], a),
            StageDef("b", ["a"], b),
            StageDef("c", ["b"], c),
        ]
        await PipelineScheduler().run(stages)
        self.assertEqual(order, ["a", "b", "c"])

    async def test_parallel_execution(self) -> None:
        """Independent stages with no deps should run concurrently."""
        started = asyncio.get_event_loop().time()

        async def slow(name: str) -> StageResult:
            await asyncio.sleep(0.05)
            return _fake_stage(name, 0.05)

        stages = [
            StageDef("x", [], lambda: slow("x")),
            StageDef("y", [], lambda: slow("y")),
            StageDef("z", [], lambda: slow("z")),
        ]
        await PipelineScheduler(max_parallel=4).run(stages)
        elapsed = asyncio.get_event_loop().time() - started
        # All three run in parallel, so total should be ~0.05s, not 0.15s.
        self.assertLess(elapsed, 0.12)

    async def test_max_parallel_limits_concurrency(self) -> None:
        """max_parallel=1 forces sequential execution of independent stages."""
        started = asyncio.get_event_loop().time()

        async def slow(name: str) -> StageResult:
            await asyncio.sleep(0.05)
            return _fake_stage(name, 0.05)

        stages = [
            StageDef("x", [], lambda: slow("x")),
            StageDef("y", [], lambda: slow("y")),
            StageDef("z", [], lambda: slow("z")),
        ]
        await PipelineScheduler(max_parallel=1).run(stages)
        elapsed = asyncio.get_event_loop().time() - started
        # Sequential: 3 * 0.05s, with some overhead.
        self.assertGreaterEqual(elapsed, 0.13)

    async def test_fan_out(self) -> None:
        """A -> B, C (fan-out) should run B and C concurrently."""
        order: list[str] = []

        async def a() -> StageResult:
            await asyncio.sleep(0.01)
            order.append("a")
            return _fake_stage("a")

        async def b() -> StageResult:
            await asyncio.sleep(0.02)
            order.append("b")
            return _fake_stage("b")

        async def c() -> StageResult:
            await asyncio.sleep(0.02)
            order.append("c")
            return _fake_stage("c")

        stages = [
            StageDef("a", [], a),
            StageDef("b", ["a"], b),
            StageDef("c", ["a"], c),
        ]
        await PipelineScheduler().run(stages)
        # a must come first, b and c can be in any order.
        self.assertEqual(order[0], "a")
        self.assertIn(order[1], ("b", "c"))
        self.assertIn(order[2], ("b", "c"))
        self.assertNotEqual(order[1], order[2])

    async def test_fan_in(self) -> None:
        """A, B -> C (fan-in) should wait for both A and B."""
        order: list[str] = []

        async def a() -> StageResult:
            await asyncio.sleep(0.01)
            order.append("a")
            return _fake_stage("a")

        async def b() -> StageResult:
            await asyncio.sleep(0.03)
            order.append("b")
            return _fake_stage("b")

        async def c() -> StageResult:
            order.append("c")
            return _fake_stage("c")

        stages = [
            StageDef("a", [], a),
            StageDef("b", [], b),
            StageDef("c", ["a", "b"], c),
        ]
        await PipelineScheduler().run(stages)
        self.assertEqual(order[-1], "c")  # c must be last
        self.assertIn("a", order[:2])
        self.assertIn("b", order[:2])

    async def test_diamond(self) -> None:
        """Test a diamond-shaped dependency graph: A -> B, C -> D."""
        order: list[str] = []

        async def a() -> StageResult:
            order.append("a")
            return _fake_stage("a")

        async def b() -> StageResult:
            await asyncio.sleep(0.01)
            order.append("b")
            return _fake_stage("b")

        async def c() -> StageResult:
            await asyncio.sleep(0.01)
            order.append("c")
            return _fake_stage("c")

        async def d() -> StageResult:
            order.append("d")
            return _fake_stage("d")

        stages = [
            StageDef("a", [], a),
            StageDef("b", ["a"], b),
            StageDef("c", ["a"], c),
            StageDef("d", ["b", "c"], d),
        ]
        await PipelineScheduler().run(stages)
        self.assertEqual(order[0], "a")
        self.assertEqual(order[-1], "d")
        self.assertIn(set(order[1:3]), ({"b", "c"}, {"c", "b"}))

    async def test_timing_fields(self) -> None:
        """Scheduler should populate queued_at, started_at, finished_at."""

        async def stage() -> StageResult:
            return _fake_stage("timed")

        stages = [StageDef("timed", [], stage)]
        result = await PipelineScheduler().run(stages)
        sr = result.stage_results[0]
        self.assertNotEqual(sr.queued_at, "")
        self.assertNotEqual(sr.started_at, "")
        self.assertNotEqual(sr.finished_at, "")
        # ISO-8601 timestamps should contain 'T'.
        self.assertIn("T", sr.queued_at)
        self.assertIn("T", sr.started_at)
        self.assertIn("T", sr.finished_at)

    async def test_sequential_duration_sum(self) -> None:
        """sequential_duration should equal sum of all stage durations."""

        async def s1() -> StageResult:
            return _fake_stage("s1", 0.1)

        async def s2() -> StageResult:
            return _fake_stage("s2", 0.2)

        stages = [
            StageDef("s1", [], s1),
            StageDef("s2", [], s2),
        ]
        result = await PipelineScheduler().run(stages)
        self.assertAlmostEqual(result.sequential_duration, 0.3, places=2)

    async def test_exception_handling(self) -> None:
        """An exception in a stage should produce a FAILED StageResult."""

        async def failing() -> StageResult:
            msg = "something went wrong"
            raise RuntimeError(msg)

        stages = [StageDef("failing", [], failing)]
        result = await PipelineScheduler().run(stages)
        self.assertEqual(len(result.stage_results), 1)
        sr = result.stage_results[0]
        self.assertIs(sr.status, StageState.FAILED)
        self.assertIn("something went wrong", sr.warnings[0])

    async def test_exception_in_dependency(self) -> None:
        """A failed dependency should not block other independent stages.
        The dependent stage runs (its coroutine runs), but it receives
        whatever shared state the failing stage would have set.
        """

        async def good() -> StageResult:
            return _fake_stage("good")

        async def failing() -> StageResult:
            msg = "fail"
            raise RuntimeError(msg)

        async def dependent() -> StageResult:
            # This runs after 'failing' errors out.
            return _fake_stage("dependent")

        stages = [
            StageDef("good", [], good),
            StageDef("failing", [], failing),
            StageDef("dependent", ["failing"], dependent),
        ]
        result = await PipelineScheduler().run(stages)
        names = [sr.name for sr in result.stage_results]
        self.assertIn("good", names)
        self.assertIn("failing", names)
        self.assertIn("dependent", names)
        # 'failing' should have FAILED status.
        failing_sr = next(sr for sr in result.stage_results if sr.name == "failing")
        self.assertIs(failing_sr.status, StageState.FAILED)

    async def test_invalid_dependency(self) -> None:
        """A dependency on a non-existent stage should raise ValueError."""

        async def orphan() -> StageResult:
            return _fake_stage("orphan")

        stages = [StageDef("orphan", ["nonexistent"], orphan)]
        with self.assertRaises(ValueError):
            await PipelineScheduler().run(stages)




# ------------------------------------------------------------------
# Retry tests
# ------------------------------------------------------------------


class RetryTests(unittest.IsolatedAsyncioTestCase):
    """Tests for scheduler retry logic."""

    async def test_no_retry_on_success(self) -> None:
        """A successful stage should not retry."""
        call_count = 0

        async def stage() -> StageResult:
            nonlocal call_count
            call_count += 1
            return _fake_stage("ok")

        stages = [StageDef("ok", [], stage, retry=RetryConfig(max_retries=2))]
        await PipelineScheduler().run(stages)
        self.assertEqual(call_count, 1)

    async def test_retry_on_timeout(self) -> None:
        """A TIMEOUT should be retried."""
        call_count = 0

        async def stage() -> StageResult:
            nonlocal call_count
            call_count += 1
            return StageResult(name="slow", status=StageState.TIMEOUT, command="", exit_code=None, duration=0.05, record_count=0)

        stages = [StageDef("slow", [], stage, retry=RetryConfig(max_retries=2, retry_delay_seconds=0.01))]
        await PipelineScheduler().run(stages)
        # Called once initially + 2 retries = 3 total
        self.assertEqual(call_count, 3)

    async def test_no_retry_on_missing_executable(self) -> None:
        """A MISSING_DEPENDENCY should never be retried."""
        call_count = 0

        async def stage() -> StageResult:
            nonlocal call_count
            call_count += 1
            return StageResult(name="missing", status=StageState.MISSING_DEPENDENCY, command="", exit_code=None, duration=0.0, record_count=0, executable_missing=True)

        stages = [StageDef("missing", [], stage, retry=RetryConfig(max_retries=2))]
        await PipelineScheduler().run(stages)
        self.assertEqual(call_count, 1)

    async def test_retry_exhausted(self) -> None:
        """After exhausting retries, the last result is returned."""
        call_count = 0

        async def stage() -> StageResult:
            nonlocal call_count
            call_count += 1
            return StageResult(name="flaky", status=StageState.TIMEOUT, command="", exit_code=None, duration=0.01, record_count=0, warnings=["timed out"])

        sd = StageDef("flaky", [], stage, retry=RetryConfig(max_retries=1, retry_delay_seconds=0.01))
        result = await PipelineScheduler().run([sd])
        sr = result.stage_results[0]
        self.assertEqual(call_count, 2)  # initial + 1 retry
        self.assertIs(sr.status, StageState.TIMEOUT)

    async def test_retry_then_success(self) -> None:
        """A transient failure followed by success on retry."""
        call_count = 0

        async def stage() -> StageResult:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return StageResult(name="flaky", status=StageState.TIMEOUT, command="", exit_code=None, duration=0.01, record_count=0, warnings=["timed out"])
            return _fake_stage("flaky")

        stages = [StageDef("flaky", [], stage, retry=RetryConfig(max_retries=2, retry_delay_seconds=0.01))]
        result = await PipelineScheduler().run(stages)
        sr = result.stage_results[0]
        self.assertEqual(call_count, 2)
        self.assertIs(sr.status, StageState.SUCCESS)

    async def test_no_retry_without_config(self) -> None:
        """Without RetryConfig, no retry occurs."""
        call_count = 0

        async def stage() -> StageResult:
            nonlocal call_count
            call_count += 1
            return StageResult(name="flaky", status=StageState.TIMEOUT, command="", exit_code=None, duration=0.01, record_count=0)

        stages = [StageDef("flaky", [], stage, retry=None)]
        await PipelineScheduler().run(stages)
        self.assertEqual(call_count, 1)

    async def test_exponential_backoff(self) -> None:
        """Exponential backoff doubles delay each attempt."""
        call_count = 0
        import time

        async def stage() -> StageResult:
            nonlocal call_count
            call_count += 1
            return StageResult(name="slow", status=StageState.TIMEOUT, command="", exit_code=None, duration=0.01, record_count=0)

        started = time.monotonic()
        stages = [StageDef("slow", [], stage, retry=RetryConfig(max_retries=2, retry_delay_seconds=0.05, exponential_backoff=True))]
        await PipelineScheduler().run(stages)
        elapsed = time.monotonic() - started
        # delays: 0.05 + 0.1 = 0.15s minimum
        self.assertGreaterEqual(elapsed, 0.14)

    async def test_retry_print_message(self) -> None:
        """print_retry=True should output retry messages."""
        import io
        from contextlib import redirect_stdout

        call_count = 0

        async def stage() -> StageResult:
            nonlocal call_count
            call_count += 1
            return StageResult(name="msg", status=StageState.TIMEOUT, command="", exit_code=None, duration=0.01, record_count=0)

        buf = io.StringIO()
        sd = StageDef("msg", [], stage, retry=RetryConfig(max_retries=1, retry_delay_seconds=0.01), print_retry=True)
        with redirect_stdout(buf):
            await PipelineScheduler().run([sd])
        output = buf.getvalue()
        self.assertIn("Retry 1/1", output)


if __name__ == "__main__":
    unittest.main()
