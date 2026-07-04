from __future__ import annotations

import sys
import unittest

from vina.core.runner import AsyncCommandRunner


class RunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_executable(self) -> None:
        runner = AsyncCommandRunner()
        result = await runner.run("definitely-not-installed-vina", timeout_seconds=1)
        self.assertTrue(result.missing_executable)

    async def test_timeout(self) -> None:
        runner = AsyncCommandRunner()
        result = await runner.run(
            sys.executable,
            ["-c", "import time; time.sleep(0.2)"],
            timeout_seconds=0.01,
        )
        self.assertTrue(result.timed_out)


if __name__ == "__main__":
    unittest.main()
