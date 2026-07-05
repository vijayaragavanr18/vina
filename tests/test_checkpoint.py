"""Tests for the pipeline checkpoint manager."""

from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path

from vina.core.checkpoint import CheckpointManager
from vina.models.stages import StageResult, StageState


class CheckpointManagerTests(unittest.TestCase):
    """Tests for :class:`CheckpointManager`."""

    def setUp(self) -> None:
        self.tmpdir = Path(__file__).resolve().parent / "_test_checkpoints"
        self._clean_checkpoints()
        self.tmpdir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self._clean_checkpoints()

    def _clean_checkpoints(self) -> None:
        if self.tmpdir.exists():
            shutil.rmtree(self.tmpdir)

    def _make_stage(self, name: str, status: StageState = StageState.SUCCESS, record_count: int = 1) -> StageResult:
        return StageResult(
            name=name, status=status, command=f"tool-{name}", exit_code=0, duration=1.0, record_count=record_count
        )

    def test_record_and_has_completed(self) -> None:
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        self.assertFalse(cp.has_completed("subfinder"))
        cp.record_stage(self._make_stage("subfinder"))
        self.assertTrue(cp.has_completed("subfinder"))

    def test_completed_stage_names(self) -> None:
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        cp.record_stage(self._make_stage("subfinder"))
        cp.record_stage(self._make_stage("httpx"))
        self.assertEqual(cp.completed_stage_names(), {"subfinder", "httpx"})

    def test_is_successfully_completed(self) -> None:
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        cp.record_stage(self._make_stage("subfinder"))
        self.assertTrue(cp.is_successfully_completed("subfinder"))

    def test_is_not_successfully_completed_for_failed(self) -> None:
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        cp.record_stage(self._make_stage("fail", StageState.FAILED))
        self.assertFalse(cp.is_successfully_completed("fail"))

    def test_restore_stage(self) -> None:
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        original = self._make_stage("subfinder", record_count=42)
        cp.record_stage(original)
        restored = cp.restore_stage("subfinder")
        self.assertEqual(restored.name, "subfinder")
        self.assertEqual(restored.record_count, 42)
        self.assertIs(restored.status, StageState.SUCCESS)

    def test_restore_outputs(self) -> None:
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        cp.record_stage(self._make_stage("subfinder"), outputs={"subdomains": ["a.com", "b.com"]})
        cp.record_stage(self._make_stage("httpx"), outputs={"alive_hosts": ["https://a.com"]})
        outputs = cp.restore_outputs()
        self.assertEqual(outputs["subdomains"], ["a.com", "b.com"])
        self.assertEqual(outputs["alive_hosts"], ["https://a.com"])

    def test_clear(self) -> None:
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        cp.record_stage(self._make_stage("subfinder"))
        self.assertTrue(cp.has_completed("subfinder"))
        cp.clear()
        self.assertFalse(cp.has_completed("subfinder"))

    def test_exists(self) -> None:
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        self.assertFalse(cp.exists())
        cp.record_stage(self._make_stage("subfinder"))
        self.assertTrue(cp.exists())

    def test_persistence(self) -> None:
        """Checkpoint data persists across CheckpointManager instances."""
        cp1 = CheckpointManager(self.tmpdir, "web", "example.com")
        cp1.record_stage(self._make_stage("subfinder", record_count=10))
        cp2 = CheckpointManager(self.tmpdir, "web", "example.com")
        self.assertTrue(cp2.has_completed("subfinder"))
        self.assertEqual(cp2.restore_stage("subfinder").record_count, 10)

    def test_empty_checkpoint_not_exists(self) -> None:
        """A brand-new manager with no recorded stages has no file."""
        cp = CheckpointManager(self.tmpdir, "web", "new-target")
        self.assertFalse(cp.exists())

    def test_get_stage_info(self) -> None:
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        cp.record_stage(self._make_stage("nmap"), outputs={"ports": [80, 443]})
        info = cp.get_stage_info("nmap")
        self.assertEqual(info["record_count"], 1)
        self.assertEqual(info["outputs"]["ports"], [80, 443])

    def test_get_stage_outputs(self) -> None:
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        cp.record_stage(self._make_stage("naabu"), outputs={"open_ports": [80]})
        outputs = cp.get_stage_outputs("naabu")
        self.assertEqual(outputs["open_ports"], [80])

    def test_json_file_format(self) -> None:
        """Verify the checkpoint file is valid JSON with expected keys."""
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        cp.record_stage(self._make_stage("subfinder", record_count=7))
        raw = cp._file.read_text()
        data = json.loads(raw)
        self.assertIn("pipeline", data)
        self.assertIn("target", data)
        self.assertIn("stages", data)
        self.assertIn("updated_at", data)
        self.assertEqual(data["pipeline"], "web")
        self.assertEqual(data["target"], "example.com")
        self.assertIn("subfinder", data["stages"])
        self.assertEqual(data["stages"]["subfinder"]["record_count"], 7)

    def test_missing_stage_info_returns_empty(self) -> None:
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        self.assertEqual(cp.get_stage_info("nonexistent"), {})
        self.assertEqual(cp.get_stage_outputs("nonexistent"), {})

    def test_restore_failure_stage_status(self) -> None:
        cp = CheckpointManager(self.tmpdir, "web", "example.com")
        cp.record_stage(self._make_stage("timeout", StageState.TIMEOUT))
        restored = cp.restore_stage("timeout")
        self.assertIs(restored.status, StageState.TIMEOUT)
        self.assertTrue(restored.timed_out)


if __name__ == "__main__":
    unittest.main()
