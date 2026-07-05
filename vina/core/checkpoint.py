"""Pipeline checkpointing for resumable execution.

Provides a :class:`CheckpointManager` that persists stage results to
JSON after every completed stage, enabling interrupted pipelines to
resume from the last unfinished stage.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..models.stages import StageResult, StageState

logger = logging.getLogger(__name__)


def _safe_name(raw: str) -> str:
    """Replace characters that are problematic in filenames."""
    return raw.replace("/", "_").replace(":", "_").replace(".", "_")


class CheckpointManager:
    """Persist and restore pipeline execution checkpoints.

    Each checkpoint is a JSON file stored under
    ``<output_dir>/checkpoints/<pipeline>_<target>.json``.

    The checkpoint records:
    * Pipeline metadata (name, target, timestamps).
    * Per-stage results (status, timing, exit code, record count, etc.).
    * Serializable output data needed to reconstruct shared state on resume.
    """

    def __init__(
        self,
        output_dir: Path,
        pipeline_name: str,
        target: str,
    ) -> None:
        self._pipeline = pipeline_name
        self._target = target
        self._dir = output_dir / "checkpoints"
        self._dir.mkdir(parents=True, exist_ok=True)
        self._file = self._dir / f"{pipeline_name}_{_safe_name(target)}.json"
        self._data: dict = self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_stage(
        self,
        stage: StageResult,
        outputs: dict | None = None,
    ) -> None:
        """Persist a completed stage to the checkpoint file."""
        self._data.setdefault("stages", {})[stage.name] = {
            "name": stage.name,
            "status": stage.status.value,
            "command": stage.command,
            "exit_code": stage.exit_code,
            "duration": stage.duration,
            "record_count": stage.record_count,
            "warnings": stage.warnings,
            "started_at": stage.started_at,
            "finished_at": stage.finished_at,
            "queued_at": stage.queued_at,
            "outputs": outputs or {},
        }
        self._data["updated_at"] = _now_iso()
        self._save()

    def completed_stage_names(self) -> set[str]:
        """Return the set of stage names recorded in the checkpoint."""
        return set(self._data.get("stages", {}))

    def has_completed(self, stage_name: str) -> bool:
        """Return True when *stage_name* has a checkpoint entry."""
        return stage_name in self._data.get("stages", {})

    def is_successfully_completed(self, stage_name: str) -> bool:
        """Return True if the stage completed with a non-terminal status.

        Stages with ``success``, ``empty``, ``skipped``, or ``timeout``
        with records are considered successful for resume purposes.
        """
        info = self._data.get("stages", {}).get(stage_name)
        if info is None:
            return False
        ok_statuses = {"success", "empty", "skipped"}
        return info.get("status") in ok_statuses

    def get_stage_info(self, stage_name: str) -> dict:
        """Return the raw checkpoint dict for a stage."""
        return self._data.get("stages", {}).get(stage_name, {})

    def get_stage_outputs(self, stage_name: str) -> dict:
        """Return the ``outputs`` dict stored for a stage."""
        return self.get_stage_info(stage_name).get("outputs", {})

    def restore_stage(self, stage_name: str) -> StageResult:
        """Reconstruct a :class:`StageResult` from the checkpoint."""
        info = self.get_stage_info(stage_name)
        return StageResult(
            name=info.get("name", stage_name),
            status=StageState(info.get("status", "failed")),
            command=info.get("command", ""),
            exit_code=info.get("exit_code"),
            duration=info.get("duration", 0.0),
            record_count=info.get("record_count", 0),
            warnings=info.get("warnings", []),
            timed_out=info.get("status") == "timeout",
            executable_missing=info.get("status") == "missing_dependency",
            started_at=info.get("started_at", ""),
            finished_at=info.get("finished_at", ""),
            queued_at=info.get("queued_at", ""),
        )

    def restore_outputs(self) -> dict:
        """Reconstruct the shared-outputs dict from all checkpoint stages.

        Returns a flat dict of output keys aggregated from every
        completed stage.
        """
        merged: dict = {}
        for stage_info in self._data.get("stages", {}).values():
            outputs = stage_info.get("outputs", {})
            merged.update(outputs)
        return merged

    def clear(self) -> None:
        """Wipe the checkpoint (used with ``--force``)."""
        self._data = self._blank()
        self._save()

    def exists(self) -> bool:
        """Return True when a checkpoint file already exists on disk."""
        return self._file.exists()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _blank(self) -> dict:
        return {
            "pipeline": self._pipeline,
            "target": self._target,
            "stages": {},
            "outputs": {},
        }

    def _load(self) -> dict:
        if self._file.exists():
            try:
                raw = self._file.read_text(encoding="utf-8")
                return dict(json.loads(raw))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to load checkpoint %s: %s", self._file, exc)
        return self._blank()

    def _save(self) -> None:
        try:
            self._file.write_text(
                json.dumps(self._data, indent=2, default=str),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Failed to write checkpoint %s: %s", self._file, exc)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "CheckpointManager",
]
