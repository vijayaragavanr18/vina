"""Asynchronous subprocess runner utilities.

This module provides a reusable AsyncCommandRunner used across pipeline
modules to execute external tools safely and consistently.

Goals and guarantees:
- Use asyncio.create_subprocess_exec (no shell=True) to avoid shell injection.
- Apply configurable timeouts and ensure processes are terminated on timeout.
- Detect missing executables early using ``shutil.which``.
- Capture and return stdout/stderr, returncode, duration and status flags.
- Emit structured logging for observability and debugging.
"""

from __future__ import annotations

import asyncio
import os
import shlex
from contextlib import suppress
from datetime import datetime, timezone
import logging
import shutil
from time import perf_counter_ns
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

logger = logging.getLogger(__name__)

_STREAM_CHUNK_SIZE = 64 * 1024
_STREAM_BYTE_LIMIT = 10 * 1024 * 1024


def _utc_now_iso8601() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""

    return datetime.now(timezone.utc).isoformat()


def _normalize_env(env: Mapping[str, str] | None) -> dict[str, str] | None:
    """Merge user overrides into the current environment.

    ``None`` is preserved to allow the subprocess to inherit the parent's
    environment unchanged.
    """

    if env is None:
        return None
    merged_env = os.environ.copy()
    merged_env.update({str(key): str(value) for key, value in env.items()})
    return merged_env


async def _collect_stream(
    stream: asyncio.StreamReader | None,
    *,
    byte_limit: int = _STREAM_BYTE_LIMIT,
) -> tuple[str, bool]:
    """Read a subprocess stream without allowing unbounded memory growth.

    The reader continues draining the stream to EOF, but only the first
    ``byte_limit`` bytes are retained in memory.
    """

    if stream is None:
        return "", False

    buffer = bytearray()
    truncated = False

    while True:
        chunk = await stream.read(_STREAM_CHUNK_SIZE)
        if not chunk:
            break

        if len(buffer) < byte_limit:
            remaining = byte_limit - len(buffer)
            if remaining > 0:
                buffer.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
        else:
            truncated = True

    return buffer.decode("utf-8", errors="replace"), truncated


@dataclass(slots=True)
class CommandResult:
    """Structured result for a single command invocation.

    Attributes:
        command: executable name invoked (as provided).
        args: tuple of arguments passed to the executable.
        returncode: process return code or ``None`` if not set (e.g. timed out).
        stdout: decoded stdout text (utf-8, replacement on error).
        stderr: decoded stderr text (utf-8, replacement on error).
        duration_seconds: wall-clock seconds the invocation took.
        timed_out: whether the invocation timed out.
        missing_executable: whether the executable was not found on PATH.
    """

    command: str
    args: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    missing_executable: bool = False
    pid: int | None = None
    full_command: str = ""
    started_at: str = ""
    finished_at: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    @property
    def succeeded(self) -> bool:
        """Return True when the command completed successfully.

        A command is considered successful only when the returncode is 0 and
        it did not time out and the executable was present.
        """

        return self.returncode == 0 and not self.timed_out and not self.missing_executable

    @property
    def success(self) -> bool:
        """Alias for :attr:`succeeded` for callers that expect success status."""

        return self.succeeded


class AsyncCommandRunner:
    """Lightweight wrapper around asyncio subprocess execution.

    Usage:
        runner = AsyncCommandRunner()
        result = await runner.run("nmap", ["-v", "example.com"], timeout_seconds=30)
    """

    async def run(
        self,
        command: str,
        args: Iterable[str] | None = None,
        *,
        timeout_seconds: float = 60.0,
        input_text: str | None = None,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        """Execute ``command`` with ``args`` asynchronously.

        Parameters
        ----------
        command:
            The executable to run. This must be a program available on PATH
            or a fully qualified path to the binary.
        args:
            Iterable of string arguments. If ``None`` an empty arg list is used.
        timeout_seconds:
            Wall-clock timeout for the entire invocation; when exceeded the
            process will be terminated and ``timed_out`` will be True in the
            returned :class:`CommandResult`.
        input_text:
            Optional text to send to the process stdin (encoded as UTF-8).
        cwd:
            Optional working directory for the process.
        env:
            Optional environment overrides merged on top of the current
            process environment.

        Returns
        -------
        CommandResult
            Structured result with stdout/stderr, timing and status flags.
        """

        args_tuple = tuple(args or ())
        full_command = shlex.join((command, *args_tuple))
        started_at = _utc_now_iso8601()
        start_ns = perf_counter_ns()
        cwd_path = os.fspath(cwd) if cwd is not None else None
        merged_env = _normalize_env(env)

        logger.info(
            "Running command: %s (timeout=%.1fs) cwd=%s env_overrides=%s",
            full_command,
            float(timeout_seconds),
            cwd_path,
            None if env is None else sorted(str(key) for key in env.keys()),
        )

        # Detect missing executable early to provide a clean, testable result.
        if shutil.which(command) is None:
            msg = f"Executable not found: {command}"
            logger.warning(msg)
            finished_at = _utc_now_iso8601()
            return CommandResult(
                command=command,
                args=args_tuple,
                returncode=None,
                stdout="",
                stderr=msg,
                duration_seconds=0.0,
                missing_executable=True,
                full_command=full_command,
                started_at=started_at,
                finished_at=finished_at,
            )

        # Prepare input bytes if provided.
        input_bytes: bytes | None = input_text.encode("utf-8") if input_text is not None else None

        try:
            process = await asyncio.create_subprocess_exec(
                command,
                *args_tuple,
                stdin=asyncio.subprocess.PIPE if input_bytes is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd_path,
                env=merged_env,
            )
        except OSError as exc:  # e.g., permission denied, file not executable
            finished_at = _utc_now_iso8601()
            duration = (perf_counter_ns() - start_ns) / 1_000_000_000
            logger.exception("Failed to spawn process %s: %s", command, exc)
            return CommandResult(
                command=command,
                args=args_tuple,
                returncode=None,
                stdout="",
                stderr=str(exc),
                duration_seconds=duration,
                full_command=full_command,
                started_at=started_at,
                finished_at=finished_at,
            )

        stdout_task: asyncio.Task[tuple[str, bool]] | None = None
        stderr_task: asyncio.Task[tuple[str, bool]] | None = None

        try:
            stdout_task = asyncio.create_task(_collect_stream(process.stdout))
            stderr_task = asyncio.create_task(_collect_stream(process.stderr))

            if input_bytes is not None and process.stdin is not None:
                process.stdin.write(input_bytes)
                await process.stdin.drain()
                process.stdin.close()
                with suppress(Exception):
                    await process.stdin.wait_closed()

            await asyncio.wait_for(process.wait(), timeout=float(timeout_seconds))
            stdout_text, stdout_truncated = await stdout_task
            stderr_text, stderr_truncated = await stderr_task
            duration = (perf_counter_ns() - start_ns) / 1_000_000_000
            finished_at = _utc_now_iso8601()

            logger.debug(
                "Command finished: %s pid=%s rc=%s duration=%.3fs stdout_len=%d stderr_len=%d",
                full_command,
                getattr(process, "pid", None),
                process.returncode,
                duration,
                len(stdout_text),
                len(stderr_text),
            )

            if stdout_truncated or stderr_truncated:
                logger.warning(
                    "Command output truncated: %s stdout_truncated=%s stderr_truncated=%s",
                    full_command,
                    stdout_truncated,
                    stderr_truncated,
                )

            # Log a short sample of output at debug level to help debugging noisy tools.
            if logger.isEnabledFor(logging.DEBUG):
                sample = (stdout_text[:1024] + "...") if len(stdout_text) > 1024 else stdout_text
                if sample:
                    logger.debug("Stdout sample for %s: %s", full_command, sample)
                sample_err = (stderr_text[:1024] + "...") if len(stderr_text) > 1024 else stderr_text
                if sample_err:
                    logger.debug("Stderr sample for %s: %s", full_command, sample_err)

            logger.info(
                "Command completed: %s rc=%s duration=%.3fs missing=%s timeout=%s",
                full_command,
                process.returncode,
                duration,
                False,
                False,
            )

            return CommandResult(
                command=command,
                args=args_tuple,
                returncode=process.returncode,
                stdout=stdout_text,
                stderr=stderr_text,
                duration_seconds=duration,
                pid=process.pid,
                full_command=full_command,
                started_at=started_at,
                finished_at=finished_at,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )

        except asyncio.TimeoutError:
            # The process exceeded the allowed time; attempt graceful termination
            logger.warning("Command timed out after %.1fs: %s", timeout_seconds, full_command)
            try:
                process.kill()
                # Allow a short grace period for the OS to reap the process.
                with suppress(Exception):
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                if stdout_task is not None:
                    stdout_text, stdout_truncated = await stdout_task
                else:
                    stdout_text, stdout_truncated = "", False
                if stderr_task is not None:
                    stderr_text, stderr_truncated = await stderr_task
                else:
                    stderr_text, stderr_truncated = "", False
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception("Error while killing timed-out process %s: %s", full_command, exc)
                stdout_text, stdout_truncated = "", False
                stderr_text, stderr_truncated = "", False

            duration = (perf_counter_ns() - start_ns) / 1_000_000_000
            finished_at = _utc_now_iso8601()
            logger.info("Command completed with timeout: %s duration=%.3fs", full_command, duration)
            return CommandResult(
                command=command,
                args=args_tuple,
                returncode=None,
                stdout=stdout_text,
                stderr=stderr_text or f"Command timed out after {timeout_seconds} seconds",
                duration_seconds=duration,
                timed_out=True,
                pid=process.pid,
                full_command=full_command,
                started_at=started_at,
                finished_at=finished_at,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )

        except asyncio.CancelledError:
            logger.warning("Command cancelled: %s", full_command)
            with suppress(Exception):
                process.kill()
            with suppress(Exception):
                await process.wait()
            if stdout_task is not None:
                stdout_task.cancel()
                with suppress(Exception):
                    await stdout_task
            if stderr_task is not None:
                stderr_task.cancel()
                with suppress(Exception):
                    await stderr_task
            raise

        except Exception as exc:  # pragma: no cover - defensive
            # Unexpected exceptions during process management or decoding.
            logger.exception("Unexpected error running command %s: %s", full_command, exc)
            with suppress(Exception):
                process.kill()
            with suppress(Exception):
                await process.wait()
            if stdout_task is not None:
                stdout_task.cancel()
                with suppress(Exception):
                    await stdout_task
            if stderr_task is not None:
                stderr_task.cancel()
                with suppress(Exception):
                    await stderr_task
            duration = (perf_counter_ns() - start_ns) / 1_000_000_000
            finished_at = _utc_now_iso8601()
            logger.info("Command failed: %s duration=%.3fs", full_command, duration)
            return CommandResult(
                command=command,
                args=args_tuple,
                returncode=None,
                stdout="",
                stderr=str(exc),
                duration_seconds=duration,
                pid=process.pid,
                full_command=full_command,
                started_at=started_at,
                finished_at=finished_at,
            )
