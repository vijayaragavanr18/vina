"""Isolated execution environment for benchmarks and integration tests.

Provides temporary directories, mock HTTP servers for feed data,
and resource-limited subprocess execution.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, ClassVar

logger = logging.getLogger("vina.testing.sandbox")


class _MockFeedHandler(BaseHTTPRequestHandler):
    """Serves canned feed responses for testing the feed manager."""

    responses: ClassVar[dict[str, tuple[int, dict[str, str], bytes]]] = {}
    served_paths: ClassVar[list[str]] = []

    @classmethod
    def reset(cls) -> None:
        cls.responses = {}
        cls.served_paths = []

    def do_GET(self) -> None:
        self.__class__.served_paths.append(self.path)
        if self.path in self.responses:
            status, headers, body = self.responses[self.path]
        else:
            status, headers, body = 404, {"Content-Type": "text/plain"}, b"Not found"
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args) -> None:
        logger.debug("MockFeed: %s", fmt % args)


class TestSandbox:
    """Creates and manages an isolated test environment.

    Usage::

        with TestSandbox() as sandbox:
            sandbox.write_config({"output_dir": str(sandbox.tmpdir)})
            sandbox.start_mock_feed_server()
            result = sandbox.run_pipeline(...)
    """

    def __init__(self, base_dir: str | Path | None = None) -> None:
        self._tmpdir: Path | None = None
        self._base_dir = Path(base_dir) if base_dir else None
        self._feed_server: HTTPServer | None = None
        self._feed_thread: threading.Thread | None = None
        self._feed_port: int = 0
        self._env_patch: dict[str, str] = {}

    # -- Context manager ---------------------------------------------------

    def __enter__(self) -> TestSandbox:
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()

    # -- Lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._tmpdir = Path(tempfile.mkdtemp(dir=self._base_dir))
        self._feed_server = None
        self._feed_thread = None
        self._env_patch = {}
        logger.info("TestSandbox started at %s", self._tmpdir)

    def stop(self) -> None:
        self.stop_mock_feed_server()
        if self._tmpdir and self._tmpdir.exists():
            import shutil

            shutil.rmtree(self._tmpdir, ignore_errors=True)
        logger.info("TestSandbox stopped")

    # -- Properties --------------------------------------------------------

    @property
    def tmpdir(self) -> Path:
        assert self._tmpdir is not None, "TestSandbox not started"
        return self._tmpdir

    @property
    def output_dir(self) -> Path:
        return self.tmpdir / "output"

    @property
    def reports_dir(self) -> Path:
        return self.output_dir / "reports"

    @property
    def feed_dir(self) -> Path:
        return self.tmpdir / "feeds"

    @property
    def feed_port(self) -> int:
        return self._feed_port

    @property
    def feed_url(self) -> str:
        return f"http://127.0.0.1:{self._feed_port}"

    # -- File helpers ------------------------------------------------------

    def write_config(self, config: dict[str, Any]) -> Path:
        """Write a YAML config file for pipeline tests."""
        path = self.tmpdir / "config.yaml"
        import yaml

        with open(path, "w") as f:
            yaml.dump(config, f)
        return path

    def write_json(self, path: str | Path, data: Any) -> Path:
        """Write a JSON data file."""
        full_path = self.tmpdir / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(json.dumps(data, indent=2))
        return full_path

    def write_text(self, path: str | Path, text: str) -> Path:
        """Write a text file."""
        full_path = self.tmpdir / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(text)
        return full_path

    # -- Mock feed server --------------------------------------------------

    def start_mock_feed_server(self) -> int:
        """Start a mock HTTP server that serves canned feed responses.

        Returns the port number.
        """
        _MockFeedHandler.reset()
        server = HTTPServer(("127.0.0.1", 0), _MockFeedHandler)
        self._feed_port = server.server_address[1]
        self._feed_server = server
        self._feed_thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._feed_thread.start()
        logger.info("Mock feed server started on port %d", self._feed_port)
        return self._feed_port

    def stop_mock_feed_server(self) -> None:
        if self._feed_server:
            self._feed_server.shutdown()
            self._feed_server.server_close()
            self._feed_server = None
        self._feed_thread = None

    def set_feed_response(
        self, path: str, status: int = 200, body: bytes = b"", content_type: str = "application/json"
    ) -> None:
        """Set the response for a specific path on the mock feed server."""
        _MockFeedHandler.responses[path] = (status, {"Content-Type": content_type}, body)
        _MockFeedHandler.served_paths.clear()

    def set_feed_json_response(self, path: str, data: Any) -> None:
        """Set a JSON response for a specific path on the mock feed server."""
        self.set_feed_response(path, 200, json.dumps(data).encode(), "application/json")

    @property
    def feed_requests(self) -> list[str]:
        return list(_MockFeedHandler.served_paths)

    # -- Environment helpers -----------------------------------------------

    def set_env(self, key: str, value: str) -> None:
        """Set an environment variable for the sandbox."""
        self._env_patch[key] = value

    def apply_env(self) -> dict[str, str]:
        """Apply patched env vars and return the full environment dict."""
        env = dict(os.environ)
        env.update(self._env_patch)
        return env

    # -- Subprocess runner -------------------------------------------------

    def run_command(self, cmd: list[str], timeout: float = 60.0, **kwargs: Any) -> subprocess.CompletedProcess:
        """Run a subprocess inside the sandbox tmpdir."""
        kwargs.setdefault("cwd", str(self.tmpdir))
        kwargs.setdefault("env", self.apply_env())
        kwargs.setdefault("capture_output", True)
        kwargs.setdefault("text", True)
        return subprocess.run(cmd, timeout=timeout, **kwargs)


__all__ = ["TestSandbox", "_MockFeedHandler"]
