"""Dependency validation for external tools.

Provides a reusable dependency checker that detects whether required
external executables exist on PATH before pipeline execution begins.
Results are cached so each executable is checked only once per session.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import ClassVar

from .config import AppConfig

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class DependencyInfo:
    """Result of checking a single external tool dependency.

    Attributes:
        name: Logical tool name (e.g. ``"subfinder"``).
        available: Whether the executable was found on PATH.
        path: Resolved absolute path to the executable, or ``None``.
        version: Version string extracted via ``--version``, or ``None``.
    """

    name: str
    available: bool
    path: str | None
    version: str | None


class DependencyChecker:
    """Check and cache the availability of external tools.

    Uses ``shutil.which`` to resolve executables on PATH.  When an
    ``AppConfig`` is provided, tool names are first resolved through
    the configuration's ``tool_bin()`` mapping, allowing custom paths
    defined in ``config.yaml`` to be used.

    Results are cached in a class-level dictionary so that repeated
    checks for the same logical tool across different pipelines or
    calls return instantly without hitting the filesystem.
    """

    _global_cache: ClassVar[dict[str, DependencyInfo]] = {}

    def __init__(self, config: AppConfig | None = None) -> None:
        self.config = config

    def check(self, name: str) -> DependencyInfo:
        """Check availability of a single tool, using the cache if present.

        Parameters
        ----------
        name:
            Logical tool name (e.g. ``"nmap"``).

        Returns
        -------
        DependencyInfo
            Cached or freshly resolved dependency information.
        """
        if name in self._global_cache:
            return self._global_cache[name]

        binary = self._resolve_binary(name)
        path: str | None = shutil.which(binary)
        available: bool = path is not None
        version: str | None = self._detect_version(path) if path else None

        info = DependencyInfo(name=name, available=available, path=path, version=version)
        self._global_cache[name] = info

        if available:
            logger.debug("Dependency OK: %s -> %s", name, path)
        else:
            logger.warning("Dependency MISSING: %s (binary=%s)", name, binary)

        return info

    def check_all(self, names: list[str]) -> list[DependencyInfo]:
        """Check availability for every tool in *names*."""
        return [self.check(name) for name in names]

    @staticmethod
    def print_summary(results: list[DependencyInfo]) -> None:
        """Print a pre-flight dependency summary to the console."""
        lines = [
            "-" * 34,
            "Dependency Check",
            "-" * 34,
        ]
        for info in results:
            icon = "✓" if info.available else "✗"
            lines.append(f"  {icon} {info.name}")
        lines.append("-" * 34)
        print("\n".join(lines))

    def available(self, name: str) -> bool:
        """Return ``True`` if *name* is available (cached or fresh)."""
        return self.check(name).available

    @staticmethod
    def clear_cache() -> None:
        """Clear the global dependency cache (useful in tests)."""
        DependencyChecker._global_cache.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_binary(self, name: str) -> str:
        """Resolve the configured binary path for a logical tool name."""
        if self.config is not None:
            return self.config.tool_bin(name, name)
        return name

    @staticmethod
    def _detect_version(path: str) -> str | None:
        """Attempt to extract a version string via ``--version``.

        Tries ``--version`` first, then ``-v`` as a fallback.
        Returns ``None`` if neither succeeds.
        """
        for flag in ("--version", "-v"):
            try:
                result = subprocess.run(
                    [path, flag],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    line = (result.stdout or result.stderr).splitlines()
                    if line:
                        return line[0].strip()[:200]
            except (OSError, subprocess.TimeoutExpired):
                pass
        return None


__all__ = [
    "DependencyChecker",
    "DependencyInfo",
]
