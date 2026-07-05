"""Version information for VINA."""

__version__ = "0.1.0"

VERSION_INFO = {
    "major": 0,
    "minor": 1,
    "patch": 0,
    "pre_release": None,
    "build": None,
}


def version_str() -> str:
    """Return the current VINA version string."""
    return __version__


def version_tuple() -> tuple[int, int, int]:
    """Return the version as a tuple of (major, minor, patch)."""
    parts = __version__.split(".")
    return tuple(int(p) for p in parts[:3])  # type: ignore[return-value]


__all__ = [
    "VERSION_INFO",
    "__version__",
    "version_str",
    "version_tuple",
]
