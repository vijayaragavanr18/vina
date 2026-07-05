"""VINA Plugin SDK — extensibility framework.

Usage::

    from vina.plugins.sdk import Plugin, PluginMetadata, PluginContext

See the individual modules for detailed documentation.
"""

from . import exceptions, hooks, loader, plugin, registry, sdk
from .context import PluginContext
from .exceptions import (
    PluginDependencyError,
    PluginDisabledError,
    PluginError,
    PluginHookError,
    PluginLoadError,
    PluginNotFoundError,
    PluginVersionError,
)
from .hooks import HookEvent, HookPoint
from .loader import PluginLoader
from .plugin import Plugin, PluginMetadata
from .registry import PluginRegistry, get_registry, reset_registry
from .sdk import make_finding, Finding, Severity, FindingCategory

__all__ = [
    "Plugin",
    "PluginMetadata",
    "PluginContext",
    "PluginLoader",
    "PluginRegistry",
    "get_registry",
    "reset_registry",
    "HookPoint",
    "HookEvent",
    "PluginError",
    "PluginLoadError",
    "PluginNotFoundError",
    "PluginDependencyError",
    "PluginDisabledError",
    "PluginHookError",
    "PluginVersionError",
    "Finding",
    "Severity",
    "FindingCategory",
    "make_finding",
    "exceptions",
    "hooks",
    "loader",
    "plugin",
    "registry",
    "sdk",
]
