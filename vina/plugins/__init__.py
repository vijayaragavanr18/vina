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
from .sdk import Finding, FindingCategory, Severity, make_finding

__all__ = [
    "Finding",
    "FindingCategory",
    "HookEvent",
    "HookPoint",
    "Plugin",
    "PluginContext",
    "PluginDependencyError",
    "PluginDisabledError",
    "PluginError",
    "PluginHookError",
    "PluginLoadError",
    "PluginLoader",
    "PluginMetadata",
    "PluginNotFoundError",
    "PluginRegistry",
    "PluginVersionError",
    "Severity",
    "exceptions",
    "get_registry",
    "hooks",
    "loader",
    "make_finding",
    "plugin",
    "registry",
    "reset_registry",
    "sdk",
]
