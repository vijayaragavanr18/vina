"""VINA Plugin SDK — convenience re-exports for plugin authors.

Usage::

    from vina.plugins.sdk import *

Or import individual items::

    from vina.plugins.sdk import Plugin, PluginMetadata, PluginContext
"""

# VINA types commonly needed by plugins
from ..models.findings import Finding, FindingCategory, Severity, make_finding
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
from .hooks import HookEvent, HookPoint, HookRegistration, is_valid_hook_point
from .plugin import Plugin, PluginMetadata
from .registry import PluginRegistry, get_registry, reset_registry

__all__ = [
    "Finding",
    "FindingCategory",
    "HookEvent",
    "HookPoint",
    "HookRegistration",
    "Plugin",
    "PluginContext",
    "PluginDependencyError",
    "PluginDisabledError",
    "PluginError",
    "PluginHookError",
    "PluginLoadError",
    "PluginMetadata",
    "PluginNotFoundError",
    "PluginRegistry",
    "PluginVersionError",
    "Severity",
    "get_registry",
    "is_valid_hook_point",
    "make_finding",
    "reset_registry",
]
