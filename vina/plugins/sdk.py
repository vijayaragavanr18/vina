"""VINA Plugin SDK — convenience re-exports for plugin authors.

Usage::

    from vina.plugins.sdk import *

Or import individual items::

    from vina.plugins.sdk import Plugin, PluginMetadata, PluginContext
"""

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

# VINA types commonly needed by plugins
from ..models.findings import Finding, Severity, FindingCategory, make_finding

__all__ = [
    # Plugin base
    "Plugin",
    "PluginMetadata",
    "PluginContext",
    # Registry
    "PluginRegistry",
    "get_registry",
    "reset_registry",
    # Hooks
    "HookPoint",
    "HookEvent",
    "HookRegistration",
    "is_valid_hook_point",
    # Exceptions
    "PluginError",
    "PluginLoadError",
    "PluginNotFoundError",
    "PluginDependencyError",
    "PluginDisabledError",
    "PluginHookError",
    "PluginVersionError",
    # VINA types
    "Finding",
    "Severity",
    "FindingCategory",
    "make_finding",
]
