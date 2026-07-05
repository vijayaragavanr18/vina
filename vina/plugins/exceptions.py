"""Custom exceptions for the VINA Plugin SDK."""


class PluginError(Exception):
    """Base exception for all plugin-related errors."""


class PluginLoadError(PluginError):
    """Raised when a plugin cannot be loaded."""


class PluginNotFoundError(PluginError):
    """Raised when a plugin is not found in the registry."""


class PluginDependencyError(PluginError):
    """Raised when a plugin's dependencies are not satisfied."""


class PluginDisabledError(PluginError):
    """Raised when an operation is attempted on a disabled plugin."""


class PluginHookError(PluginError):
    """Raised when a hook handler fails."""


class PluginVersionError(PluginError):
    """Raised when a plugin requires a newer VINA version."""


__all__ = [
    "PluginError",
    "PluginLoadError",
    "PluginNotFoundError",
    "PluginDependencyError",
    "PluginDisabledError",
    "PluginHookError",
    "PluginVersionError",
]
