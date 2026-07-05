"""Plugin registry — the central hub for managing plugins and executing hooks."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from .exceptions import PluginNotFoundError
from .hooks import HookEvent, HookRegistration, is_valid_hook_point
from .plugin import Plugin

logger = logging.getLogger("vina.plugins.registry")


class PluginRegistry:
    """Central registry for plugins and hook handlers.

    This is a simple container — it does not load or discover plugins on its
    own (see :class:`PluginLoader` for that).
    """

    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}
        self._enabled: dict[str, bool] = {}
        self._hooks: dict[str, list[HookRegistration]] = defaultdict(list)
        self._scanners: dict[str, type] = {}
        self._enrichment_rules: list[Any] = []
        self._correlation_rules: list[Any] = []
        self._report_sections: list[Any] = []
        self._cli_commands: list[Any] = []
        self._parsers: list[Any] = []
        self._exporters: list[Any] = []

    # -- Plugin lifecycle ---------------------------------------------------

    def register(self, plugin: Plugin) -> None:
        """Register a plugin and (by default) enable it."""
        pid = plugin.metadata.id
        if pid in self._plugins:
            logger.warning("Overwriting already-registered plugin '%s'", pid)
        self._plugins[pid] = plugin
        self._enabled[pid] = True
        self._collect_registrations(plugin)
        logger.info("Registered plugin '%s' v%s", pid, plugin.metadata.version)

    def unregister(self, plugin_id: str) -> None:
        """Unregister a plugin and remove its hook handlers."""
        plugin = self._get_or_raise(plugin_id)
        plugin.on_unload()
        self._remove_hooks_for(plugin_id)
        self._plugins.pop(plugin_id, None)
        self._enabled.pop(plugin_id, None)
        logger.info("Unregistered plugin '%s'", plugin_id)

    def get(self, plugin_id: str) -> Plugin | None:
        return self._plugins.get(plugin_id)

    def get_enabled(self, plugin_id: str) -> Plugin | None:
        p = self.get(plugin_id)
        if p is not None and self._enabled.get(plugin_id, True):
            return p
        return None

    def list_plugins(self) -> list[Plugin]:
        return list(self._plugins.values())

    def list_enabled(self) -> list[Plugin]:
        return [p for pid, p in self._plugins.items() if self._enabled.get(pid, True)]

    def count(self) -> int:
        return len(self._plugins)

    # -- Enable / disable ---------------------------------------------------

    def enable(self, plugin_id: str) -> None:
        plugin = self._get_or_raise(plugin_id)
        self._enabled[plugin_id] = True
        plugin._enabled = True
        plugin.on_enable()
        logger.info("Enabled plugin '%s'", plugin_id)

    def disable(self, plugin_id: str) -> None:
        plugin = self._get_or_raise(plugin_id)
        self._enabled[plugin_id] = False
        plugin._enabled = False
        plugin.on_disable()
        logger.info("Disabled plugin '%s'", plugin_id)

    def is_enabled(self, plugin_id: str) -> bool:
        plugin = self.get(plugin_id)
        if plugin is None:
            raise PluginNotFoundError(plugin_id)
        return self._enabled.get(plugin_id, True)

    # -- Hook management ---------------------------------------------------

    def add_hook(self, hook_point: str, handler: Callable, *, priority: int = 0, plugin_id: str = "") -> None:
        if not is_valid_hook_point(hook_point):
            logger.warning("Unknown hook point '%s'", hook_point)
        reg = HookRegistration(handler=handler, priority=priority, plugin_id=plugin_id)
        self._hooks[hook_point].append(reg)
        self._hooks[hook_point].sort(key=lambda r: r.priority, reverse=False)

    def remove_hooks(self, hook_point: str) -> None:
        self._hooks.pop(hook_point, None)

    def _remove_hooks_for(self, plugin_id: str) -> None:
        for hp in list(self._hooks):
            self._hooks[hp] = [r for r in self._hooks[hp] if r.plugin_id != plugin_id]

    def run_hook(self, hook_point: str, **data: Any) -> HookEvent:
        """Execute all handlers registered for *hook_point*.

        Returns the accumulated :class:`HookEvent` so callers can inspect
        modifications to ``data`` or check for errors.
        """
        event = HookEvent(hook_point=hook_point, data=data)
        registrations = list(self._hooks.get(hook_point, []))
        registrations.sort(key=lambda r: r.priority)
        for reg in registrations:
            if event.cancelled:
                break
            pid = reg.plugin_id
            if pid and not self._enabled.get(pid, True):
                continue
            try:
                result = reg.handler(event)
                event.results.append(result)
            except Exception as exc:
                logger.error(
                    "Hook '%s' handler from '%s' failed: %s", hook_point, reg.plugin_id or "?", exc, exc_info=True
                )
                event.errors.append((reg.plugin_id or "?", exc))
        return event

    # -- Capability collections ---------------------------------------------

    def get_scanners(self) -> dict[str, type]:
        return dict(self._scanners)

    def get_enrichment_rules(self) -> list[Any]:
        return list(self._enrichment_rules)

    def get_correlation_rules(self) -> list[Any]:
        return list(self._correlation_rules)

    def get_report_sections(self) -> list[Any]:
        return list(self._report_sections)

    def get_cli_commands(self) -> list[Any]:
        return list(self._cli_commands)

    def get_parsers(self) -> list[Any]:
        return list(self._parsers)

    def get_exporters(self) -> list[Any]:
        return list(self._exporters)

    # -- Internal helpers ---------------------------------------------------

    def _get_or_raise(self, plugin_id: str) -> Plugin:
        plugin = self._plugins.get(plugin_id)
        if plugin is None:
            raise PluginNotFoundError(f"Plugin '{plugin_id}' not found")
        return plugin

    def _collect_registrations(self, plugin: Plugin) -> None:
        pid = plugin.metadata.id

        scanners = plugin.register_scanners()
        if scanners:
            for s in scanners:
                name = getattr(s, "__name__", type(s).__name__)
                self._scanners[name] = s

        rules = plugin.register_enrichment_rules()
        if rules:
            self._enrichment_rules.extend(rules)

        corr = plugin.register_correlation_rules()
        if corr:
            self._correlation_rules.extend(corr)

        sections = plugin.register_report_sections()
        if sections:
            self._report_sections.extend(sections)

        cmds = plugin.register_cli_commands()
        if cmds:
            self._cli_commands.extend(cmds)

        parsers = plugin.register_parsers()
        if parsers:
            self._parsers.extend(parsers)

        exporters = plugin.register_exporters()
        if exporters:
            self._exporters.extend(exporters)

        hooks = plugin.register_hooks()
        if hooks:
            for hp, handlers in hooks.items():
                for h in handlers:
                    if callable(h):
                        self.add_hook(hp, h, plugin_id=pid)
                    elif isinstance(h, (list, tuple)):
                        handler_fn, priority = h[0], h[1] if len(h) > 1 else 0
                        self.add_hook(hp, handler_fn, priority=priority, plugin_id=pid)


_REGISTRY: PluginRegistry | None = None


def get_registry() -> PluginRegistry:
    """Return the application-wide singleton registry."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = PluginRegistry()
    return _REGISTRY


def reset_registry() -> None:
    """Reset the singleton registry (useful in tests)."""
    global _REGISTRY
    _REGISTRY = PluginRegistry()


__all__ = ["PluginRegistry", "get_registry", "reset_registry"]
