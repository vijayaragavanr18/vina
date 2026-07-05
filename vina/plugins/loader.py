"""Plugin discovery and loading."""

from __future__ import annotations

import importlib
import importlib.metadata
import inspect
import logging
import sys
from pathlib import Path

from .exceptions import PluginLoadError, PluginVersionError
from .plugin import Plugin, PluginMetadata

logger = logging.getLogger("vina.plugins.loader")

# Directories checked for local plugin packages
LOCAL_PLUGIN_DIRS: list[Path] = [Path.cwd() / "plugins", Path.home() / ".vina" / "plugins"]

ENTRY_POINT_GROUP = "vina.plugins"

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------


def _check_vina_version(metadata: PluginMetadata) -> None:
    """Raise :class:`PluginVersionError` if the plugin requires a newer VINA."""
    from .. import __version__

    required = metadata.minimum_vina_version
    if required and _compare_versions(__version__, required) < 0:
        raise PluginVersionError(f"Plugin '{metadata.id}' requires VINA {required} (installed: {__version__})")


def _compare_versions(installed: str, required: str) -> int:
    """Compare two semver-like version strings. Returns -1, 0, or 1."""
    inst_parts = [int(x) for x in installed.split(".")]
    req_parts = [int(x) for x in required.split(".")]
    for a, b in zip(inst_parts, req_parts):
        if a < b:
            return -1
        if a > b:
            return 1
    if len(inst_parts) < len(req_parts):
        return -1
    if len(inst_parts) > len(req_parts):
        return 1
    return 0


def _find_plugin_classes(module: object) -> list[type[Plugin]]:
    """Return all :class:`Plugin` subclasses found in *module*."""
    results: list[type[Plugin]] = []
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, Plugin) and obj is not Plugin and not inspect.isabstract(obj):
            results.append(obj)
    return results


# ---------------------------------------------------------------------------
#  Loader
# ---------------------------------------------------------------------------


class PluginLoader:
    """Discovers and instantiates plugins from multiple sources."""

    def __init__(self) -> None:
        self._loaded_paths: set[Path] = set()

    # -- Built-in plugins ---------------------------------------------------

    def load_builtin(self) -> list[Plugin]:
        """Load plugins bundled inside ``vina/plugins/builtin/``."""
        builtin_dir = Path(__file__).parent / "builtin"
        if not builtin_dir.is_dir():
            return []
        return self._load_directory(builtin_dir)

    # -- Local directory plugins -------------------------------------------

    def load_local(self, extra_dirs: list[Path] | None = None) -> list[Plugin]:
        """Scan standard local plugin directories + *extra_dirs*."""
        dirs = list(LOCAL_PLUGIN_DIRS)
        if extra_dirs:
            dirs.extend(extra_dirs)
        plugins: list[Plugin] = []
        for d in dirs:
            if d.is_dir() and d not in self._loaded_paths:
                try:
                    plugins.extend(self._load_directory(d))
                    self._loaded_paths.add(d)
                except Exception:
                    logger.warning("Failed to load plugins from '%s'", d, exc_info=True)
        return plugins

    # -- Entry-point plugins ------------------------------------------------

    def load_entry_points(self) -> list[Plugin]:
        """Discover plugins registered via the ``vina.plugins`` entry point."""
        plugins: list[Plugin] = []
        try:
            eps = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
        except TypeError:
            # Python 3.9 compat
            eps = importlib.metadata.entry_points().get(ENTRY_POINT_GROUP, [])

        for ep in eps:
            try:
                cls = ep.load()
                if inspect.isclass(cls) and issubclass(cls, Plugin) and cls is not Plugin:
                    instance = cls()
                    plugins.append(instance)
                    logger.info("Loaded entry-point plugin '%s' from %s", instance.metadata.id, ep.module)
            except Exception:
                logger.warning("Failed to load entry-point plugin '%s'", ep.name, exc_info=True)
        return plugins

    # -- Module-path plugin ------------------------------------------------

    def load_module(self, module_path: str) -> Plugin | None:
        """Import a dotted module path and return the first Plugin subclass found."""
        try:
            module = importlib.import_module(module_path)
        except Exception as exc:
            raise PluginLoadError(f"Cannot import module '{module_path}': {exc}") from exc

        classes = _find_plugin_classes(module)
        if not classes:
            logger.warning("No Plugin subclass found in '%s'", module_path)
            return None
        if len(classes) > 1:
            logger.warning("Multiple Plugin subclasses in '%s'; using first one", module_path)
        instance = classes[0]()
        _check_vina_version(instance.metadata)
        return instance

    # -- Manual registration via class --------------------------------------

    def load_class(self, plugin_cls: type[Plugin]) -> Plugin:
        """Instantiate a :class:`Plugin` subclass directly."""
        if not issubclass(plugin_cls, Plugin) or plugin_cls is Plugin:
            raise PluginLoadError(f"{plugin_cls.__name__} is not a Plugin subclass")
        instance = plugin_cls()
        _check_vina_version(instance.metadata)
        return instance

    # -- Discovery convenience ----------------------------------------------

    def discover_all(self, extra_dirs: list[Path] | None = None) -> list[Plugin]:
        """Discover plugins from all sources and return them."""
        plugins: list[Plugin] = []
        for loader in (self.load_builtin, lambda: self.load_local(extra_dirs), self.load_entry_points):
            try:
                plugins.extend(loader())
            except Exception:
                logger.warning("Plugin discovery step failed", exc_info=True)
        return plugins

    # -- Internal helpers ---------------------------------------------------

    def _load_directory(self, directory: Path) -> list[Plugin]:
        """Scan *directory* for plugin packages (directories with ``plugin.py``)."""
        plugins: list[Plugin] = []
        if not directory.is_dir():
            return plugins
        for entry in sorted(directory.iterdir()):
            if not entry.is_dir() or entry.name.startswith("__"):
                continue
            plugin_file = entry / "plugin.py"
            if not plugin_file.is_file():
                continue
            try:
                plugin = self._load_single(entry)
                if plugin is not None:
                    plugins.append(plugin)
            except Exception:
                logger.warning("Failed to load plugin from '%s'", entry, exc_info=True)
        return plugins

    def _load_single(self, plugin_dir: Path) -> Plugin | None:
        """Load a single plugin from a directory."""
        sys.path.insert(0, str(plugin_dir.parent))
        try:
            mod_name = plugin_dir.name
            module = importlib.import_module(f"{mod_name}.plugin")
            classes = _find_plugin_classes(module)
            if not classes:
                return None
            instance = classes[0]()
            _check_vina_version(instance.metadata)
            return instance
        except PluginVersionError:
            raise
        except Exception as exc:
            raise PluginLoadError(f"Cannot load plugin from '{plugin_dir}': {exc}") from exc
        finally:
            if sys.path and sys.path[0] == str(plugin_dir.parent):
                sys.path.pop(0)


__all__ = ["ENTRY_POINT_GROUP", "LOCAL_PLUGIN_DIRS", "PluginLoader"]
