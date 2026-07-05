"""Plugin runtime context."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..core.config import AppConfig
    from ..core.dependency import DependencyChecker


logger = logging.getLogger("vina.plugins")


@dataclass
class PluginContext:
    """Runtime context provided to every plugin on load.

    Provides access to VINA core services so plugins can interact with the
    framework without importing internals directly.
    """

    logger: logging.Logger = field(default_factory=lambda: logger.getChild("plugin"))
    config: Any = None
    output_dir: Path | None = None
    dependency_checker: Any = None
    knowledge_base: Any = None
    vulnerability_database: Any = None
    feed_manager: Any = None
    data_dir: Path | None = None
    plugin_dir: Path | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        config: AppConfig | None = None,
        output_dir: Path | None = None,
        dependency_checker: DependencyChecker | None = None,
        knowledge_base: Any = None,
        vulnerability_database: Any = None,
        feed_manager: Any = None,
        data_dir: Path | None = None,
        plugin_dir: Path | None = None,
        **extra: Any,
    ) -> PluginContext:
        return cls(
            logger=logger.getChild("plugin"),
            config=config,
            output_dir=output_dir or Path("output"),
            dependency_checker=dependency_checker,
            knowledge_base=knowledge_base,
            vulnerability_database=vulnerability_database,
            feed_manager=feed_manager,
            data_dir=data_dir,
            plugin_dir=plugin_dir,
            extra=extra,
        )


__all__ = ["PluginContext"]
