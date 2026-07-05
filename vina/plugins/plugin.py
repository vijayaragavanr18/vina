"""Plugin base class and metadata model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .context import PluginContext


@dataclass(slots=True)
class PluginMetadata:
    """Declarative metadata for a VINA plugin."""

    id: str
    name: str
    version: str
    author: str = ""
    description: str = ""
    license: str = ""
    homepage: str = ""
    minimum_vina_version: str = "0.1.0"
    categories: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "license": self.license,
            "homepage": self.homepage,
            "minimum_vina_version": self.minimum_vina_version,
            "categories": list(self.categories),
            "dependencies": list(self.dependencies),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PluginMetadata:
        return cls(
            id=data["id"],
            name=data.get("name", data["id"]),
            version=data.get("version", "0.1.0"),
            author=data.get("author", ""),
            description=data.get("description", ""),
            license=data.get("license", ""),
            homepage=data.get("homepage", ""),
            minimum_vina_version=data.get("minimum_vina_version", "0.1.0"),
            categories=list(data.get("categories", [])),
            dependencies=list(data.get("dependencies", [])),
        )


class Plugin:
    """Base class that all VINA plugins must subclass."""

    metadata: PluginMetadata

    def __init__(self) -> None:
        self._enabled: bool = True
        self._context: PluginContext | None = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    def on_load(self, context: PluginContext) -> None:
        """Called after the plugin is loaded and registered."""

    def on_unload(self) -> None:
        """Called when the plugin is unregistered."""

    def on_enable(self) -> None:
        """Called when the plugin is enabled."""

    def on_disable(self) -> None:
        """Called when the plugin is disabled."""

    # -- Registration hooks (override to provide capabilities) --

    def register_scanners(self):  # -> list[type] | None
        """Return scanner module classes to register."""
        return None

    def register_enrichment_rules(self):  # -> list[KnowledgeRule] | None
        """Return enrichment rules to register."""
        return None

    def register_correlation_rules(self):  # -> list[CorrelationRule] | None
        """Return correlation rules to register."""
        return None

    def register_report_sections(self):  # -> list[ReportSection] | None
        """Return report sections to register."""
        return None

    def register_cli_commands(self):  # -> list[CLICommand] | None
        """Return CLI commands to register."""
        return None

    def register_parsers(self):  # -> list[ParserDef] | None
        """Return output parsers to register."""
        return None

    def register_exporters(self):  # -> list[ExporterDef] | None
        """Return data exporters to register."""
        return None

    def register_hooks(self):  # -> dict[str, list[Callable]] | None
        """Return additional hook handlers."""
        return None


__all__ = [
    "Plugin",
    "PluginMetadata",
]
