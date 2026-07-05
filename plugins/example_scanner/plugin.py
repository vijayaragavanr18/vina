"""Example scanner plugin — adds a custom system scan stage."""

from vina.plugins.sdk import Plugin, PluginMetadata, PluginContext
from vina.plugins.sdk import HookPoint


class ExampleScannerPlugin(Plugin):
    """Demonstrates registering a custom scanner and hook handlers."""

    metadata = PluginMetadata(
        id="example_scanner",
        name="Example Scanner",
        version="1.0.0",
        author="VINA Team",
        description="Registers a dummy scanner and pipeline hooks",
        license="MIT",
        categories=["scanner", "example"],
    )

    def on_load(self, context: PluginContext) -> None:
        context.logger.info("ExampleScannerPlugin loaded")

    def register_scanners(self):
        """Provide a scanner module class."""
        return [ExampleScanner]

    def register_hooks(self):
        return {
            HookPoint.BEFORE_PIPELINE: [self._on_before_pipeline],
            HookPoint.AFTER_PIPELINE: [self._on_after_pipeline],
        }

    @staticmethod
    def _on_before_pipeline(event) -> None:
        event.data.setdefault("greetings", []).append("from example_scanner")

    @staticmethod
    def _on_after_pipeline(event) -> None:
        event.data.setdefault("farewells", []).append("from example_scanner")


class ExampleScanner:
    """A trivial scanner module that plugins can register with the pipeline."""

    def __init__(self, config=None, context=None) -> None:
        self.config = config
        self.context = context

    async def run(self, target) -> dict:
        return {"plugin": "example_scanner", "target": str(target)}
