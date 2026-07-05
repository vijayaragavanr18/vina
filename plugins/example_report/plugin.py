"""Example report plugin — adds a custom report section."""

from vina.plugins.sdk import HookPoint, Plugin, PluginContext, PluginMetadata


class ExampleReportPlugin(Plugin):
    """Demonstrates registering a custom report section."""

    metadata = PluginMetadata(
        id="example_report",
        name="Example Report",
        version="1.0.0",
        author="VINA Team",
        description="Adds a custom report section",
        license="MIT",
        categories=["report", "example"],
    )

    def on_load(self, context: PluginContext) -> None:
        context.logger.info("ExampleReportPlugin loaded")

    def register_report_sections(self):
        return [ExampleReportSection()]

    def register_hooks(self):
        return {
            HookPoint.BEFORE_REPORT: [self._before_report],
            HookPoint.AFTER_REPORT: [self._after_report],
        }

    @staticmethod
    def _before_report(event) -> None:
        event.data.setdefault("plugin_sections", []).append("example_report")

    @staticmethod
    def _after_report(event) -> None:
        event.data["report_complete"] = True


class ExampleReportSection:
    """A simple report section descriptor."""

    name = "example_report"
    title = "Example Report Section"
    order = 100

    def render_markdown(self, _data: dict) -> str:
        return "\n## Example Report Section\n\nThis is a plugin-provided report section.\n"

    def render_html(self, _data: dict) -> str:
        return '<div class="plugin-section"><h2>Example Report Section</h2><p>Plugin content.</p></div>\n'
