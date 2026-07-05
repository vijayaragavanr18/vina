"""Example enrichment plugin — adds custom enrichment rules."""

from vina.plugins.sdk import HookPoint, Plugin, PluginContext, PluginMetadata


class ExampleEnrichmentPlugin(Plugin):
    """Demonstrates registering custom enrichment rules."""

    metadata = PluginMetadata(
        id="example_enrichment",
        name="Example Enrichment",
        version="1.0.0",
        author="VINA Team",
        description="Adds custom knowledge-base enrichment rules",
        license="MIT",
        categories=["enrichment", "example"],
    )

    def on_load(self, context: PluginContext) -> None:
        context.logger.info("ExampleEnrichmentPlugin loaded")

    def register_enrichment_rules(self):
        from vina.core.knowledge import KnowledgeRule

        return [
            KnowledgeRule(
                rule_id="EXAMPLE-001",
                title_patterns=["custom finding", "example finding"],
                explanation="This is an example enrichment rule from a plugin.",
                security_impact="Low — demonstration only.",
                remediation="No action required.",
                references=["https://example.com/plugin-docs"],
                confidence_score=0.5,
            ),
        ]

    def register_hooks(self):
        return {
            HookPoint.BEFORE_FINDING: [self._tag_findings],
            HookPoint.AFTER_FINDING: [self._log_findings],
        }

    @staticmethod
    def _tag_findings(event) -> None:
        findings = event.data.get("findings", [])
        for f in findings:
            if "example" in f.title.lower():
                f.tags.append("plugin_tagged")

    @staticmethod
    def _log_findings(event) -> None:
        count = len(event.data.get("findings", []))
        event.data.setdefault("plugin_stats", {})["example_enrichment"] = count
