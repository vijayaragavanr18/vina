"""Unit tests for the VINA Plugin SDK."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vina.plugins.context import PluginContext
from vina.plugins.exceptions import (
    PluginDependencyError,
    PluginDisabledError,
    PluginError,
    PluginHookError,
    PluginLoadError,
    PluginNotFoundError,
    PluginVersionError,
)
from vina.plugins.hooks import HookEvent, HookPoint, get_all_hook_points, is_valid_hook_point
from vina.plugins.loader import PluginLoader
from vina.plugins.plugin import Plugin, PluginMetadata
from vina.plugins.registry import get_registry, reset_registry
from vina.plugins.sdk import Finding, make_finding

# =========================================================================
#  PluginMetadata
# =========================================================================


class TestPluginMetadata:
    def test_default_values(self):
        m = PluginMetadata(id="test", name="Test", version="1.0.0")
        assert m.author == ""
        assert m.description == ""
        assert m.license == ""
        assert m.homepage == ""
        assert m.minimum_vina_version == "0.1.0"
        assert m.categories == []
        assert m.dependencies == []

    def test_to_dict(self):
        m = PluginMetadata(
            id="test",
            name="Test",
            version="1.0.0",
            author="me",
            description="desc",
            license="MIT",
            homepage="https://example.com",
            minimum_vina_version="0.2.0",
            categories=["scanner"],
            dependencies=["other"],
        )
        d = m.to_dict()
        assert d["id"] == "test"
        assert d["version"] == "1.0.0"
        assert d["author"] == "me"
        assert d["categories"] == ["scanner"]

    def test_from_dict(self):
        m = PluginMetadata.from_dict(
            {
                "id": "p2",
                "name": "P2",
                "version": "2.0.0",
                "author": "a",
                "description": "d",
                "license": "MIT",
                "homepage": "https://x",
                "minimum_vina_version": "0.3.0",
                "categories": ["report"],
                "dependencies": ["dep1"],
            }
        )
        assert m.id == "p2"
        assert m.version == "2.0.0"
        assert m.categories == ["report"]

    def test_from_dict_minimal(self):
        m = PluginMetadata.from_dict({"id": "min"})
        assert m.id == "min"
        assert m.name == "min"
        assert m.version == "0.1.0"


# =========================================================================
#  Plugin base class
# =========================================================================


class TestPlugin:
    def test_default_enabled(self):
        class TestPluginImpl(Plugin):
            metadata = PluginMetadata(id="t1", name="T1", version="1.0.0")

        p = TestPluginImpl()
        assert p.enabled is True

    def test_lifecycle_methods(self):
        class LCPlugin(Plugin):
            metadata = PluginMetadata(id="lc", name="LC", version="1.0.0")

            def __init__(self):
                super().__init__()
                self.events = []

            def on_load(self, _ctx):
                self.events.append("load")

            def on_unload(self):
                self.events.append("unload")

            def on_enable(self):
                self.events.append("enable")

            def on_disable(self):
                self.events.append("disable")

        p = LCPlugin()
        p.on_load(MagicMock())
        p.on_enable()
        p.on_disable()
        p.on_unload()
        assert p.events == ["load", "enable", "disable", "unload"]

    def test_registration_methods_default_none(self):
        class EmptyPlugin(Plugin):
            metadata = PluginMetadata(id="e", name="E", version="1.0.0")

        p = EmptyPlugin()
        assert p.register_scanners() is None
        assert p.register_enrichment_rules() is None
        assert p.register_correlation_rules() is None
        assert p.register_report_sections() is None
        assert p.register_cli_commands() is None
        assert p.register_parsers() is None
        assert p.register_exporters() is None
        assert p.register_hooks() is None


# =========================================================================
#  PluginContext
# =========================================================================


class TestPluginContext:
    def test_create_defaults(self):
        ctx = PluginContext.create()
        assert ctx.output_dir == Path("output")
        assert ctx.config is None

    def test_create_with_args(self):
        ctx = PluginContext.create(
            output_dir=Path("/tmp/test"),
            custom_key="custom_val",
        )
        assert ctx.output_dir == Path("/tmp/test")
        assert ctx.extra["custom_key"] == "custom_val"

    def test_logger_created(self):
        ctx = PluginContext.create()
        assert ctx.logger.name == "vina.plugins.plugin"


# =========================================================================
#  Hook system
# =========================================================================


class TestHookSystem:
    def test_hook_point_enum_values(self):
        assert HookPoint.BEFORE_PIPELINE == "before_pipeline"
        assert HookPoint.AFTER_PIPELINE == "after_pipeline"
        assert HookPoint.BEFORE_STAGE == "before_stage"
        assert HookPoint.AFTER_STAGE == "after_stage"
        assert HookPoint.BEFORE_REPORT == "before_report"
        assert HookPoint.AFTER_REPORT == "after_report"
        assert HookPoint.BEFORE_FINDING == "before_finding"
        assert HookPoint.AFTER_FINDING == "after_finding"
        assert HookPoint.BEFORE_CORRELATION == "before_correlation"
        assert HookPoint.AFTER_CORRELATION == "after_correlation"
        assert HookPoint.BEFORE_EXPLOITABILITY == "before_exploitability"
        assert HookPoint.AFTER_EXPLOITABILITY == "after_exploitability"
        assert HookPoint.BEFORE_VULNERABILITY_LOOKUP == "before_vulnerability_lookup"
        assert HookPoint.AFTER_VULNERABILITY_LOOKUP == "after_vulnerability_lookup"

    def test_is_valid_hook_point(self):
        assert is_valid_hook_point("before_pipeline") is True
        assert is_valid_hook_point("invalid_hook") is False

    def test_get_all_hook_points(self):
        points = get_all_hook_points()
        assert "before_pipeline" in points
        assert "after_report" in points
        assert len(points) == 14

    def test_hook_event_creation(self):
        event = HookEvent(hook_point="test", data={"key": "val"})
        assert event.hook_point == "test"
        assert event.data["key"] == "val"
        assert event.cancelled is False
        assert event.results == []
        assert event.errors == []


# =========================================================================
#  PluginRegistry
# =========================================================================


class _TestPlugin(Plugin):
    metadata = PluginMetadata(id="test_p", name="Test Plugin", version="1.0.0")


class _PluginWithHooks(Plugin):
    metadata = PluginMetadata(id="hooks_p", name="Hooks Plugin", version="1.0.0")

    def register_hooks(self):
        return {
            HookPoint.BEFORE_PIPELINE: [self._handler],
        }

    @staticmethod
    def _handler(event):
        event.data["called"] = True
        return "ok"


class _FailingHookPlugin(Plugin):
    metadata = PluginMetadata(id="fail_p", name="Fail Plugin", version="1.0.0")

    def register_hooks(self):
        return {
            HookPoint.BEFORE_PIPELINE: [self._fail_handler],
        }

    @staticmethod
    def _fail_handler(_event):
        raise RuntimeError("handler failed")


class _EnrichmentPlugin(Plugin):
    metadata = PluginMetadata(id="enrich_p", name="Enrich Plugin", version="1.0.0")

    def register_enrichment_rules(self):
        from vina.core.knowledge import KnowledgeRule

        return [
            KnowledgeRule(
                rule_id="PLUGIN-001",
                title_patterns=["plugin test"],
                explanation="x",
                security_impact="y",
                remediation="z",
            )
        ]


class _ScannerPlugin(Plugin):
    metadata = PluginMetadata(id="scan_p", name="Scan Plugin", version="1.0.0")

    def register_scanners(self):
        class CustomScanner:
            pass

        return [CustomScanner]


class _ReportSectionPlugin(Plugin):
    metadata = PluginMetadata(id="rpt_p", name="Report Plugin", version="1.0.0")

    def register_report_sections(self):
        return [{"name": "custom", "title": "Custom Section"}]


class _CorrelationPlugin(Plugin):
    metadata = PluginMetadata(id="corr_p", name="Corr Plugin", version="1.0.0")

    def register_correlation_rules(self):
        from vina.core.correlation import CorrelationRule, FindingMatcher

        return [
            CorrelationRule(
                rule_id="PLUGIN-CORR-001",
                title="Plugin rule",
                description="d",
                attack_type="privilege_escalation",
                severity="high",
                required_findings=[FindingMatcher(title_contains="test")],
            )
        ]


class TestPluginRegistry:
    def setup_method(self):
        reset_registry()

    def test_singleton(self):
        r1 = get_registry()
        r2 = get_registry()
        assert r1 is r2

    def test_register_and_list(self):
        registry = get_registry()
        p = _TestPlugin()
        registry.register(p)
        assert registry.count() == 1
        plugins = registry.list_plugins()
        assert len(plugins) == 1
        assert plugins[0].metadata.id == "test_p"

    def test_register_duplicate_overwrites(self):
        registry = get_registry()
        p1 = _TestPlugin()
        p2 = _TestPlugin()
        registry.register(p1)
        registry.register(p2)
        assert registry.count() == 1

    def test_get_returns_plugin(self):
        registry = get_registry()
        p = _TestPlugin()
        registry.register(p)
        assert registry.get("test_p") is p
        assert registry.get("nonexistent") is None

    def test_get_enabled(self):
        registry = get_registry()
        p = _TestPlugin()
        registry.register(p)
        assert registry.get_enabled("test_p") is p
        registry.disable("test_p")
        assert registry.get_enabled("test_p") is None

    def test_unregister(self):
        registry = get_registry()
        p = _TestPlugin()
        registry.register(p)
        registry.unregister("test_p")
        assert registry.count() == 0
        assert registry.get("test_p") is None

    def test_enable_disable(self):
        registry = get_registry()
        p = _TestPlugin()
        registry.register(p)
        assert registry.is_enabled("test_p") is True
        registry.disable("test_p")
        assert registry.is_enabled("test_p") is False
        assert p.enabled is False
        registry.enable("test_p")
        assert registry.is_enabled("test_p") is True
        assert p.enabled is True

    def test_enable_nonexistent_raises(self):
        registry = get_registry()
        with pytest.raises(PluginNotFoundError):
            registry.enable("nonexistent")

    def test_is_enabled_nonexistent_raises(self):
        registry = get_registry()
        with pytest.raises(PluginNotFoundError):
            registry.is_enabled("nonexistent")

    def test_get_enrichment_rules(self):
        registry = get_registry()
        p = _EnrichmentPlugin()
        registry.register(p)
        rules = registry.get_enrichment_rules()
        assert len(rules) == 1
        assert rules[0].rule_id == "PLUGIN-001"

    def test_get_scanners(self):
        registry = get_registry()
        p = _ScannerPlugin()
        registry.register(p)
        scanners = registry.get_scanners()
        assert len(scanners) == 1
        assert "CustomScanner" in scanners

    def test_get_report_sections(self):
        registry = get_registry()
        p = _ReportSectionPlugin()
        registry.register(p)
        sections = registry.get_report_sections()
        assert len(sections) == 1

    def test_get_correlation_rules(self):
        registry = get_registry()
        p = _CorrelationPlugin()
        registry.register(p)
        rules = registry.get_correlation_rules()
        assert len(rules) == 1
        assert rules[0].rule_id == "PLUGIN-CORR-001"

    # -- Hook tests --

    def test_add_hook(self):
        registry = get_registry()
        handler = MagicMock()
        registry.add_hook("before_pipeline", handler, plugin_id="test")
        assert len(registry._hooks["before_pipeline"]) == 1

    def test_add_hook_invalid_point_warns(self):
        registry = get_registry()
        handler = MagicMock()
        registry.add_hook("invalid_point", handler)
        assert len(registry._hooks.get("invalid_point", [])) == 1

    def test_run_hook_executes_handlers(self):
        registry = get_registry()
        results = []

        def handler(_event):
            results.append("called")
            return "ok"

        registry.add_hook("before_pipeline", handler, plugin_id="test")
        event = registry.run_hook("before_pipeline", key="val")
        assert len(results) == 1
        assert event.data["key"] == "val"
        assert event.results == ["ok"]

    def test_run_hook_with_disabled_plugin_skips(self):
        registry = get_registry()
        p = _PluginWithHooks()
        registry.register(p)
        registry.disable("hooks_p")
        event = registry.run_hook("before_pipeline")
        assert event.data.get("called") is None

    def test_run_hook_continues_on_error(self):
        registry = get_registry()
        p = _FailingHookPlugin()
        registry.register(p)
        event = registry.run_hook("before_pipeline")
        assert len(event.errors) == 1
        assert "fail_p" in event.errors[0][0]

    def test_run_hook_respects_priority(self):
        registry = get_registry()
        order = []

        def handler1(_event):
            order.append(1)

        def handler2(_event):
            order.append(2)

        registry.add_hook("before_pipeline", handler2, priority=10, plugin_id="p2")
        registry.add_hook("before_pipeline", handler1, priority=0, plugin_id="p1")
        registry.run_hook("before_pipeline")
        assert order == [1, 2]

    def test_run_hook_cancelled_stops(self):
        registry = get_registry()
        calls = []

        def handler1(event):
            calls.append(1)
            event.cancelled = True

        def handler2(_event):
            calls.append(2)

        registry.add_hook("before_pipeline", handler1, plugin_id="p1")
        registry.add_hook("before_pipeline", handler2, plugin_id="p2")
        registry.run_hook("before_pipeline")
        assert calls == [1]

    def test_remove_hooks(self):
        registry = get_registry()
        registry.add_hook("before_pipeline", MagicMock(), plugin_id="test")
        registry.remove_hooks("before_pipeline")
        assert "before_pipeline" not in registry._hooks

    def test_auto_collect_hooks_from_plugin(self):
        registry = get_registry()
        p = _PluginWithHooks()
        registry.register(p)
        assert "before_pipeline" in registry._hooks
        event = registry.run_hook("before_pipeline")
        assert event.data.get("called") is True

    def test_unregister_removes_hooks(self):
        registry = get_registry()
        p = _PluginWithHooks()
        registry.register(p)
        registry.unregister("hooks_p")
        assert "hooks_p" not in {r.plugin_id for r in registry._hooks.get("before_pipeline", [])}

    def test_list_enabled(self):
        registry = get_registry()
        p1 = _TestPlugin()
        p2 = _PluginWithHooks()
        registry.register(p1)
        registry.register(p2)
        registry.disable("hooks_p")
        enabled = registry.list_enabled()
        assert len(enabled) == 1
        assert enabled[0].metadata.id == "test_p"


# =========================================================================
#  PluginLoader
# =========================================================================


class TestPluginLoader:
    def test_load_class(self):
        loader = PluginLoader()
        p = loader.load_class(_TestPlugin)
        assert p.metadata.id == "test_p"

    def test_load_class_non_plugin_raises(self):
        loader = PluginLoader()
        with pytest.raises(PluginLoadError):
            loader.load_class(int)

    @patch("vina.plugins.loader.importlib.import_module")
    def test_load_module(self, mock_import):
        mock_mod = MagicMock()
        mock_mod.TestPlugin = _TestPlugin
        mock_import.return_value = mock_mod
        loader = PluginLoader()
        p = loader.load_module("some.module")
        assert p is not None
        assert p.metadata.id == "test_p"

    @patch("vina.plugins.loader.importlib.import_module")
    def test_load_module_no_plugin_class(self, mock_import):
        mock_mod = MagicMock(spec=[])
        mock_import.return_value = mock_mod
        loader = PluginLoader()
        p = loader.load_module("empty.module")
        assert p is None

    @patch("vina.plugins.loader.importlib.import_module")
    def test_load_module_import_error(self, mock_import):
        mock_import.side_effect = ImportError("no module")
        loader = PluginLoader()
        with pytest.raises(PluginLoadError):
            loader.load_module("bad.module")

    def test_discover_all_returns_empty_when_no_sources(self):
        loader = PluginLoader()
        plugins = loader.discover_all()
        assert isinstance(plugins, list)

    @patch("vina.plugins.loader.importlib.metadata.entry_points")
    def test_load_entry_points(self, mock_eps):
        mock_ep = MagicMock()
        mock_ep.name = "test_plugin"
        mock_ep.module = "test_mod"
        mock_ep.load.return_value = _TestPlugin
        mock_eps.return_value = [mock_ep]
        loader = PluginLoader()
        plugins = loader.load_entry_points()
        assert len(plugins) == 1
        assert plugins[0].metadata.id == "test_p"

    @patch("vina.plugins.loader.importlib.metadata.entry_points")
    def test_load_entry_points_skips_invalid(self, mock_eps):
        mock_ep = MagicMock()
        mock_ep.name = "bad"
        mock_ep.load.side_effect = Exception("bad")
        mock_eps.return_value = [mock_ep]
        loader = PluginLoader()
        plugins = loader.load_entry_points()
        assert len(plugins) == 0

    def test_load_builtin_no_directory(self):
        loader = PluginLoader()
        plugins = loader.load_builtin()
        assert plugins == []

    def test_load_local_no_directories(self):
        loader = PluginLoader()
        plugins = loader.load_local()
        assert isinstance(plugins, list)


# =========================================================================
#  Example plugins
# =========================================================================


class TestExamplePlugins:
    def test_example_scanner_can_instantiate(self):
        from plugins.example_scanner.plugin import ExampleScannerPlugin

        p = ExampleScannerPlugin()
        assert p.metadata.id == "example_scanner"
        assert p.metadata.categories == ["scanner", "example"]

    def test_example_scanner_registers_scanner(self):
        from plugins.example_scanner.plugin import ExampleScannerPlugin

        p = ExampleScannerPlugin()
        scanners = p.register_scanners()
        assert scanners is not None
        assert len(scanners) == 1

    def test_example_scanner_registers_hooks(self):
        from plugins.example_scanner.plugin import ExampleScannerPlugin

        p = ExampleScannerPlugin()
        hooks = p.register_hooks()
        assert hooks is not None
        assert HookPoint.BEFORE_PIPELINE in hooks
        assert HookPoint.AFTER_PIPELINE in hooks

    def test_example_scanner_hook_handlers(self):
        from plugins.example_scanner.plugin import ExampleScannerPlugin
        from vina.plugins.hooks import HookEvent

        p = ExampleScannerPlugin()
        hooks = p.register_hooks()
        event = HookEvent(hook_point=HookPoint.BEFORE_PIPELINE, data={})
        hooks[HookPoint.BEFORE_PIPELINE][0](event)
        assert event.data["greetings"] == ["from example_scanner"]

    def test_example_report_can_instantiate(self):
        from plugins.example_report.plugin import ExampleReportPlugin

        p = ExampleReportPlugin()
        assert p.metadata.id == "example_report"
        assert p.metadata.categories == ["report", "example"]

    def test_example_report_registers_section(self):
        from plugins.example_report.plugin import ExampleReportPlugin

        p = ExampleReportPlugin()
        sections = p.register_report_sections()
        assert sections is not None
        assert sections[0].name == "example_report"

    def test_example_report_registers_hooks(self):
        from plugins.example_report.plugin import ExampleReportPlugin

        p = ExampleReportPlugin()
        hooks = p.register_hooks()
        assert hooks is not None
        assert HookPoint.BEFORE_REPORT in hooks
        assert HookPoint.AFTER_REPORT in hooks

    def test_example_enrichment_can_instantiate(self):
        from plugins.example_enrichment.plugin import ExampleEnrichmentPlugin

        p = ExampleEnrichmentPlugin()
        assert p.metadata.id == "example_enrichment"
        assert p.metadata.categories == ["enrichment", "example"]

    def test_example_enrichment_registers_rules(self):
        from plugins.example_enrichment.plugin import ExampleEnrichmentPlugin

        p = ExampleEnrichmentPlugin()
        rules = p.register_enrichment_rules()
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].rule_id == "EXAMPLE-001"

    def test_example_enrichment_registers_hooks(self):
        from plugins.example_enrichment.plugin import ExampleEnrichmentPlugin

        p = ExampleEnrichmentPlugin()
        hooks = p.register_hooks()
        assert hooks is not None
        assert HookPoint.BEFORE_FINDING in hooks
        assert HookPoint.AFTER_FINDING in hooks

    def test_example_enrichment_hook_tags_finding(self):
        from plugins.example_enrichment.plugin import ExampleEnrichmentPlugin
        from vina.models.findings import Finding
        from vina.plugins.hooks import HookEvent

        p = ExampleEnrichmentPlugin()
        hooks = p.register_hooks()
        finding = Finding(title="example finding title")
        event = HookEvent(hook_point=HookPoint.BEFORE_FINDING, data={"findings": [finding]})
        hooks[HookPoint.BEFORE_FINDING][0](event)
        assert "plugin_tagged" in finding.tags


# =========================================================================
#  SDK exports
# =========================================================================


class TestSDKExports:
    def test_sdk_has_plugin(self):
        from vina.plugins.sdk import Plugin

        assert Plugin is not None

    def test_sdk_has_plugin_metadata(self):
        from vina.plugins.sdk import PluginMetadata

        assert PluginMetadata is not None

    def test_sdk_has_hook_point(self):
        from vina.plugins.sdk import HookPoint

        assert HookPoint is not None

    def test_sdk_has_finding(self):
        assert Finding is not None

    def test_sdk_has_make_finding(self):
        assert make_finding is not None

    def test_package_exports(self):
        import vina.plugins

        assert hasattr(vina.plugins, "Plugin")
        assert hasattr(vina.plugins, "PluginMetadata")
        assert hasattr(vina.plugins, "PluginContext")
        assert hasattr(vina.plugins, "PluginLoader")
        assert hasattr(vina.plugins, "PluginRegistry")
        assert hasattr(vina.plugins, "get_registry")
        assert hasattr(vina.plugins, "HookPoint")
        assert hasattr(vina.plugins, "HookEvent")


# =========================================================================
#  Exceptions
# =========================================================================


class TestExceptions:
    def test_exception_hierarchy(self):
        assert issubclass(PluginLoadError, PluginError)
        assert issubclass(PluginNotFoundError, PluginError)
        assert issubclass(PluginDependencyError, PluginError)
        assert issubclass(PluginDisabledError, PluginError)
        assert issubclass(PluginHookError, PluginError)
        assert issubclass(PluginVersionError, PluginError)

    def test_exception_message(self):
        exc = PluginNotFoundError("test plugin")
        assert "test plugin" in str(exc)


# =========================================================================
#  Version compatibility check
# =========================================================================


class TestVersionCompatibility:
    def test_load_class_version_match(self):
        class CompatPlugin(Plugin):
            metadata = PluginMetadata(id="compat", name="Compat", version="1.0.0", minimum_vina_version="0.1.0")

        loader = PluginLoader()
        p = loader.load_class(CompatPlugin)
        assert p.metadata.id == "compat"
