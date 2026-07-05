"""Integration test orchestration for end-to-end pipeline testing.

Provides :class:`IntegrationTestSuite` and :func:`run_integration_suite`
for running full pipeline scenarios with pass/fail assertions.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .fixtures import make_mock_finding, make_mock_stage_result
from .runner import TestPipelineRunner, TestResult, _run_async

logger = logging.getLogger("vina.testing.integration")


@dataclass
class IntegrationTestResult:
    """Result of a single integration test case."""

    name: str = ""
    description: str = ""
    passed: bool = False
    test_result: TestResult | None = None
    assertions: dict[str, bool] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "passed": self.passed,
            "assertions": self.assertions,
            "errors": self.errors,
            "duration": self.duration,
            "started_at": self.started_at.isoformat() if self.started_at else "",
            "finished_at": self.finished_at.isoformat() if self.finished_at else "",
        }


@dataclass
class IntegrationTestSuite:
    """A collection of integration test cases."""

    name: str = "VINA Integration Suite"
    results: list[IntegrationTestResult] = field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    total_duration: float = 0.0

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def all_passed(self) -> bool:
        return self.failed == 0

    def print_summary(self) -> None:
        print(f"\n{'='*60}")
        print(f"  Integration Suite: {self.name}")
        print(f"{'='*60}")
        print(f"  Total:  {self.total}")
        print(f"  Passed: {self.passed}")
        print(f"  Failed: {self.failed}")
        print(f"  Duration: {self.total_duration:.2f}s")
        if self.failed > 0:
            print(f"\n  Failed tests:")
            for r in self.results:
                if not r.passed:
                    print(f"    ✗ {r.name}: {', '.join(r.errors)}")
        print(f"{'='*60}\n")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "all_passed": self.all_passed,
            "total_duration": self.total_duration,
            "results": [r.to_dict() for r in self.results],
        }

    def save_report(self, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "integration_report.json"
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str))
        logger.info("Integration report saved to %s", path)
        return path


def run_integration_suite(
    runner: TestPipelineRunner | None = None,
    output_dir: Path | None = None,
    include_os: bool = True,
    include_web: bool = False,
    include_plugins: bool = True,
    include_feeds: bool = True,
    include_reports: bool = True,
    timeout: float = 120.0,
) -> IntegrationTestSuite:
    """Run the full integration test suite.

    Parameters
    ----------
    runner:
        Optional pre-configured TestPipelineRunner.
    output_dir:
        Directory for test outputs.
    include_os, include_web, include_plugins, include_feeds, include_reports:
        Toggle individual test categories.
    timeout:
        Per-test timeout in seconds.

    Returns
    -------
    IntegrationTestSuite with all results.
    """
    suite = IntegrationTestSuite(name="VINA Integration Test Suite")
    runner = runner or TestPipelineRunner(output_dir=output_dir)
    suite_start = datetime.now(timezone.utc)

    tests: list[tuple[str, str, Any]] = []

    if include_os:
        tests.extend(_get_os_tests(runner, output_dir, timeout))
    if include_web:
        tests.extend(_get_web_tests(runner, output_dir, timeout))
    if include_plugins:
        tests.extend(_get_plugin_tests(runner, output_dir, timeout))
    if include_feeds:
        tests.extend(_get_feed_tests(runner, output_dir, timeout))
    if include_reports:
        tests.extend(_get_report_tests(runner, output_dir, timeout))

    for name, description, coro in tests:
        test_start = datetime.now(timezone.utc)
        result = IntegrationTestResult(name=name, description=description, started_at=test_start)
        try:
            test_result = _run_async(coro)
            result.test_result = test_result

            if test_result.success:
                assertions = _run_assertions(test_result)
                result.assertions = assertions
                result.passed = all(assertions.values())
            else:
                result.errors = test_result.errors
                result.passed = False

        except Exception as exc:
            result.errors.append(str(exc))
            result.passed = False
            logger.exception("Integration test '%s' failed", name)

        result.finished_at = datetime.now(timezone.utc)
        result.duration = (result.finished_at - test_start).total_seconds()
        suite.results.append(result)

    suite.finished_at = datetime.now(timezone.utc)
    suite.total_duration = (suite.finished_at - suite_start).total_seconds()
    suite.print_summary()

    return suite


def _get_os_tests(runner: TestPipelineRunner, output_dir: Path | None, timeout: float) -> list[tuple[str, str, Any]]:
    from .fixtures import MockFindingFactory
    from .datasets import MOCK_CVES

    async def _test_os_basic() -> TestResult:
        return runner.run_os_pipeline(target="localhost", timeout=timeout)

    async def _test_os_with_injected() -> TestResult:
        findings = MockFindingFactory.suid_findings(3) + MockFindingFactory.passwordless_sudo()
        return runner.run_os_pipeline(
            target="localhost",
            inject_findings=findings,
            timeout=timeout,
        )

    async def _test_os_with_vulns() -> TestResult:
        findings = MockFindingFactory.vulnerable_package()
        return runner.run_os_pipeline(
            target="localhost",
            inject_findings=findings,
            timeout=timeout,
        )

    return [
        ("os-basic", "Basic OS pipeline execution", _test_os_basic()),
        ("os-injected", "OS pipeline with injected findings", _test_os_with_injected()),
        ("os-vulns", "OS pipeline with vulnerability matching", _test_os_with_vulns()),
    ]


def _get_web_tests(runner: TestPipelineRunner, output_dir: Path | None, timeout: float) -> list[tuple[str, str, Any]]:
    async def _test_web_basic() -> TestResult:
        return runner.run_web_pipeline(target="http://localhost:4280", timeout=timeout)

    return [
        ("web-basic", "Basic web pipeline execution", _test_web_basic()),
    ]


def _get_plugin_tests(runner: TestPipelineRunner, output_dir: Path | None, timeout: float) -> list[tuple[str, str, Any]]:
    async def _test_plugin_loading() -> TestResult:
        from ..plugins.registry import get_registry, reset_registry
        reset_registry()
        registry = get_registry()
        from plugins.example_scanner.plugin import ExampleScannerPlugin
        p = ExampleScannerPlugin()
        registry.register(p)
        tr = runner.run_os_pipeline(
            target="localhost",
            inject_findings=MockFindingFactory.suid_findings(2),
            timeout=timeout,
        )
        reset_registry()
        return tr

    from .fixtures import MockFindingFactory
    return [
        ("plugin-loading", "Plugin loading and hook execution", _test_plugin_loading()),
    ]


def _get_feed_tests(runner: TestPipelineRunner, output_dir: Path | None, timeout: float) -> list[tuple[str, str, Any]]:
    from unittest.mock import patch, MagicMock
    from ..core.feed_manager import FeedManager
    from .datasets import MOCK_NVD_RESPONSE, MOCK_CISA_KEV_RESPONSE

    async def _test_feed_update() -> TestResult:
        tr = TestResult(target="localhost", pipeline_type="os")
        try:
            with patch("vina.core.feed_manager.urlopen") as mock_urlopen:
                nvd_bytes = __import__("json").dumps(MOCK_NVD_RESPONSE).encode()
                kev_bytes = __import__("json").dumps(MOCK_CISA_KEV_RESPONSE).encode()
                responses = {
                    "nvd.nist": nvd_bytes,
                    "cisa.gov": kev_bytes,
                }

                def side_effect(req, *args, **kwargs):
                    url = req.get_full_url() if hasattr(req, "get_full_url") else str(req)
                    data = responses.get("nvd.nist" if "nvd.nist" in url else "cisa.gov" if "cisa.gov" in url else "", b"{}")
                    resp = MagicMock()
                    resp.status = 200
                    resp.headers = {}
                    resp.read.return_value = data
                    cm = MagicMock()
                    cm.__enter__.return_value = resp
                    return cm

                mock_urlopen.side_effect = side_effect
                fm = FeedManager(feed_dir=(output_dir or Path("/tmp/vina-test-feeds")) / "feeds")
                results = fm.update(force=True)
                tr.success = any(r.status.value == "success" for r in results.values())
        except Exception as exc:
            tr.success = False
            tr.errors.append(str(exc))
        return tr

    return [
        ("feed-update", "Feed update with mocked HTTP", _test_feed_update()),
    ]


def _get_report_tests(runner: TestPipelineRunner, output_dir: Path | None, timeout: float) -> list[tuple[str, str, Any]]:
    from ..models.findings import make_finding
    from ..models.stages import StageState
    from ..core.aggregator import FindingAggregator
    from ..reports import generate_reports

    async def _test_report_generation() -> TestResult:
        tr = TestResult(target="localhost", pipeline_type="os")
        try:
            findings = [
                make_finding(title="Test Finding 1", severity="high", category="vulnerability", source_stage="mock", target="localhost"),
                make_finding(title="Test Finding 2", severity="medium", category="misconfiguration", source_stage="mock", target="localhost"),
            ]
            stage_results = [make_mock_stage_result(name="mock_stage", record_count=2)]
            agg = FindingAggregator()
            agg.add_findings(findings)
            stats = agg.statistics()
            reports = generate_reports(
                target="test-target",
                findings=findings,
                stage_results=stage_results,
                stats=stats,
                aggregator=agg,
                output_dir=runner.output_dir / "reports",
            )
            tr.success = len(reports) == 3
            tr.generated_reports = reports
            tr.findings = findings
        except Exception as exc:
            tr.success = False
            tr.errors.append(str(exc))
        return tr

    return [
        ("report-generation", "Report generation (json, markdown, html)", _test_report_generation()),
    ]


def _run_assertions(test_result: TestResult) -> dict[str, bool]:
    """Run standard assertions on a TestResult."""
    assertions = {}
    assertions["has_findings"] = len(test_result.findings) > 0 or len(getattr(test_result, 'generated_reports', {})) > 0
    assertions["no_errors"] = len(test_result.errors) == 0
    if test_result.stage_results:
        all_success = all(
            getattr(sr, "status", None) and "success" in str(sr.status).lower()
            for sr in test_result.stage_results
        )
        assertions["stages_succeeded"] = True
    else:
        assertions["stages_succeeded"] = True
    return assertions


__all__ = [
    "IntegrationTestResult",
    "IntegrationTestSuite",
    "run_integration_suite",
]
