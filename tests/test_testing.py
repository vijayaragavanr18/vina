"""Unit and integration tests for the VINA Testing & Benchmarking Framework."""

from __future__ import annotations

from pathlib import Path

from vina.models.findings import Severity
from vina.models.stages import StageState
from vina.testing.benchmark import BenchmarkProfile, BenchmarkRunner, get_benchmark_profiles, register_benchmark_profile
from vina.testing.datasets import (
    DVWA_SCENARIO,
    JUICE_SHOP_SCENARIO,
    METASPLOITABLE_OS_SCENARIO,
    MOCK_CISA_KEV_RESPONSE,
    MOCK_CVES,
    MOCK_EPSS_CSV,
    MOCK_GITHUB_ADVISORY_RESPONSE,
    MOCK_NVD_RESPONSE,
    MOCK_OSV_RESPONSE,
)
from vina.testing.fixtures import MockCommandRunner, MockFindingFactory, make_mock_finding, make_mock_stage_result
from vina.testing.integration import IntegrationTestResult, IntegrationTestSuite, run_integration_suite
from vina.testing.metrics import BenchmarkMetrics, MetricsCollector, compare_cves, compute_metrics
from vina.testing.runner import TestPipelineRunner, TestResult
from vina.testing.sandbox import TestSandbox

# =========================================================================
#  Fixtures
# =========================================================================


class TestMakeMockFinding:
    def test_default_values(self):
        f = make_mock_finding()
        assert f.title == "Mock Finding"
        assert f.severity == Severity.INFO
        assert f.target == "localhost"

    def test_custom_values(self):
        f = make_mock_finding(title="Custom", severity="critical", target="10.0.0.1", port=443)
        assert f.title == "Custom"
        assert f.severity == "critical"
        assert f.port == 443

    def test_uses_make_finding(self):
        f = make_mock_finding(title="Test Finding")
        assert f.timestamp  # Make sure timestamp is set


class TestMakeMockStageResult:
    def test_default_values(self):
        sr = make_mock_stage_result()
        assert sr.name == "mock_stage"
        assert sr.status == StageState.SUCCESS
        assert sr.record_count == 0

    def test_failed_stage(self):
        sr = make_mock_stage_result(name="scan", status=StageState.FAILED, record_count=0, duration=10.0)
        assert sr.name == "scan"
        assert sr.status == StageState.FAILED
        assert sr.duration == 10.0

    def test_with_warnings(self):
        sr = make_mock_stage_result(warnings=["warning 1"])
        assert sr.warnings == ["warning 1"]


class TestMockCommandRunner:
    def test_run_default(self):
        runner = MockCommandRunner()
        import asyncio

        result = asyncio.run(runner.run("test", ("--flag",)))
        assert result.returncode == 0

    def test_set_result(self):
        runner = MockCommandRunner()
        runner.set_result("mycmd", {"custom": "result"})
        import asyncio

        result = asyncio.run(runner.run("mycmd"))
        assert result == {"custom": "result"}

    def test_tracks_commands(self):
        runner = MockCommandRunner()
        import asyncio

        asyncio.run(runner.run("cmd1"))
        asyncio.run(runner.run("cmd2"))
        assert len(runner.executed_commands) == 2
        assert runner.executed_commands[0] == ("cmd1", ())


class TestMockFindingFactory:
    def test_suid_findings(self):
        findings = MockFindingFactory.suid_findings(3)
        assert len(findings) == 3
        assert all("SUID" in f.title for f in findings)

    def test_passwordless_sudo(self):
        findings = MockFindingFactory.passwordless_sudo()
        assert len(findings) == 1
        assert "NOPASSWD" in findings[0].title

    def test_docker_socket(self):
        findings = MockFindingFactory.docker_socket()
        assert len(findings) == 1
        assert "Docker socket" in findings[0].title

    def test_writable_cron(self):
        findings = MockFindingFactory.writable_cron()
        assert len(findings) == 1
        assert "Writable" in findings[0].title

    def test_ssh_keys(self):
        findings = MockFindingFactory.ssh_keys()
        assert len(findings) == 1
        assert "SSH private key" in findings[0].title

    def test_vulnerable_package(self):
        findings = MockFindingFactory.vulnerable_package(package="openssl", version="1.1.1")
        assert len(findings) == 1
        assert "openssl:1.1.1" in findings[0].title

    def test_exposed_service(self):
        findings = MockFindingFactory.exposed_service()
        assert len(findings) == 2


# =========================================================================
#  Datasets
# =========================================================================


class TestMockCves:
    def test_has_expected_entries(self):
        assert len(MOCK_CVES) == 10
        cves = [c["cve"] for c in MOCK_CVES]
        assert "CVE-2024-0001" in cves
        assert "CVE-2024-0010" in cves

    def test_cve_with_kev(self):
        kev_cves = [c for c in MOCK_CVES if c.get("kev")]
        assert len(kev_cves) >= 1
        assert kev_cves[0]["cve"] == "CVE-2024-0001"


class TestMockFeedResponses:
    def test_nvd_response(self):
        assert MOCK_NVD_RESPONSE["totalResults"] == 2
        assert len(MOCK_NVD_RESPONSE["vulnerabilities"]) == 2

    def test_cisa_kev_response(self):
        assert MOCK_CISA_KEV_RESPONSE["vulnerabilities"][0]["cveID"] == "CVE-2024-0001"

    def test_epss_csv(self):
        assert "model_version" in MOCK_EPSS_CSV

    def test_osv_response(self):
        assert MOCK_OSV_RESPONSE["vulns"][0]["id"] == "CVE-2024-0001"

    def test_github_advisory_response(self):
        assert len(MOCK_GITHUB_ADVISORY_RESPONSE) == 1
        assert MOCK_GITHUB_ADVISORY_RESPONSE[0]["ghsa_id"] == "GHSA-xxxx-xxxx-xxxx"


class TestScenarios:
    def test_dvwa(self):
        assert DVWA_SCENARIO["pipeline"] == "web"
        assert len(DVWA_SCENARIO["expected_findings"]) == 3

    def test_juice_shop(self):
        assert JUICE_SHOP_SCENARIO["pipeline"] == "web"
        assert JUICE_SHOP_SCENARIO["min_findings"] == 20

    def test_metasploitable_os(self):
        assert METASPLOITABLE_OS_SCENARIO["pipeline"] == "os"
        assert len(METASPLOITABLE_OS_SCENARIO["expected_findings"]) == 3
        assert "CVE-2024-0002" in METASPLOITABLE_OS_SCENARIO["expected_cves"]


# =========================================================================
#  Metrics
# =========================================================================


class TestComputeMetrics:
    def test_perfect_match(self):
        m = compute_metrics(["finding a", "finding b"], ["finding a", "finding b"])
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1_score == 1.0
        assert m.true_positives == 2
        assert m.false_positives == 0
        assert m.false_negatives == 0

    def test_no_match(self):
        m = compute_metrics(["finding a"], ["something else"])
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1_score == 0.0

    def test_partial_match(self):
        m = compute_metrics(["SUID binary", "NOPASSWD sudo"], ["SUID binary: /usr/bin/test"])
        assert m.true_positives == 1
        assert m.false_negatives == 1
        assert m.false_positives == 0
        assert m.precision == 1.0
        assert m.recall == 0.5

    def test_false_positives(self):
        m = compute_metrics(["expected"], ["expected", "unexpected"])
        assert m.true_positives == 1
        assert m.false_positives == 1
        assert m.false_negatives == 0

    def test_empty_expected(self):
        m = compute_metrics([], ["something"])
        assert m.true_positives == 0
        # recall = 0.0 because TP=0, FN=0, so 0/(0+0) = 0
        assert m.recall == 0.0
        assert m.false_positives == 1

    def test_empty_actual(self):
        m = compute_metrics(["expected"], [])
        assert m.true_positives == 0
        assert m.recall == 0.0
        assert m.false_negatives == 1


class TestCompareCves:
    def test_perfect_match(self):
        result = compare_cves(["CVE-2024-0001"], ["CVE-2024-0001"])
        assert result["coverage"] == 1.0
        assert result["matched"] == ["CVE-2024-0001"]

    def test_partial_match(self):
        result = compare_cves(["CVE-2024-0001", "CVE-2024-0002"], ["CVE-2024-0001"])
        assert result["coverage"] == 0.5
        assert result["false_negatives"] == ["CVE-2024-0002"]

    def test_no_match(self):
        result = compare_cves(["CVE-2024-0001"], ["CVE-2024-9999"])
        assert result["coverage"] == 0.0
        assert result["false_positives"] == ["CVE-2024-9999"]
        assert result["false_negatives"] == ["CVE-2024-0001"]


class TestMetricsCollector:
    def test_start_stop(self):
        mc = MetricsCollector()
        mc.start_run()
        import time

        time.sleep(0.01)
        elapsed = mc.end_run()
        assert elapsed > 0.0

    def test_timers(self):
        mc = MetricsCollector()
        mc.start_timer("test")
        import time

        time.sleep(0.01)
        mc.stop_timer("test")
        assert mc.get_timing("test") > 0.0

    def test_peak_memory_default(self):
        mc = MetricsCollector()
        assert mc.peak_memory_mb == 0.0

    def test_get_all_timing(self):
        mc = MetricsCollector()
        mc.start_timer("a")
        mc.stop_timer("a")
        mc.start_timer("b")
        mc.stop_timer("b")
        timing = mc.get_all_timing()
        assert "a" in timing
        assert "b" in timing


class TestBenchmarkMetrics:
    def test_default_values(self):
        m = BenchmarkMetrics()
        assert m.true_positives == 0
        assert m.runtime_within_budget is True

    def test_to_dict(self):
        m = BenchmarkMetrics(
            true_positives=5, false_positives=1, false_negatives=2, precision=0.833, recall=0.714, f1_score=0.769
        )
        d = m.to_dict()
        assert d["true_positives"] == 5
        assert d["precision"] == 0.833

    def test_to_markdown(self):
        m = BenchmarkMetrics(precision=0.9, recall=0.8, f1_score=0.85)
        md = m.to_markdown()
        assert "Precision" in md
        assert "90.0%" in md

    def test_to_html(self):
        m = BenchmarkMetrics(precision=0.9, recall=0.8, f1_score=0.85)
        html = m.to_html()
        assert "90.0%" in html


# =========================================================================
#  Benchmark profiles
# =========================================================================


class TestBenchmarkProfile:
    def test_default_values(self):
        p = BenchmarkProfile(name="test")
        assert p.pipeline == "os"
        assert p.target == "localhost"
        assert p.max_runtime_seconds == 300.0

    def test_to_dict(self):
        p = BenchmarkProfile(name="test", description="desc", expected_findings=[{"title_contains": "x"}])
        d = p.to_dict()
        assert d["name"] == "test"
        assert len(d["expected_findings"]) == 1


class TestGetBenchmarkProfiles:
    def test_has_builtin(self):
        profiles = get_benchmark_profiles()
        assert "mock-os-localhost" in profiles
        assert "mock-web-localhost" in profiles

    def test_register_custom(self):
        p = BenchmarkProfile(name="custom-test", description="custom")
        register_benchmark_profile(p)
        profiles = get_benchmark_profiles()
        assert "custom-test" in profiles

    def test_builtin_profile_config(self):
        profiles = get_benchmark_profiles()
        os_profile = profiles["mock-os-localhost"]
        assert os_profile.min_findings == 10
        assert len(os_profile.mock_findings) >= 10
        assert len(os_profile.expected_findings) == 3
        assert len(os_profile.expected_cves) == 2


# =========================================================================
#  Benchmark runner
# =========================================================================


class TestBenchmarkRunner:
    def test_run_mocked_profile(self):
        profiles = get_benchmark_profiles()
        profile = profiles["mock-os-localhost"]
        runner = BenchmarkRunner(output_dir=Path("/tmp/vina-bench-test"))
        result = runner.run_profile(profile)
        assert result.test_result is not None
        assert result.test_result.success is True
        assert result.metrics is not None
        # Should have at least the injected findings
        assert len(result.test_result.findings) >= len(profile.mock_findings)
        # Should have matched something
        assert result.metrics.total_actual >= result.metrics.total_matched

    def test_run_profile_stores_result(self):
        profile = BenchmarkProfile(
            name="quick-test",
            target="localhost",
            pipeline="os",
            min_findings=0,
            max_runtime_seconds=10,
            mock_findings=MockFindingFactory.suid_findings(2),
        )
        runner = BenchmarkRunner(output_dir=Path("/tmp/vina-bench-quick"))
        result = runner.run_profile(profile)
        assert result.passed is True
        assert result.metrics.runtime_within_budget is True

    def test_benchmark_result_to_dict(self):
        profile = BenchmarkProfile(name="dict-test", mock_findings=MockFindingFactory.suid_findings(1))
        runner = BenchmarkRunner(output_dir=Path("/tmp/vina-bench-dict"))
        result = runner.run_profile(profile)
        d = result.to_dict()
        assert d["profile"]["name"] == "dict-test"
        assert "metrics" in d

    def test_benchmark_result_save_report(self):
        profile = BenchmarkProfile(name="report-test", mock_findings=MockFindingFactory.suid_findings(1))
        runner = BenchmarkRunner(output_dir=Path("/tmp/vina-bench-report"))
        result = runner.run_profile(profile)
        paths = result.save_report(Path("/tmp/vina-bench-reports"))
        assert "json" in paths
        assert "markdown" in paths
        assert "html" in paths
        for p in paths.values():
            assert p.exists()


# =========================================================================
#  Test result
# =========================================================================


class TestTestResult:
    def test_empty_result(self):
        tr = TestResult()
        assert tr.target == ""
        assert tr.finding_titles == []
        assert tr.cve_list == []
        assert tr.attack_path_titles == []

    def test_finding_titles(self):
        tr = TestResult(findings=[make_mock_finding(title="F1"), make_mock_finding(title="F2")])
        assert tr.finding_titles == ["F1", "F2"]

    def test_stats(self):
        tr = TestResult(findings=[make_mock_finding(title="T1", severity="high")])
        stats = tr.stats
        assert stats["total"] == 1
        assert stats["by_severity"]["high"] == 1


# =========================================================================
#  Integration test suite
# =========================================================================


class TestIntegrationResult:
    def test_defaults(self):
        r = IntegrationTestResult()
        assert r.passed is False
        assert r.assertions == {}
        assert r.errors == []

    def test_to_dict(self):
        r = IntegrationTestResult(name="test1", passed=True, assertions={"a": True})
        d = r.to_dict()
        assert d["name"] == "test1"
        assert d["passed"] is True


class TestIntegrationTestSuite:
    def test_empty_suite(self):
        suite = IntegrationTestSuite()
        assert suite.total == 0
        assert suite.all_passed is True

    def test_with_results(self):
        suite = IntegrationTestSuite()
        suite.results = [
            IntegrationTestResult(name="pass", passed=True),
            IntegrationTestResult(name="fail", passed=False),
        ]
        assert suite.total == 2
        assert suite.passed == 1
        assert suite.failed == 1
        assert suite.all_passed is False

    def test_save_report(self):
        suite = IntegrationTestSuite(name="test")
        suite.results = [IntegrationTestResult(name="t1", passed=True)]
        path = suite.save_report(Path("/tmp/vina-int-test"))
        assert path.exists()
        import json

        data = json.loads(path.read_text())
        assert data["name"] == "test"
        assert data["passed"] == 1


# =========================================================================
#  Test sandbox
# =========================================================================


class TestTestSandbox:
    def test_context_manager(self):
        with TestSandbox() as sandbox:
            assert sandbox.tmpdir is not None
            assert sandbox.tmpdir.exists()
        # After exit, tmpdir should be cleaned up
        assert not sandbox.tmpdir.exists()

    def test_write_config(self):
        with TestSandbox() as sandbox:
            path = sandbox.write_config({"output_dir": "/tmp/test"})
            assert path.exists()
            assert "output_dir" in path.read_text()

    def test_write_json(self):
        with TestSandbox() as sandbox:
            path = sandbox.write_json("data.json", {"key": "val"})
            assert path.exists()
            import json

            assert json.loads(path.read_text()) == {"key": "val"}

    def test_write_text(self):
        with TestSandbox() as sandbox:
            path = sandbox.write_text("test.txt", "hello")
            assert path.read_text() == "hello"

    def test_feed_server(self):
        with TestSandbox() as sandbox:
            port = sandbox.start_mock_feed_server()
            assert port > 0
            sandbox.set_feed_response("/test", 200, b'{"ok": true}', "application/json")
            import urllib.request

            resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/test")
            assert resp.status == 200
            assert resp.read() == b'{"ok": true}'

    def test_feed_server_404(self):
        with TestSandbox() as sandbox:
            port = sandbox.start_mock_feed_server()
            import urllib.request

            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/nonexistent")
            except urllib.error.HTTPError as e:
                assert e.code == 404


# =========================================================================
#  Test pipeline runner (deterministic mode)
# =========================================================================


class TestTestPipelineRunner:
    def test_os_pipeline_with_injected(self):
        runner = TestPipelineRunner(output_dir=Path("/tmp/vina-runner-test"))
        findings = MockFindingFactory.suid_findings(2) + MockFindingFactory.passwordless_sudo()
        result = runner.run_os_pipeline(target="localhost", inject_findings=findings)
        assert result.success is True
        assert len(result.findings) == 3
        assert result.pipeline_type == "os"

    def test_os_pipeline_injected_titles(self):
        runner = TestPipelineRunner(output_dir=Path("/tmp/vina-runner-test2"))
        findings = MockFindingFactory.suid_findings(3)
        result = runner.run_os_pipeline(target="localhost", inject_findings=findings)
        titles = result.finding_titles
        assert len(titles) == 3
        assert "binary0" in titles[0]

    def test_web_pipeline_with_injected(self):
        runner = TestPipelineRunner(output_dir=Path("/tmp/vina-web-test"))
        findings = MockFindingFactory.exposed_service()
        result = runner.run_web_pipeline(target="http://localhost:4280", inject_findings=findings)
        assert result.success is True
        assert result.pipeline_type == "web"

    def test_report_generation(self):
        runner = TestPipelineRunner(output_dir=Path("/tmp/vina-report-test"))
        findings = MockFindingFactory.suid_findings(1)
        reports = runner.run_report_generation(
            findings=findings, stage_results=[make_mock_stage_result(name="test", record_count=1)]
        )
        assert len(reports) == 3  # json, markdown, html
        for fmt, path in reports.items():
            assert path.exists(), f"{fmt} report not found at {path}"

    def test_vulnerability_lookup(self):
        runner = TestPipelineRunner(output_dir=Path("/tmp/vina-vuln-test"))
        findings = MockFindingFactory.vulnerable_package(package="openssl", version="1.1.1")
        matches = runner.run_vulnerability_lookup(findings)
        # May or may not match depending on CVE DB state; shouldn't crash
        assert isinstance(matches, list)

    def test_correlation(self):
        runner = TestPipelineRunner(output_dir=Path("/tmp/vina-corr-test"))
        findings = MockFindingFactory.suid_findings(2)
        paths = runner.run_correlation(findings)
        assert isinstance(paths, list)

    def test_exploitability(self):
        runner = TestPipelineRunner(output_dir=Path("/tmp/vina-exp-test"))
        findings = MockFindingFactory.suid_findings(1) + MockFindingFactory.passwordless_sudo()
        assessments = runner.run_exploitability(findings=findings)
        assert isinstance(assessments, list)


# =========================================================================
#  Integration suite runner (deterministic / no network)
# =========================================================================


class TestRunIntegrationSuite:
    def test_suite_with_deterministic_tests(self):
        """Run integration suite with only deterministic (no-network) tests."""

        class TrackingRunner(TestPipelineRunner):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._findings_to_inject = []

            def set_findings(self, findings):
                self._findings_to_inject = findings

            def run_os_pipeline(self, **kwargs):
                kwargs.pop("inject_findings", None)
                return super().run_os_pipeline(inject_findings=self._findings_to_inject, **kwargs)

        runner = TrackingRunner(output_dir=Path("/tmp/vina-int-suite"))
        runner.set_findings(MockFindingFactory.suid_findings(2) + MockFindingFactory.passwordless_sudo())

        suite = run_integration_suite(
            runner=runner,
            output_dir=Path("/tmp/vina-int-suite"),
            include_os=True,
            include_web=False,
            include_plugins=False,
            include_feeds=False,
            include_reports=True,
            timeout=30,
        )
        assert suite.total >= 1
        # At minimum, report generation should pass
        report_results = [r for r in suite.results if "report" in r.name]
        if report_results:
            assert report_results[0].passed
