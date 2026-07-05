"""Benchmark profiles, expected-vs-actual comparison, and benchmark runner.

Defines :class:`BenchmarkProfile` for known vulnerable environments and
:class:`BenchmarkRunner` that executes profiles and compares results
against expected outcomes.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .datasets import MOCK_CVES
from .fixtures import MockFindingFactory
from .metrics import BenchmarkMetrics, compare_cves, compute_metrics
from .runner import TestPipelineRunner, TestResult

logger = logging.getLogger("vina.testing.benchmark")


@dataclass(slots=True)
class BenchmarkProfile:
    """Defines a benchmark scenario with expected outcomes."""

    name: str
    description: str = ""
    target: str = "localhost"
    pipeline: str = "os"  # "os" or "web"

    # Expected outcomes
    expected_findings: list[dict[str, str]] = field(default_factory=list)
    expected_cves: list[str] = field(default_factory=list)
    expected_attack_paths: list[dict[str, str]] = field(default_factory=list)
    expected_exploitability_min_score: float = 0.0
    expected_exploitability_max_score: float = 100.0

    # Constraints
    min_findings: int = 0
    max_runtime_seconds: float = 300.0
    min_precision: float = 0.0
    min_recall: float = 0.0
    min_f1: float = 0.0

    # Mock data for deterministic runs
    mock_findings: list[Any] | None = None
    mock_cves: list[dict[str, Any]] | None = None
    mock_stage_results: list[Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "target": self.target,
            "pipeline": self.pipeline,
            "expected_findings": self.expected_findings,
            "expected_cves": self.expected_cves,
            "expected_attack_paths": self.expected_attack_paths,
            "expected_exploitability_min_score": self.expected_exploitability_min_score,
            "expected_exploitability_max_score": self.expected_exploitability_max_score,
            "min_findings": self.min_findings,
            "max_runtime_seconds": self.max_runtime_seconds,
            "min_precision": self.min_precision,
            "min_recall": self.min_recall,
            "min_f1": self.min_f1,
        }


@dataclass
class BenchmarkResult:
    """Result of executing a :class:`BenchmarkProfile`."""

    profile: BenchmarkProfile
    test_result: TestResult | None = None
    metrics: BenchmarkMetrics | None = None
    cve_comparison: dict[str, Any] | None = None
    attack_path_comparison: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)
    passed: bool = False
    started_at: datetime | None = None
    finished_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.to_dict(),
            "success": self.test_result.success,
            "passed": self.passed,
            "total_findings": len(self.test_result.findings),
            "total_attack_paths": len(self.test_result.attack_paths),
            "total_vuln_matches": len(self.test_result.vuln_matches),
            "errors": self.errors,
            "metrics": self.metrics.to_dict() if self.metrics else {},
            "cve_comparison": self.cve_comparison or {},
            "attack_path_comparison": self.attack_path_comparison or {},
            "started_at": self.started_at.isoformat() if self.started_at else "",
            "finished_at": self.finished_at.isoformat() if self.finished_at else "",
        }

    def to_markdown(self) -> str:
        lines = [
            f"# Benchmark: {self.profile.name}\n",
            f"**Target**: {self.profile.target}  \n",
            f"**Pipeline**: {self.profile.pipeline}  \n",
            f"**Status**: {'✅ PASSED' if self.passed else '❌ FAILED'}  \n",
            f"**Total Findings**: {len(self.test_result.findings)}  \n",
            f"**Total Attack Paths**: {len(self.test_result.attack_paths)}  \n",
            f"**Total CVE Matches**: {len(self.test_result.vuln_matches)}  \n",
        ]
        if self.metrics:
            lines.append("\n" + self.metrics.to_markdown())
        if self.cve_comparison:
            lines.append("\n## CVE Comparison\n")
            lines.append(f"- Matched: {self.cve_comparison.get('matched', [])}")
            lines.append(f"- False Positives: {self.cve_comparison.get('false_positives', [])}")
            lines.append(f"- False Negatives: {self.cve_comparison.get('false_negatives', [])}")
            lines.append(f"- Coverage: {self.cve_comparison.get('coverage', 0.0):.1%}")
        return "\n".join(lines)

    def to_html(self) -> str:
        status = "passed" if self.passed else "failed"
        sections = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'>",
            f"<title>Benchmark: {self.profile.name}</title>",
            "<style>body{font-family:sans-serif;margin:2em}.passed{color:green}.failed{color:red}</style>",
            "</head><body>",
            f"<h1>Benchmark: {self.profile.name}</h1>",
            f"<p class='{status}'><strong>Status: {'PASSED' if self.passed else 'FAILED'}</strong></p>",
            f"<p>Target: {self.profile.target} | Pipeline: {self.profile.pipeline}</p>",
            f"<p>Total Findings: {len(self.test_result.findings)}</p>",
            f"<p>Total Attack Paths: {len(self.test_result.attack_paths)}</p>",
            f"<p>Total CVE Matches: {len(self.test_result.vuln_matches)}</p>",
        ]
        if self.metrics:
            sections.append(self.metrics.to_html())
        if self.cve_comparison:
            sections.append("<h2>CVE Comparison</h2>")
            sections.append(f"<p>Matched: {self.cve_comparison.get('matched', [])}</p>")
            sections.append(f"<p>False Positives: {self.cve_comparison.get('false_positives', [])}</p>")
            sections.append(f"<p>False Negatives: {self.cve_comparison.get('false_negatives', [])}</p>")
            sections.append(f"<p>Coverage: {self.cve_comparison.get('coverage', 0.0):.1%}</p>")
        if self.errors:
            sections.append("<h2>Errors</h2><ul>")
            for err in self.errors:
                sections.append(f"<li>{err}</li>")
            sections.append("</ul>")
        sections.append("</body></html>")
        return "\n".join(sections)

    def save_report(self, output_dir: Path) -> dict[str, Path]:
        """Write benchmark report files."""
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = self.profile.name.replace(" ", "_").replace("/", "_")
        paths: dict[str, Path] = {}

        json_path = output_dir / f"{safe_name}_benchmark.json"
        json_path.write_text(json.dumps(self.to_dict(), indent=2, default=str))
        paths["json"] = json_path

        md_path = output_dir / f"{safe_name}_benchmark.md"
        md_path.write_text(self.to_markdown(), encoding="utf-8")
        paths["markdown"] = md_path

        html_path = output_dir / f"{safe_name}_benchmark.html"
        html_path.write_text(self.to_html(), encoding="utf-8")
        paths["html"] = html_path

        return paths


# ---------------------------------------------------------------------------
#  Built-in benchmark profiles
# ---------------------------------------------------------------------------

_BUILTIN_PROFILES: dict[str, BenchmarkProfile] = {}


def _register_builtin_profiles() -> None:
    profiles = [
        BenchmarkProfile(
            name="mock-os-localhost",
            description="Mock OS pipeline scan of localhost with injected findings",
            target="localhost",
            pipeline="os",
            expected_findings=[
                {"title_contains": "SUID", "severity": "medium"},
                {"title_contains": "NOPASSWD", "severity": "high"},
                {"title_contains": "Docker socket", "severity": "critical"},
            ],
            expected_cves=["CVE-2024-0001", "CVE-2024-0002"],
            expected_attack_paths=[{"title_contains": "Passwordless sudo", "severity": "critical"}],
            expected_exploitability_min_score=40.0,
            min_findings=10,
            max_runtime_seconds=30.0,
            min_precision=0.5,
            min_recall=0.5,
            min_f1=0.5,
            mock_findings=(
                MockFindingFactory.passwordless_sudo()
                + MockFindingFactory.suid_findings(3)
                + MockFindingFactory.docker_socket()
                + MockFindingFactory.writable_cron()
                + MockFindingFactory.ssh_keys()
                + MockFindingFactory.exposed_service()
                + MockFindingFactory.vulnerable_package()
            ),
            mock_cves=MOCK_CVES,
        ),
        BenchmarkProfile(
            name="mock-web-localhost",
            description="Mock web pipeline scan",
            target="http://localhost:4280",
            pipeline="web",
            expected_findings=[{"title_contains": "Service", "severity": "info"}],
            min_findings=0,
            max_runtime_seconds=30.0,
            mock_findings=MockFindingFactory.exposed_service(),
        ),
    ]
    for p in profiles:
        _BUILTIN_PROFILES[p.name] = p


_register_builtin_profiles()


def get_benchmark_profiles() -> dict[str, BenchmarkProfile]:
    """Return all registered benchmark profiles (built-in + user-registered)."""
    return dict(_BUILTIN_PROFILES)


def register_benchmark_profile(profile: BenchmarkProfile) -> None:
    """Register a custom benchmark profile."""
    _BUILTIN_PROFILES[profile.name] = profile


# ---------------------------------------------------------------------------
#  Benchmark runner
# ---------------------------------------------------------------------------


class BenchmarkRunner:
    """Executes benchmark profiles and compares expected vs actual results."""

    def __init__(self, output_dir: Path | None = None) -> None:
        self.output_dir = (output_dir or Path.cwd() / "benchmark_output").resolve()
        self._runner = TestPipelineRunner(output_dir=self.output_dir)

    def run_profile(self, profile: BenchmarkProfile, _force: bool = False) -> BenchmarkResult:
        """Execute a single benchmark profile.

        If the profile provides ``mock_findings``, the pipeline runs in
        deterministic mode with injected data.
        """
        logger.info("Running benchmark: %s", profile.name)
        started_at = datetime.now(UTC)
        result = BenchmarkResult(profile=profile, started_at=started_at)

        try:
            test_result = self._run_mocked(profile) if profile.mock_findings else self._run_live(profile)

            result.test_result = test_result

            # Compute metrics
            expected_titles = [f["title_contains"] for f in profile.expected_findings]
            actual_titles = test_result.finding_titles
            result.metrics = compute_metrics(expected_titles, actual_titles)
            result.metrics.max_runtime_seconds = profile.max_runtime_seconds
            result.metrics.runtime_seconds = test_result.total_duration
            result.metrics.runtime_within_budget = test_result.total_duration <= profile.max_runtime_seconds

            if test_result.metrics:
                mc = test_result.metrics
                result.metrics.peak_memory_mb = mc.peak_memory_mb
                result.metrics.avg_cpu_percent = mc.avg_cpu_percent
                result.metrics.stage_timing = mc.get_all_timing()

            # Compute CVE comparison
            if profile.expected_cves:
                result.cve_comparison = compare_cves(profile.expected_cves, test_result.cve_list)
                result.metrics.cve_coverage = result.cve_comparison.get("coverage", 0.0)

            # Compute attack path comparison
            if profile.expected_attack_paths:
                expected_ap = [ap["title_contains"] for ap in profile.expected_attack_paths]
                actual_ap = test_result.attack_path_titles
                ap_result = compute_metrics(expected_ap, actual_ap)
                result.metrics.attack_path_coverage = ap_result.recall
                result.attack_path_comparison = {
                    "matched": ap_result.true_positives,
                    "false_positives": ap_result.false_positives,
                    "false_negatives": ap_result.false_negatives,
                    "coverage": ap_result.recall,
                }

            # Determine pass/fail
            result.passed = self._evaluate(profile, test_result, result.metrics)

        except Exception as exc:
            logger.exception("Benchmark '%s' failed", profile.name)
            result.errors.append(str(exc))
            result.passed = False

        result.finished_at = datetime.now(UTC)
        return result

    def _run_mocked(self, profile: BenchmarkProfile) -> TestResult:
        """Run in deterministic mode with injected mock findings."""
        findings = list(profile.mock_findings or [])
        test_result = self._runner.run_os_pipeline(
            target=profile.target,
            inject_findings=findings,
            enable_vuln_intel=True,
            enable_enrichment=True,
            enable_correlation=True,
            enable_exploitability=True,
            enable_reports=True,
        )
        return test_result

    def _run_live(self, profile: BenchmarkProfile) -> TestResult:
        """Run against a live target."""
        if profile.pipeline == "web":
            return self._runner.run_web_pipeline(target=profile.target)
        return self._runner.run_os_pipeline(target=profile.target)

    @staticmethod
    def _evaluate(profile: BenchmarkProfile, test_result: TestResult, metrics: BenchmarkMetrics) -> bool:
        """Check if the benchmark result meets all pass criteria."""
        checks = []

        # Minimum findings
        if profile.min_findings > 0:
            checks.append(len(test_result.findings) >= profile.min_findings)

        # Runtime budget
        if profile.max_runtime_seconds > 0:
            checks.append(test_result.total_duration <= profile.max_runtime_seconds)

        # Precision / recall / F1
        if profile.min_precision > 0:
            checks.append(metrics.precision >= profile.min_precision)
        if profile.min_recall > 0:
            checks.append(metrics.recall >= profile.min_recall)
        if profile.min_f1 > 0:
            checks.append(metrics.f1_score >= profile.min_f1)

        return all(checks) if checks else True


__all__ = [
    "BenchmarkProfile",
    "BenchmarkResult",
    "BenchmarkRunner",
    "get_benchmark_profiles",
    "register_benchmark_profile",
]
