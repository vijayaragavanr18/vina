"""VINA Testing & Benchmarking Framework.

Provides repeatable end-to-end testing, benchmark profiles for
vulnerable environments, and performance measurement tools.
"""

from .benchmark import BenchmarkProfile, BenchmarkResult, BenchmarkRunner, get_benchmark_profiles
from .fixtures import (
    MockCommandRunner,
    MockFindingFactory,
    MockPipelineContext,
    make_mock_finding,
    make_mock_stage_result,
)
from .integration import IntegrationTestResult, IntegrationTestSuite, run_integration_suite
from .metrics import BenchmarkMetrics, MetricsCollector, compute_metrics
from .runner import TestPipelineRunner, TestResult
from .sandbox import TestSandbox

__all__ = [
    # Benchmark
    "BenchmarkProfile",
    "BenchmarkResult",
    "BenchmarkRunner",
    "get_benchmark_profiles",
    # Fixtures
    "MockCommandRunner",
    "MockFindingFactory",
    "MockPipelineContext",
    "make_mock_finding",
    "make_mock_stage_result",
    # Integration
    "IntegrationTestResult",
    "IntegrationTestSuite",
    "run_integration_suite",
    # Metrics
    "BenchmarkMetrics",
    "MetricsCollector",
    "compute_metrics",
    # Runner
    "TestPipelineRunner",
    "TestResult",
    # Sandbox
    "TestSandbox",
]
