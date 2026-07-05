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
    "BenchmarkMetrics",
    "BenchmarkProfile",
    "BenchmarkResult",
    "BenchmarkRunner",
    "IntegrationTestResult",
    "IntegrationTestSuite",
    "MetricsCollector",
    "MockCommandRunner",
    "MockFindingFactory",
    "MockPipelineContext",
    "TestPipelineRunner",
    "TestResult",
    "TestSandbox",
    "compute_metrics",
    "get_benchmark_profiles",
    "make_mock_finding",
    "make_mock_stage_result",
    "run_integration_suite",
]
