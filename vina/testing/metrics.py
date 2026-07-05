"""Metrics collection, precision/recall computation, and performance measurement."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class BenchmarkMetrics:
    """Aggregated metrics for a benchmark run."""

    # Detection quality
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0

    # Derived scores
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    accuracy: float = 0.0

    # Coverage
    finding_coverage: float = 0.0
    cve_coverage: float = 0.0
    attack_path_coverage: float = 0.0
    total_expected: int = 0
    total_actual: int = 0
    total_matched: int = 0

    # Performance
    runtime_seconds: float = 0.0
    max_runtime_seconds: float = 0.0
    runtime_within_budget: bool = True

    # Resource usage (approximate)
    peak_memory_mb: float = 0.0
    avg_cpu_percent: float = 0.0

    # Timing breakdown
    stage_timing: dict[str, float] = field(default_factory=dict)
    enrichment_time: float = 0.0
    correlation_time: float = 0.0
    exploitability_time: float = 0.0
    vuln_lookup_time: float = 0.0
    report_generation_time: float = 0.0
    plugin_overhead_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "accuracy": round(self.accuracy, 4),
            "finding_coverage": round(self.finding_coverage, 4),
            "cve_coverage": round(self.cve_coverage, 4),
            "attack_path_coverage": round(self.attack_path_coverage, 4),
            "total_expected": self.total_expected,
            "total_actual": self.total_actual,
            "total_matched": self.total_matched,
            "runtime_seconds": round(self.runtime_seconds, 2),
            "max_runtime_seconds": self.max_runtime_seconds,
            "runtime_within_budget": self.runtime_within_budget,
            "peak_memory_mb": round(self.peak_memory_mb, 2),
            "avg_cpu_percent": round(self.avg_cpu_percent, 2),
            "stage_timing": self.stage_timing,
            "enrichment_time": round(self.enrichment_time, 3),
            "correlation_time": round(self.correlation_time, 3),
            "exploitability_time": round(self.exploitability_time, 3),
            "vuln_lookup_time": round(self.vuln_lookup_time, 3),
            "report_generation_time": round(self.report_generation_time, 3),
            "plugin_overhead_time": round(self.plugin_overhead_time, 3),
        }

    def to_markdown(self) -> str:
        lines = [
            "## Benchmark Metrics\n",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Precision | {self.precision:.1%} |",
            f"| Recall | {self.recall:.1%} |",
            f"| F1 Score | {self.f1_score:.3f} |",
            f"| Accuracy | {self.accuracy:.1%} |",
            f"| True Positives | {self.true_positives} |",
            f"| False Positives | {self.false_positives} |",
            f"| False Negatives | {self.false_negatives} |",
            f"| Finding Coverage | {self.finding_coverage:.1%} |",
            f"| CVE Coverage | {self.cve_coverage:.1%} |",
            f"| Attack Path Coverage | {self.attack_path_coverage:.1%} |",
            f"| Total Expected | {self.total_expected} |",
            f"| Total Actual | {self.total_actual} |",
            f"| Total Matched | {self.total_matched} |",
            f"| Runtime | {self.runtime_seconds:.1f}s |",
            f"| Runtime Budget | {self.max_runtime_seconds:.1f}s |",
            f"| Within Budget | {self.runtime_within_budget} |",
            f"| Peak Memory | {self.peak_memory_mb:.1f} MB |",
            f"| Avg CPU | {self.avg_cpu_percent:.1f}% |",
        ]
        if self.stage_timing:
            lines.append("\n### Stage Timing\n")
            lines.append("| Stage | Duration |")
            lines.append("|-------|----------|")
            for stage, dur in sorted(self.stage_timing.items()):
                lines.append(f"| {stage} | {dur:.3f}s |")
        return "\n".join(lines)

    def to_html(self) -> str:
        sections = [
            "<div class='metrics'>",
            "<h2>Benchmark Metrics</h2>",
            "<table><tr><th>Metric</th><th>Value</th></tr>",
            f"<tr><td>Precision</td><td>{self.precision:.1%}</td></tr>",
            f"<tr><td>Recall</td><td>{self.recall:.1%}</td></tr>",
            f"<tr><td>F1 Score</td><td>{self.f1_score:.3f}</td></tr>",
            f"<tr><td>Accuracy</td><td>{self.accuracy:.1%}</td></tr>",
            f"<tr><td>True Positives</td><td>{self.true_positives}</td></tr>",
            f"<tr><td>False Positives</td><td>{self.false_positives}</td></tr>",
            f"<tr><td>False Negatives</td><td>{self.false_negatives}</td></tr>",
            f"<tr><td>Runtime</td><td>{self.runtime_seconds:.1f}s</td></tr>",
            f"<tr><td>Peak Memory</td><td>{self.peak_memory_mb:.1f} MB</td></tr>",
            "</table>",
            "</div>",
        ]
        return "\n".join(sections)


class MetricsCollector:
    """Collects timing and resource metrics during a benchmark run."""

    def __init__(self) -> None:
        self._start_time: float | None = None
        self._timers: dict[str, float] = {}
        self._running: dict[str, float] = {}
        self._memory_samples: list[float] = []
        self._cpu_samples: list[float] = []

    def start_run(self) -> None:
        self._start_time = time.perf_counter()
        self._memory_samples = []
        self._cpu_samples = []

    def end_run(self) -> float:
        if self._start_time is None:
            return 0.0
        return time.perf_counter() - self._start_time

    def start_timer(self, name: str) -> None:
        self._running[name] = time.perf_counter()

    def stop_timer(self, name: str) -> float:
        elapsed = time.perf_counter() - self._running.pop(name, time.perf_counter())
        self._timers[name] = self._timers.get(name, 0.0) + elapsed
        return elapsed

    def get_timing(self, name: str) -> float:
        return self._timers.get(name, 0.0)

    def get_all_timing(self) -> dict[str, float]:
        return dict(self._timers)

    def sample_resources(self) -> None:
        try:
            import psutil

            proc = psutil.Process(os.getpid())
            self._memory_samples.append(proc.memory_info().rss / (1024 * 1024))
            self._cpu_samples.append(proc.cpu_percent(interval=0))
        except (ImportError, Exception):
            pass

    @property
    def peak_memory_mb(self) -> float:
        return max(self._memory_samples) if self._memory_samples else 0.0

    @property
    def avg_cpu_percent(self) -> float:
        return (sum(self._cpu_samples) / len(self._cpu_samples)) if self._cpu_samples else 0.0


def compute_metrics(
    expected_titles: list[str],
    actual_titles: list[str],
    true_negatives: int = 0,
) -> BenchmarkMetrics:
    """Compute precision, recall, F1, FP, FN between expected and actual finding titles.

    Parameters
    ----------
    expected_titles:
        List of title substrings that are expected to be found.
    actual_titles:
        List of actual finding titles returned by the pipeline.
    true_negatives:
        Number of true negatives (difficult to determine; defaults to 0).

    Returns
    -------
    BenchmarkMetrics with computed values.
    """
    expected_set = {t.lower() for t in expected_titles}
    actual_set = {t.lower() for t in actual_titles}

    true_positives = 0
    for exp in expected_set:
        for act in actual_set:
            if exp in act or act in exp:
                true_positives += 1
                break

    false_positives = len(actual_set) - true_positives
    false_negatives = len(expected_set) - true_positives

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    total = true_positives + false_positives + false_negatives + true_negatives
    accuracy = (true_positives + true_negatives) / total if total > 0 else 0.0

    return BenchmarkMetrics(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        true_negatives=true_negatives,
        precision=precision,
        recall=recall,
        f1_score=f1,
        accuracy=accuracy,
        total_expected=len(expected_set),
        total_actual=len(actual_set),
        total_matched=true_positives,
    )


def compare_cves(expected_cves: list[str], actual_cves: list[str]) -> dict[str, Any]:
    """Compare expected vs actual CVE lists."""
    expected_set = set(expected_cves)
    actual_set = set(actual_cves)
    matched = expected_set & actual_set
    fp = actual_set - expected_set
    fn = expected_set - actual_set
    coverage = len(matched) / len(expected_set) if expected_set else 1.0
    return {
        "matched": sorted(matched),
        "false_positives": sorted(fp),
        "false_negatives": sorted(fn),
        "coverage": coverage,
    }


__all__ = [
    "BenchmarkMetrics",
    "MetricsCollector",
    "compare_cves",
    "compute_metrics",
]
