"""AI-assisted summary analysis and report generation.

This module consumes a ``summary.json`` artifact produced by the scan
pipeline, ranks findings by severity, removes obvious false positives,
and produces Markdown and HTML reports. The analyzer never asserts that a
vulnerability is confirmed; it only produces evidence-backed triage and
manual verification guidance.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import html
import json
import logging
import re
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Iterable, Mapping, Sequence

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class FindingRecord:
	"""Normalized finding extracted from ``summary.json``."""

	title: str
	severity: str
	target: str
	tool: str = "unknown"
	evidence: str = ""
	confidence: float | None = None
	category: str | None = None
	raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Recommendation:
	"""Evidence-backed manual triage guidance for a finding."""

	title: str
	severity: str
	score: int
	target: str
	tool: str
	evidence: str
	rationale: str
	manual_verification: list[str] = field(default_factory=list)
	burp_request: str | None = None
	attack_paths: list[str] = field(default_factory=list)
	payloads: list[str] = field(default_factory=list)
	false_positive_reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisReport:
	"""Structured report returned by the analyzer."""

	source_path: Path
	generated_at: datetime
	target: str
	total_findings: int
	kept_findings: int
	removed_findings: int
	recommendations: list[Recommendation] = field(default_factory=list)
	markdown: str = ""
	html: str = ""


class SummaryAnalyzer:
	"""Analyze scan summaries and generate evidence-based triage reports."""

	def __init__(self) -> None:
		self._severity_weights = {
			"critical": 100,
			"high": 80,
			"medium": 60,
			"low": 35,
			"info": 15,
			"unknown": 20,
		}

	def analyze(self, summary: str | Path | Mapping[str, Any]) -> AnalysisReport:
		"""Analyze a ``summary.json`` file or parsed summary mapping.

		Parameters
		----------
		summary:
			Path to ``summary.json``, raw JSON text, or a parsed mapping.

		Returns
		-------
		AnalysisReport
			Structured analysis result with Markdown and HTML renderings.
		"""

		summary_data, source_path = self._load_summary(summary)
		target = self._extract_target(summary_data)
		findings = self._extract_findings(summary_data)
		total_findings = len(findings)

		kept_findings: list[FindingRecord] = []
		removed_findings: list[FindingRecord] = []
		for finding in findings:
			if self._is_obvious_false_positive(finding):
				removed_findings.append(finding)
			else:
				kept_findings.append(finding)

		recommendations = [self._build_recommendation(finding) for finding in kept_findings]
		recommendations.sort(key=lambda item: item.score, reverse=True)

		generated_at = datetime.now(timezone.utc)
		report = AnalysisReport(
			source_path=source_path,
			generated_at=generated_at,
			target=target,
			total_findings=total_findings,
			kept_findings=len(kept_findings),
			removed_findings=len(removed_findings),
			recommendations=recommendations,
		)
		report.markdown = self.render_markdown(report)
		report.html = self.render_html(report)
		return report

	def analyze_file(self, summary_path: str | Path) -> AnalysisReport:
		"""Convenience wrapper to analyze a file path."""

		return self.analyze(Path(summary_path))

	def save_reports(
		self,
		report: AnalysisReport,
		output_dir: str | Path,
		stem: str = "summary-analysis",
	) -> tuple[Path, Path]:
		"""Persist Markdown and HTML reports to ``output_dir``."""

		destination_root = Path(output_dir)
		destination_root.mkdir(parents=True, exist_ok=True)
		markdown_path = destination_root / f"{stem}.md"
		html_path = destination_root / f"{stem}.html"
		markdown_path.write_text(report.markdown, encoding="utf-8")
		html_path.write_text(report.html, encoding="utf-8")
		logger.info("Saved analysis reports to %s and %s", markdown_path, html_path)
		return markdown_path, html_path

	def render_markdown(self, report: AnalysisReport) -> str:
		"""Render the analysis report as Markdown."""

		lines: list[str] = []
		lines.append(f"# VINA Analysis Report")
		lines.append("")
		lines.append(f"- Target: {report.target}")
		lines.append(f"- Source: {report.source_path}")
		lines.append(f"- Generated at: {report.generated_at.isoformat()}")
		lines.append(f"- Findings processed: {report.total_findings}")
		lines.append(f"- Findings kept: {report.kept_findings}")
		lines.append(f"- False positives removed: {report.removed_findings}")
		lines.append("")
		lines.append("## Ranked Recommendations")
		if not report.recommendations:
			lines.append("No evidence-backed recommendations were produced.")
			return "\n".join(lines).rstrip() + "\n"

		for index, recommendation in enumerate(report.recommendations, start=1):
			lines.append(f"### {index}. {recommendation.title}")
			lines.append(f"- Severity: {recommendation.severity}")
			lines.append(f"- Score: {recommendation.score}")
			lines.append(f"- Target: {recommendation.target}")
			lines.append(f"- Tool: {recommendation.tool}")
			lines.append(f"- Evidence: {recommendation.evidence}")
			lines.append(f"- Rationale: {recommendation.rationale}")
			if recommendation.false_positive_reasons:
				lines.append("- False-positive screening:" )
				for reason in recommendation.false_positive_reasons:
					lines.append(f"  - {reason}")
			if recommendation.manual_verification:
				lines.append("- Manual verification:")
				for step in recommendation.manual_verification:
					lines.append(f"  - {step}")
			if recommendation.burp_request:
				lines.append("- Burp Suite request:")
				lines.append("```http")
				lines.append(recommendation.burp_request)
				lines.append("```")
			if recommendation.attack_paths:
				lines.append("- Attack paths:")
				for path in recommendation.attack_paths:
					lines.append(f"  - {path}")
			if recommendation.payloads:
				lines.append("- Payloads:")
				for payload in recommendation.payloads:
					lines.append(f"  - {payload}")
			lines.append("")
		return "\n".join(lines).rstrip() + "\n"

	def render_html(self, report: AnalysisReport) -> str:
		"""Render the analysis report as HTML."""

		cards = []
		for recommendation in report.recommendations:
			payload_items = "".join(f"<li>{html.escape(item)}</li>" for item in recommendation.payloads) or "<li>None</li>"
			path_items = "".join(f"<li>{html.escape(item)}</li>" for item in recommendation.attack_paths) or "<li>None</li>"
			verification_items = "".join(f"<li>{html.escape(item)}</li>" for item in recommendation.manual_verification) or "<li>None</li>"
			fp_items = "".join(f"<li>{html.escape(item)}</li>" for item in recommendation.false_positive_reasons) or "<li>None</li>"
			burp_block = f"<pre><code>{html.escape(recommendation.burp_request or '')}</code></pre>" if recommendation.burp_request else "<p>None</p>"
			cards.append(
				"<article class='finding'>"
				f"<h3>{html.escape(recommendation.title)}</h3>"
				f"<p><strong>Severity:</strong> {html.escape(recommendation.severity)} | <strong>Score:</strong> {recommendation.score}</p>"
				f"<p><strong>Target:</strong> {html.escape(recommendation.target)}</p>"
				f"<p><strong>Tool:</strong> {html.escape(recommendation.tool)}</p>"
				f"<p><strong>Evidence:</strong> {html.escape(recommendation.evidence)}</p>"
				f"<p><strong>Rationale:</strong> {html.escape(recommendation.rationale)}</p>"
				f"<p><strong>False-positive screening:</strong></p><ul>{fp_items}</ul>"
				f"<p><strong>Manual verification:</strong></p><ul>{verification_items}</ul>"
				f"<p><strong>Attack paths:</strong></p><ul>{path_items}</ul>"
				f"<p><strong>Payloads:</strong></p><ul>{payload_items}</ul>"
				f"<p><strong>Burp Suite request:</strong></p>{burp_block}"
				"</article>"
			)

		findings_html = "".join(cards) or "<p>No evidence-backed recommendations were produced.</p>"
		return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
	<title>VINA Analysis Report</title>
  <style>
	body {{ font-family: system-ui, sans-serif; margin: 0; background: #0b1020; color: #e8ecf3; }}
	main {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 64px; }}
	.meta, .finding {{ background: #121a33; border: 1px solid #243054; border-radius: 14px; padding: 16px; }}
	.meta {{ margin-bottom: 24px; }}
	.finding {{ margin-bottom: 18px; }}
	h1, h2, h3 {{ line-height: 1.15; }}
	pre {{ overflow-x: auto; background: #1a2445; padding: 12px; border-radius: 10px; }}
	code {{ color: #d9e6ff; }}
  </style>
</head>
<body>
  <main>
	<h1>VINA Analysis Report</h1>
	<section class="meta">
	  <p><strong>Target:</strong> {html.escape(report.target)}</p>
	  <p><strong>Source:</strong> {html.escape(str(report.source_path))}</p>
	  <p><strong>Generated at:</strong> {html.escape(report.generated_at.isoformat())}</p>
	  <p><strong>Findings processed:</strong> {report.total_findings}</p>
	  <p><strong>Findings kept:</strong> {report.kept_findings}</p>
	  <p><strong>False positives removed:</strong> {report.removed_findings}</p>
	</section>
	<section>
	  <h2>Ranked Recommendations</h2>
	  {findings_html}
	</section>
  </main>
</body>
</html>
"""

	def _load_summary(self, summary: str | Path | Mapping[str, Any]) -> tuple[dict[str, Any], Path]:
		if isinstance(summary, Mapping):
			return dict(summary), Path("summary.json")
		if isinstance(summary, Path):
			text = summary.read_text(encoding="utf-8")
			return self._parse_summary_text(text), summary
		if isinstance(summary, str):
			path_candidate = Path(summary)
			if path_candidate.exists():
				return self._load_summary(path_candidate)
			return self._parse_summary_text(summary), Path("summary.json")
		raise TypeError(f"Unsupported summary input type: {type(summary)!r}")

	@staticmethod
	def _parse_summary_text(text: str) -> dict[str, Any]:
		data = json.loads(text)
		if not isinstance(data, dict):
			raise ValueError("summary.json must contain a JSON object")
		return data

	def _extract_target(self, summary: Mapping[str, Any]) -> str:
		for key in ("target", "host", "domain", "scope"):
			value = summary.get(key)
			if isinstance(value, str) and value.strip():
				return value.strip()
		metadata = summary.get("metadata")
		if isinstance(metadata, Mapping):
			for key in ("target", "host", "domain", "scope"):
				value = metadata.get(key)
				if isinstance(value, str) and value.strip():
					return value.strip()
		return "unknown"

	def _extract_findings(self, summary: Mapping[str, Any]) -> list[FindingRecord]:
		raw_findings = self._findings_source(summary)
		findings: list[FindingRecord] = []
		for item in raw_findings:
			normalized = self._normalize_finding(item)
			if normalized is not None:
				findings.append(normalized)
		return findings

	def _findings_source(self, summary: Mapping[str, Any]) -> list[Any]:
		for key in ("findings", "vulnerabilities", "results", "issues", "scan_results"):
			value = summary.get(key)
			if isinstance(value, list):
				return value
		modules = summary.get("modules")
		if isinstance(modules, Mapping):
			for key in ("findings", "vulnerabilities", "results", "issues", "scan_results"):
				value = modules.get(key)
				if isinstance(value, list):
					return value
		return []

	def _normalize_finding(self, item: Any) -> FindingRecord | None:
		if isinstance(item, str):
			return FindingRecord(title=item.strip() or "Untitled finding", severity="unknown", target="unknown", evidence=item)
		if not isinstance(item, Mapping):
			return None

		title = self._pick_text(item, ("title", "name", "finding", "message", "template", "issue"), default="Untitled finding")
		severity = self._pick_text(item, ("severity", "level", "risk", "confidence"), default="unknown")
		target = self._pick_text(item, ("target", "host", "url", "matched-at", "endpoint"), default="unknown")
		tool = self._pick_text(item, ("tool", "scanner", "source", "plugin", "template_id", "template-id"), default="unknown")
		evidence = self._extract_evidence_text(item)
		confidence = self._pick_confidence(item)
		category = self._pick_text(item, ("category", "type", "tag"), default=None)
		return FindingRecord(
			title=title,
			severity=severity,
			target=target,
			tool=tool,
			evidence=evidence,
			confidence=confidence,
			category=category,
			raw=dict(item),
		)

	def _pick_text(self, item: Mapping[str, Any], keys: Sequence[str], default: str | None = None) -> str:
		for key in keys:
			value = item.get(key)
			if isinstance(value, str) and value.strip():
				return value.strip()
			if isinstance(value, Mapping):
				nested = self._extract_text_from_mapping(value)
				if nested:
					return nested
		return default if default is not None else ""

	def _pick_confidence(self, item: Mapping[str, Any]) -> float | None:
		value = item.get("confidence")
		if isinstance(value, (int, float)):
			return float(value)
		risk = item.get("risk")
		if isinstance(risk, (int, float)):
			return float(risk)
		return None

	def _extract_text_from_mapping(self, mapping: Mapping[str, Any]) -> str:
		for value in mapping.values():
			if isinstance(value, str) and value.strip():
				return value.strip()
			if isinstance(value, Mapping):
				nested = self._extract_text_from_mapping(value)
				if nested:
					return nested
		return ""

	def _extract_evidence_text(self, item: Mapping[str, Any]) -> str:
		evidence_candidates: list[Any] = []
		for key in ("evidence", "evidences", "raw", "response", "match", "matched", "snippet", "detail"):
			if key in item:
				evidence_candidates.append(item[key])
		for candidate in evidence_candidates:
			text = self._stringify_evidence(candidate)
			if text:
				return text
		return self._stringify_evidence(item)

	def _stringify_evidence(self, value: Any) -> str:
		if isinstance(value, str):
			return value.strip()
		if isinstance(value, Mapping):
			return json.dumps(value, ensure_ascii=False, sort_keys=True)
		if isinstance(value, (list, tuple, set)):
			return json.dumps(list(value), ensure_ascii=False)
		return str(value)

	def _is_obvious_false_positive(self, finding: FindingRecord) -> bool:
		title = finding.title.lower()
		evidence = finding.evidence.lower()
		target = finding.target.lower()
		false_positive_signals = [
			"false positive",
			"informational",
			"no issue",
			"not vulnerable",
			"unsupported",
			"placeholder",
		]
		if any(signal in title or signal in evidence for signal in false_positive_signals):
			return True
		if finding.severity.lower() in {"info", "informational"} and not any(token in title for token in ("exposed", "leak", "xss", "sqli", "rce", "ssrf", "auth", "path", "cmd")):
			return True
		if target in {"localhost", "127.0.0.1", "0.0.0.0", "unknown"} and not evidence:
			return True
		return False

	def _build_recommendation(self, finding: FindingRecord) -> Recommendation:
		score = self._score(finding)
		rationale = self._build_rationale(finding)
		manual_verification = self._manual_verification(finding)
		burp_request = self._burp_request(finding)
		attack_paths = self._attack_paths(finding)
		payloads = self._payloads(finding)
		false_positive_reasons = self._false_positive_reasons(finding)
		return Recommendation(
			title=finding.title,
			severity=finding.severity,
			score=score,
			target=finding.target,
			tool=finding.tool,
			evidence=finding.evidence,
			rationale=rationale,
			manual_verification=manual_verification,
			burp_request=burp_request,
			attack_paths=attack_paths,
			payloads=payloads,
			false_positive_reasons=false_positive_reasons,
		)

	def _score(self, finding: FindingRecord) -> int:
		severity = finding.severity.lower().strip() or "unknown"
		base = self._severity_weights.get(severity, self._severity_weights["unknown"])
		if finding.confidence is not None:
			base += int(max(0.0, min(1.0, finding.confidence)) * 5)
		if any(token in finding.title.lower() for token in ("auth", "xss", "sqli", "rce", "ssrf", "lfi", "rfi", "open redirect", "csrf")):
			base += 10
		if finding.evidence:
			base += 5
		return min(base, 100)

	def _build_rationale(self, finding: FindingRecord) -> str:
		severity = finding.severity.lower() or "unknown"
		return (
			f"{finding.tool} reported {finding.title} at {finding.target} with severity {severity}. "
			f"The scan evidence is: {finding.evidence}. This is a triage signal only and does not confirm a vulnerability."
		)

	def _manual_verification(self, finding: FindingRecord) -> list[str]:
		steps = [
			f"Review the reported evidence from {finding.tool}: {finding.evidence}.",
			"Reproduce the behavior manually in Burp Suite or a browser before drawing conclusions.",
			"Compare the response to a benign baseline request and document the delta.",
		]
		if finding.category:
			steps.append(f"Confirm whether the category '{finding.category}' matches the observed behavior.")
		return steps

	def _burp_request(self, finding: FindingRecord) -> str:
		target = finding.target
		if target.startswith("http://") or target.startswith("https://"):
			parsed = urlparse(target)
			host = parsed.netloc or parsed.path
			path = parsed.path or "/"
			if parsed.query:
				path = f"{path}?{parsed.query}"
		else:
			host = target
			path = "/"
		return "\n".join(
			[
				f"GET {path} HTTP/1.1",
				f"Host: {host}",
				"User-Agent: VINA/AI-Analyzer",
				"Accept: */*",
				"Connection: close",
				"",
			]
		)

	def _attack_paths(self, finding: FindingRecord) -> list[str]:
		title = finding.title.lower()
		evidence = finding.evidence
		paths = [
			f"Start from the evidence: {evidence}",
			"Validate the reported target manually and identify the minimum request needed to reproduce it.",
		]
		if any(token in title for token in ("xss", "script", "reflected")):
			paths.append("Check for reflection, context-sensitive encoding, and cookie/session exposure.")
		if any(token in title for token in ("sqli", "sql", "database")):
			paths.append("Test whether input alters query behavior or causes server-side SQL errors.")
		if any(token in title for token in ("rce", "command", "template", "injection")):
			paths.append("Look for command execution primitives, parameter interpolation, or template evaluation.")
		if any(token in title for token in ("ssrf", "url fetch", "fetch")):
			paths.append("Check whether the server makes outbound requests that can reach internal or metadata endpoints.")
		if any(token in title for token in ("auth", "access", "permission", "role")):
			paths.append("Verify whether authorization boundaries can be bypassed by changing roles, IDs, or request context.")
		return paths

	def _payloads(self, finding: FindingRecord) -> list[str]:
		title = finding.title.lower()
		payloads = ["FUZZ"]
		if any(token in title for token in ("xss", "script", "reflected")):
			payloads.extend(["<script>alert(1)</script>", "\"'><svg/onload=alert(1)>", "%3Cscript%3Ealert(1)%3C/script%3E"])
		if any(token in title for token in ("sqli", "sql", "database")):
			payloads.extend(["'", "' OR '1'='1", '" OR "1"="1', "UNION SELECT NULL--"]) 
		if any(token in title for token in ("lfi", "path", "file")):
			payloads.extend(["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd"])
		if any(token in title for token in ("ssrf", "url fetch", "fetch")):
			payloads.extend(["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"])
		if any(token in title for token in ("auth", "access", "permission", "role")):
			payloads.extend(["admin", "test", "0", "1"])
		return list(dict.fromkeys(payloads))

	def _false_positive_reasons(self, finding: FindingRecord) -> list[str]:
		reasons = [
			"The analyzer treats scanner output as a signal, not as proof of impact.",
			f"Evidence from the scan: {finding.evidence}.",
		]
		if finding.severity.lower() in {"info", "informational"}:
			reasons.append("Informational severity usually requires additional manual validation before escalation.")
		if finding.confidence is not None and finding.confidence < 0.5:
			reasons.append(f"Confidence value is low ({finding.confidence:.2f}), so the result may be noisy.")
		return reasons


def analyze_summary(summary: str | Path | Mapping[str, Any]) -> AnalysisReport:
	"""Convenience function that analyzes ``summary.json`` data."""

	return SummaryAnalyzer().analyze(summary)


def save_analysis_reports(
	summary: str | Path | Mapping[str, Any],
	output_dir: str | Path,
	stem: str = "summary-analysis",
) -> tuple[AnalysisReport, Path, Path]:
	"""Analyze summary data and persist Markdown and HTML reports."""

	analyzer = SummaryAnalyzer()
	report = analyzer.analyze(summary)
	markdown_path, html_path = analyzer.save_reports(report, output_dir=output_dir, stem=stem)
	return report, markdown_path, html_path


__all__ = [
	"AnalysisReport",
	"FindingRecord",
	"Recommendation",
	"SummaryAnalyzer",
	"analyze_summary",
	"save_analysis_reports",
]
