"""AI-assisted prioritization and manual verification planning."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models.common import AnalysisItem, Finding, ParameterCandidate, PortEntry, TechnologyEntry


@dataclass(slots=True)
class AnalysisResult:
    items: list[AnalysisItem] = field(default_factory=list)


class AIAnalysisModule:
    def run(
        self,
        findings: list[Finding],
        ports: list[PortEntry],
        technologies: list[TechnologyEntry],
        parameters: list[ParameterCandidate],
    ) -> AnalysisResult:
        items = [self._score_finding(finding) for finding in findings]
        if not items:
            items = self._fallback_items(ports, technologies, parameters)
        items.sort(key=lambda item: item.score, reverse=True)
        return AnalysisResult(items=items)

    def _score_finding(self, finding: Finding) -> AnalysisItem:
        severity_map = {
            "critical": 95,
            "high": 80,
            "medium": 60,
            "low": 35,
            "info": 15,
        }
        score = severity_map.get(finding.severity.lower(), 20)
        rationale = f"{finding.tool} reported {finding.title} for {finding.target}. This is a triage signal, not proof of impact."
        return AnalysisItem(
            finding_title=finding.title,
            score=score,
            rationale=rationale,
            manual_verification=[
                "Reproduce the response or behavior manually in Burp Suite.",
                "Confirm the issue still exists without relying on tool output alone.",
            ],
            burp_request=self._burp_template(finding),
            payload_ideas=self._payload_ideas(finding),
        )

    def _fallback_items(
        self,
        ports: list[PortEntry],
        technologies: list[TechnologyEntry],
        parameters: list[ParameterCandidate],
    ) -> list[AnalysisItem]:
        items: list[AnalysisItem] = []
        if parameters:
            items.append(
                AnalysisItem(
                    finding_title="Parameterized endpoints",
                    score=55,
                    rationale="Endpoints with query parameters deserve manual review because they often justify Burp-assisted testing.",
                    manual_verification=["Check reflected input and parameter handling in Burp.", "Map allowed methods and auth boundaries."],
                    burp_request=f"GET {parameters[0].url} HTTP/1.1\nHost: {parameters[0].url}",
                    payload_ideas=["FUZZ", "<script>alert(1)</script>", "' OR '1'='1"],
                )
            )
        if ports:
            items.append(
                AnalysisItem(
                    finding_title="Exposed services",
                    score=40,
                    rationale="Open ports expand the attack surface and should be correlated with exposed technologies and expected service posture.",
                    manual_verification=["Confirm which ports are truly required.", "Check for version disclosure and default configurations."],
                )
            )
        if technologies:
            items.append(
                AnalysisItem(
                    finding_title="Technology fingerprints",
                    score=30,
                    rationale="Detected technologies help prioritize manual review, especially when they map to known risky components.",
                    manual_verification=["Check whether the fingerprint is accurate.", "Review version-specific advisories manually."],
                )
            )
        return items

    @staticmethod
    def _burp_template(finding: Finding) -> str:
        return f"GET / HTTP/1.1\nHost: {finding.target}\nUser-Agent: VINA/AI-Analyzer"

    @staticmethod
    def _payload_ideas(finding: Finding) -> list[str]:
        severity = finding.severity.lower()
        ideas = ["FUZZ"]
        if severity in {"high", "critical"}:
            ideas.extend(["<script>alert(1)</script>", "' OR '1'='1", "../../../../etc/passwd"])
        elif severity in {"medium", "low"}:
            ideas.extend(["test", "1", "admin"])
        return ideas
