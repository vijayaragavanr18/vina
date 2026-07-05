"""Tests for the Correlation & Attack Path engine."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vina.core.correlation import (
    AttackPath,
    CorrelationEngine,
    CorrelationRule,
    FindingMatcher,
    compute_correlation_stats,
    correlate,
)
from vina.models.findings import Finding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UNIQUE_ID = 0


def _make_finding(
    title: str = "test finding",
    severity: str = "medium",
    source_stage: str = "test",
    category: str = "vulnerability",
    evidence: str = "",
    target: str = "localhost",
) -> Finding:
    global _UNIQUE_ID
    _UNIQUE_ID += 1
    return Finding(
        id=f"test-{_UNIQUE_ID}",
        title=title,
        description=f"desc for {title}",
        severity=severity,
        category=category,
        source_stage=source_stage,
        target=target,
        evidence=evidence or f"evidence for {_UNIQUE_ID}",
        recommendation="fix it",
        timestamp=datetime.now(UTC).isoformat(),
    )


# ---------------------------------------------------------------------------
# AttackPath model
# ---------------------------------------------------------------------------


class TestAttackPathModel:
    def test_minimal_attack_path(self):
        path = AttackPath(
            id="AP-1",
            title="Test Path",
            description="A test",
            severity="high",
            confidence=0.8,
            likelihood=0.7,
            impact=0.7,
            score=75.0,
            attack_type="privilege_escalation",
            findings=[],
        )
        assert path.id == "AP-1"
        assert path.severity == "high"
        assert path.score == 75.0
        assert path.attack_type == "privilege_escalation"

    def test_attack_path_to_dict(self):
        f1 = _make_finding("finding one")
        path = AttackPath(
            id="AP-2",
            title="Full Path",
            description="A full path",
            severity="critical",
            confidence=0.95,
            likelihood=0.9,
            impact=0.9,
            score=92.0,
            attack_type="container_escape",
            findings=[f1],
            explanation="chained through docker",
            remediation="update docker",
            mitre_attack=["T1611"],
            cwe="CWE-250",
            cis_controls=["4.1"],
            references=["https://example.com"],
        )
        d = path.to_dict()
        assert d["id"] == "AP-2"
        assert d["score"] == 92.0
        assert d["severity"] == "critical"
        assert len(d["findings"]) == 1
        assert d["mitre_attack"] == ["T1611"]
        assert d["explanation"] == "chained through docker"

    def test_attack_path_with_prerequisites(self):
        path = AttackPath(
            id="AP-3",
            title="Prereq Path",
            description="desc",
            severity="medium",
            confidence=0.5,
            likelihood=0.5,
            impact=0.5,
            score=40.0,
            attack_type="lateral_movement",
            findings=[],
            prerequisites=["user shell", "network access"],
        )
        assert "user shell" in path.prerequisites

    def test_attack_path_empty_findings(self):
        path = AttackPath(
            id="AP-4",
            title="Empty",
            description="desc",
            severity="low",
            confidence=0.3,
            likelihood=0.3,
            impact=0.3,
            score=15.0,
            attack_type="exploitation",
            findings=[],
        )
        assert path.findings == []


# ---------------------------------------------------------------------------
# FindingMatcher
# ---------------------------------------------------------------------------


class TestFindingMatcher:
    def test_title_contains(self):
        matcher = FindingMatcher(title_contains="SUDO")
        CorrelationEngine(rules=[])
        f = _make_finding(title="sudoers misconfiguration")
        # Use the engine's static matching method
        assert CorrelationEngine._finding_matches(matcher, f)
        assert CorrelationEngine._finding_matches(matcher, _make_finding(title="SUDOERS privilege"))
        assert not CorrelationEngine._finding_matches(matcher, _make_finding(title="ssh keys found"))

    def test_source_stage_match(self):
        matcher = FindingMatcher(source_stage="docker")
        assert CorrelationEngine._finding_matches(matcher, _make_finding(source_stage="docker"))
        assert not CorrelationEngine._finding_matches(matcher, _make_finding(source_stage="ssh"))

    def test_category_match(self):
        matcher = FindingMatcher(category="vulnerability")
        assert CorrelationEngine._finding_matches(matcher, _make_finding(category="vulnerability"))
        assert not CorrelationEngine._finding_matches(matcher, _make_finding(category="misconfiguration"))

    def test_severity_minimum(self):
        matcher = FindingMatcher(severity_min="high")
        assert CorrelationEngine._finding_matches(matcher, _make_finding(severity="critical"))
        assert CorrelationEngine._finding_matches(matcher, _make_finding(severity="high"))
        assert not CorrelationEngine._finding_matches(matcher, _make_finding(severity="medium"))
        assert not CorrelationEngine._finding_matches(matcher, _make_finding(severity="low"))

    def test_combined_matcher(self):
        matcher = FindingMatcher(title_contains="docker", source_stage="docker", severity_min="medium")
        good = _make_finding(title="docker exposed", source_stage="docker", severity="high")
        assert CorrelationEngine._finding_matches(matcher, good)
        bad = _make_finding(title="docker exposed", source_stage="ssh", severity="high")
        assert not CorrelationEngine._finding_matches(matcher, bad)

    def test_empty_matcher(self):
        matcher = FindingMatcher()
        assert CorrelationEngine._finding_matches(matcher, _make_finding(title="anything"))


# ---------------------------------------------------------------------------
# CorrelationRule
# ---------------------------------------------------------------------------


class TestCorrelationRule:
    def test_rule_defaults(self):
        rule = CorrelationRule(
            rule_id="R-1",
            title="defaults",
            description="desc",
            severity="medium",
            attack_type="pe",
            required_findings=[FindingMatcher(title_contains="x")],
            optional_findings=[],
        )
        assert rule.exploitability_bonus == 0.0
        assert rule.credential_bonus == 0.0
        assert rule.gtfo_bonus == 0.0

    def test_rule_with_bonuses(self):
        rule = CorrelationRule(
            rule_id="R-2",
            title="bonus",
            description="desc",
            severity="high",
            attack_type="pe",
            required_findings=[FindingMatcher(title_contains="x")],
            optional_findings=[],
            exploitability_bonus=15.0,
            credential_bonus=10.0,
            gtfo_bonus=5.0,
        )
        assert rule.exploitability_bonus == 15.0
        assert rule.credential_bonus == 10.0
        assert rule.gtfo_bonus == 5.0


# ---------------------------------------------------------------------------
# CorrelationEngine - integration
# ---------------------------------------------------------------------------


def _engine(*, rules: list[CorrelationRule] | None = None) -> CorrelationEngine:
    return CorrelationEngine(rules=rules)


def _simple_rule(
    rule_id: str = "C-1",
    title: str = "Test Rule",
    severity: str = "high",
    attack_type: str = "privilege_escalation",
    required: list[FindingMatcher] | None = None,
    optional: list[FindingMatcher] | None = None,
    **kw,
) -> CorrelationRule:
    return CorrelationRule(
        rule_id=rule_id,
        title=title,
        description="desc",
        severity=severity,
        attack_type=attack_type,
        required_findings=required or [FindingMatcher(title_contains="required")],
        optional_findings=optional or [],
        **kw,
    )


class TestCorrelationEngine:
    def test_no_rules_no_findings(self):
        assert _engine(rules=[]).run([]) == []

    def test_single_rule_single_match(self):
        rule = _simple_rule(rule_id="C-1", required=[FindingMatcher(title_contains="docker", source_stage="docker")])
        f = _make_finding(title="docker socket mounted", source_stage="docker", severity="critical")
        paths = _engine(rules=[rule]).run([f])
        assert len(paths) == 1
        assert paths[0].id.startswith("C-1")
        assert paths[0].attack_type == "privilege_escalation"

    def test_multiple_rules(self):
        rules = [
            _simple_rule(rule_id="PE-1", required=[FindingMatcher(title_contains="suid")]),
            _simple_rule(rule_id="PE-2", required=[FindingMatcher(title_contains="capability")]),
        ]
        paths = _engine(rules=rules).run([_make_finding(title="suid binary found")])
        assert len(paths) == 1
        assert paths[0].id.startswith("PE-1")

    def test_risk_scoring_with_gtfo_bins(self):
        from vina.core.knowledge import EnrichedFinding

        f = _make_finding(title="gtfo bin found", evidence="/usr/bin/find")
        enriched = EnrichedFinding(
            finding=f,
            gtfo_bins=[{"binary": "find", "url": "https://gtfobins.github.io/gtfobins/find/", "technique": "suid"}],
            confidence_score=0.8,
        )
        rule = _simple_rule(rule_id="PE-GTFO", required=[FindingMatcher(title_contains="gtfo")], gtfo_bonus=15.0)
        paths = _engine(rules=[rule]).run([enriched])
        assert len(paths) == 1
        assert paths[0].score > 50

    def test_multiple_required_findings_all_present(self):
        rule = _simple_rule(
            rule_id="C-MULTI", required=[FindingMatcher(title_contains="req-a"), FindingMatcher(title_contains="req-b")]
        )
        paths = _engine(rules=[rule]).run([_make_finding(title="req-a"), _make_finding(title="req-b")])
        assert len(paths) == 1

    def test_multiple_required_findings_one_missing(self):
        rule = _simple_rule(
            rule_id="C-MULTI-MISS",
            required=[FindingMatcher(title_contains="req-a"), FindingMatcher(title_contains="req-b")],
        )
        paths = _engine(rules=[rule]).run([_make_finding(title="req-a")])
        assert len(paths) == 0

    def test_confidence_increases_with_more_matches(self):
        rule = _simple_rule(
            rule_id="C-CONF",
            required=[FindingMatcher(title_contains="base")],
            optional=[FindingMatcher(title_contains="extra-a"), FindingMatcher(title_contains="extra-b")],
        )
        base = _make_finding(title="base finding")
        extra1 = _make_finding(title="extra-a")
        extra2 = _make_finding(title="extra-b")
        engine = _engine(rules=[rule])
        paths1 = engine.run([base])
        assert len(paths1) == 1
        paths2 = engine.run([base, extra1, extra2])
        assert paths2[0].confidence >= paths1[0].confidence

    def test_no_match_when_required_missing(self):
        rule = _simple_rule(required=[FindingMatcher(title_contains="required")])
        paths = _engine(rules=[rule]).run([_make_finding(title="something else")])
        assert len(paths) == 0


# ---------------------------------------------------------------------------
# CorrelationStats
# ---------------------------------------------------------------------------


class TestCorrelationStats:
    def test_empty_stats(self):
        stats = compute_correlation_stats([])
        assert stats.total_paths == 0
        assert stats.by_severity == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        assert stats.highest_severity == ""
        assert stats.highest_score == 0.0
        assert stats.average_confidence == 0.0
        assert stats.overall_risk_score == 0.0
        assert stats.critical_chains == 0
        assert stats.high_chains == 0

    def test_stats_with_paths(self):
        paths = [
            AttackPath(
                id="a",
                title="a",
                description="",
                severity="critical",
                confidence=0.9,
                likelihood=0.9,
                impact=0.9,
                score=95.0,
                attack_type="pe",
                findings=[],
            ),
            AttackPath(
                id="b",
                title="b",
                description="",
                severity="high",
                confidence=0.7,
                likelihood=0.7,
                impact=0.7,
                score=70.0,
                attack_type="pe",
                findings=[],
            ),
            AttackPath(
                id="c",
                title="c",
                description="",
                severity="medium",
                confidence=0.5,
                likelihood=0.5,
                impact=0.5,
                score=45.0,
                attack_type="pe",
                findings=[],
            ),
        ]
        stats = compute_correlation_stats(paths)
        assert stats.total_paths == 3
        assert stats.by_severity == {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0}
        assert stats.highest_severity == "critical"
        assert stats.highest_score == 95.0
        assert stats.average_confidence == pytest.approx(0.7)
        assert stats.critical_chains == 1
        assert stats.high_chains == 1

    def test_risk_score_weighted(self):
        paths = [
            AttackPath(
                id="a",
                title="a",
                description="",
                severity="critical",
                confidence=0.9,
                likelihood=0.9,
                impact=0.9,
                score=90.0,
                attack_type="pe",
                findings=[],
            )
        ]
        stats = compute_correlation_stats(paths)
        assert stats.overall_risk_score == pytest.approx(90.0)


# ---------------------------------------------------------------------------
# convenience function: correlate()
# ---------------------------------------------------------------------------


class TestCorrelateConvenience:
    def test_correlate_returns_paths(self):
        findings = [_make_finding(title="docker exposed", source_stage="docker", severity="critical")]
        paths = correlate(findings)
        assert isinstance(paths, list)

    def test_correlate_empty(self):
        assert correlate([]) == []


# ---------------------------------------------------------------------------
# Regression: report integration
# ---------------------------------------------------------------------------


class TestCorrelationIntegration:
    def test_attack_path_serializable_to_json(self):
        import json

        f = _make_finding("test")
        path = AttackPath(
            id="AP-JSON",
            title="JSON Path",
            description="desc",
            severity="high",
            confidence=0.8,
            likelihood=0.7,
            impact=0.7,
            score=80.0,
            attack_type="lateral_movement",
            findings=[f],
            attack_chain=["step 1", "step 2"],
            explanation="chain",
            prerequisites=["shell"],
        )
        d = path.to_dict()
        dumped = json.dumps(d, indent=2, default=str)
        loaded = json.loads(dumped)
        assert loaded["id"] == "AP-JSON"
        assert loaded["score"] == 80.0
        assert len(loaded["findings"]) == 1
        assert loaded["attack_chain"] == ["step 1", "step 2"]
        assert loaded["prerequisites"] == ["shell"]

    def test_engine_is_reusable(self):
        engine = _engine()
        f1 = _make_finding(title="writable script", category="writable")
        f2 = _make_finding(title="PATH injection", category="misconfiguration")
        first = engine.run([f1])
        second = engine.run([f2])
        assert isinstance(first, list)
        assert isinstance(second, list)


# ---------------------------------------------------------------------------
# Confidence and risk score edge cases
# ---------------------------------------------------------------------------


class TestRiskScoreEdgeCases:
    def test_score_capped_at_100(self):
        rule = _simple_rule(
            rule_id="CAP",
            required=[FindingMatcher(title_contains="a")],
            optional=[FindingMatcher(title_contains="b")],
            exploitability_bonus=50.0,
            credential_bonus=50.0,
            gtfo_bonus=50.0,
        )
        engine = _engine(rules=[rule])
        f1 = _make_finding(title="a is required", evidence="/usr/bin/find")
        f2 = _make_finding(title="b is optional", evidence="/usr/bin/bash")
        paths = engine.run([f1, f2])
        assert paths[0].score <= 100

    def test_score_at_least_zero(self):
        rule = _simple_rule(rule_id="ZERO", required=[FindingMatcher(title_contains="a")])
        paths = _engine(rules=[rule]).run([_make_finding(title="a")])
        assert paths[0].score >= 0


# ---------------------------------------------------------------------------
# CorrelationStats edge cases
# ---------------------------------------------------------------------------


class TestCorrelationStatsEdgeCases:
    def test_all_same_severity(self):
        paths = [
            AttackPath(
                id="a",
                title="a",
                description="",
                severity="high",
                confidence=0.5,
                likelihood=0.5,
                impact=0.5,
                score=50.0,
                attack_type="pe",
                findings=[],
            ),
            AttackPath(
                id="b",
                title="b",
                description="",
                severity="high",
                confidence=0.6,
                likelihood=0.6,
                impact=0.6,
                score=60.0,
                attack_type="pe",
                findings=[],
            ),
        ]
        stats = compute_correlation_stats(paths)
        assert stats.by_severity == {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0}
        assert stats.highest_severity == "high"
        assert stats.critical_chains == 0
        assert stats.high_chains == 2

    def test_no_attack_paths_returns_zero_values(self):
        stats = compute_correlation_stats([])
        assert stats.highest_score == 0.0
        assert stats.highest_severity == ""
        assert stats.average_confidence == 0.0
        assert stats.overall_risk_score == 0.0
