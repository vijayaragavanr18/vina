"""Tests for the knowledge base and enrichment engine."""

from __future__ import annotations

import unittest

from vina.core.knowledge import (
    ALL_RULES,
    GTFOBINS_BINARIES,
    EnrichedFinding,
    EnrichmentEngine,
    KnowledgeRule,
    enrich_all,
    enrich_finding,
)
from vina.models.findings import Finding, make_finding


class EnrichedFindingTests(unittest.TestCase):
    """EnrichedFinding wrapper behaviour."""

    def test_delegates_finding_attributes(self):
        finding = Finding(
            id="test/example/title",
            title="Test finding",
            severity="high",
            category="misconfiguration",
            source_stage="test",
            target="example.com",
        )
        ef = EnrichedFinding(finding=finding)
        self.assertEqual(ef.id, "test/example/title")
        self.assertEqual(ef.title, "Test finding")
        self.assertEqual(ef.severity, "high")
        self.assertEqual(ef.category, "misconfiguration")
        self.assertEqual(ef.source_stage, "test")
        self.assertEqual(ef.target, "example.com")

    def test_enrichment_fields_default_to_empty(self):
        finding = Finding(title="test", severity="info", category="other", source_stage="t", target="t")
        ef = EnrichedFinding(finding=finding)
        self.assertEqual(ef.explanation, "")
        self.assertEqual(ef.security_impact, "")
        self.assertEqual(ef.remediation, "")
        self.assertEqual(ef.cis_control, "")
        self.assertEqual(ef.mitre_attack, [])
        self.assertEqual(ef.cwe, "")
        self.assertEqual(ef.gtfo_bins, [])
        self.assertEqual(ef.confidence_score, 0.0)

    def test_enriched_fields_are_settable(self):
        finding = Finding(title="test", severity="info", category="other", source_stage="t", target="t")
        ef = EnrichedFinding(
            finding=finding,
            explanation="test explanation",
            security_impact="test impact",
            remediation="test remediation",
            cis_control="CIS-1.0",
            cwe="CWE-200",
        )
        self.assertEqual(ef.explanation, "test explanation")
        self.assertEqual(ef.security_impact, "test impact")
        self.assertEqual(ef.remediation, "test remediation")
        self.assertEqual(ef.cis_control, "CIS-1.0")
        self.assertEqual(ef.cwe, "CWE-200")

    def test_to_dict_includes_all_fields(self):
        finding = Finding(
            id="test/example/Title",
            title="Title",
            severity="high",
            category="misconfiguration",
            source_stage="test",
            target="example.com",
            evidence="evidence text",
        )
        ef = EnrichedFinding(
            finding=finding,
            explanation="exp",
            security_impact="imp",
            remediation="rem",
            cis_control="CIS-1",
            mitre_attack=["T1003"],
            cwe="CWE-200",
            confidence_score=0.9,
        )
        d = ef.to_dict()
        # Original Finding fields
        self.assertEqual(d["id"], "test/example/Title")
        self.assertEqual(d["title"], "Title")
        self.assertEqual(d["severity"], "high")
        self.assertEqual(d["evidence"], "evidence text")
        # Enriched fields
        self.assertEqual(d["explanation"], "exp")
        self.assertEqual(d["security_impact"], "imp")
        self.assertEqual(d["remediation"], "rem")
        self.assertEqual(d["cis_control"], "CIS-1")
        self.assertEqual(d["mitre_attack"], ["T1003"])
        self.assertEqual(d["cwe"], "CWE-200")
        self.assertEqual(d["confidence_score"], 0.9)

    def test_has_enrichment_false_when_empty(self):
        finding = Finding(title="t", severity="info", category="o", source_stage="s", target="t")
        ef = EnrichedFinding(finding=finding)
        self.assertFalse(ef.has_enrichment())

    def test_has_enrichment_true_when_set(self):
        finding = Finding(title="t", severity="info", category="o", source_stage="s", target="t")
        ef = EnrichedFinding(finding=finding, explanation="something")
        self.assertTrue(ef.has_enrichment())

    def test_has_enrichment_true_with_gtfo(self):
        finding = Finding(title="t", severity="info", category="o", source_stage="s", target="t")
        ef = EnrichedFinding(finding=finding, gtfo_bins=[{"binary": "find"}])
        self.assertTrue(ef.has_enrichment())


class KnowledgeRuleTests(unittest.TestCase):
    """KnowledgeRule dataclass behaviour."""

    def test_minimal_rule(self):
        rule = KnowledgeRule(
            rule_id="TEST-001",
            title_patterns=["test"],
            explanation="test explanation",
            security_impact="test impact",
            remediation="test remediation",
        )
        self.assertEqual(rule.rule_id, "TEST-001")
        self.assertEqual(rule.title_patterns, ["test"])
        self.assertEqual(rule.explanation, "test explanation")
        self.assertEqual(rule.security_impact, "test impact")
        self.assertEqual(rule.remediation, "test remediation")
        self.assertEqual(rule.references, [])
        self.assertEqual(rule.cis_control, "")
        self.assertEqual(rule.mitre_attack, [])
        self.assertEqual(rule.cwe, "")
        self.assertEqual(rule.tags, [])
        self.assertEqual(rule.confidence_score, 0.8)
        self.assertIsNone(rule.source_stages)
        self.assertIsNone(rule.source_categories)

    def test_full_rule(self):
        rule = KnowledgeRule(
            rule_id="TEST-002",
            title_patterns=["pattern1", "pattern2"],
            explanation="test",
            security_impact="test",
            remediation="test",
            references=["https://example.com"],
            cis_control="CIS-1",
            mitre_attack=["T1003"],
            cwe="CWE-200",
            tags=["tag1"],
            confidence_score=0.95,
            source_stages=["test"],
            source_categories=["vulnerability"],
        )
        self.assertEqual(rule.references, ["https://example.com"])
        self.assertEqual(rule.cis_control, "CIS-1")
        self.assertEqual(rule.mitre_attack, ["T1003"])
        self.assertEqual(rule.cwe, "CWE-200")
        self.assertEqual(rule.tags, ["tag1"])
        self.assertEqual(rule.confidence_score, 0.95)
        self.assertEqual(rule.source_stages, ["test"])
        self.assertEqual(rule.source_categories, ["vulnerability"])


class TestAllRules(unittest.TestCase):
    """Verify the consolidated rule list."""

    def test_all_rules_have_required_fields(self):
        for rule in ALL_RULES:
            with self.subTest(rule_id=rule.rule_id):
                self.assertTrue(rule.rule_id)
                self.assertTrue(rule.title_patterns)
                self.assertTrue(rule.explanation)
                self.assertTrue(rule.security_impact)
                self.assertTrue(rule.remediation)

    def test_all_rules_have_unique_ids(self):
        ids = [r.rule_id for r in ALL_RULES]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate rule IDs found")

    def test_rule_ids_use_expected_prefixes(self):
        prefixes = {
            "PE-",
            "CAP-",
            "SSH-",
            "DOCKER-",
            "KERNEL-",
            "WRITABLE-",
            "SEC-",
            "AUTH-",
            "PROC-",
            "PKG-",
            "SVC-",
            "CRON-",
            "BIN-",
            "FS-",
        }
        for rule in ALL_RULES:
            with self.subTest(rule_id=rule.rule_id):
                self.assertTrue(
                    any(rule.rule_id.startswith(p) for p in prefixes),
                    f"Unexpected prefix in {rule.rule_id}",
                )


class GTFOBinsTests(unittest.TestCase):
    """GTFOBins mapping validation."""

    def test_required_binaries_present(self):
        required = {"find", "bash", "tar", "python3", "perl", "nmap"}
        for binary in required:
            with self.subTest(binary=binary):
                self.assertIn(binary, GTFOBINS_BINARIES)

    def test_each_entry_has_url_and_technique(self):
        for name, entry in GTFOBINS_BINARIES.items():
            with self.subTest(name=name):
                self.assertIn("url", entry)
                self.assertIn("technique", entry)
                self.assertIn("description", entry)
                self.assertTrue(entry["url"].startswith("https://"))


class EnrichmentEngineMatchingTests(unittest.TestCase):
    """EnrichmentEngine finding-to-rule matching."""

    def setUp(self):
        self.engine = EnrichmentEngine()

    def test_match_by_title_substring(self):
        finding = make_finding(
            title="NOPASSWD sudo: ALL commands",
            severity="critical",
            category="misconfiguration",
            source_stage="sudo",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("sudo", enriched.explanation.lower())

    def test_no_match_for_unknown_finding(self):
        finding = make_finding(
            title="Some random informational message",
            severity="info",
            category="information",
            source_stage="test",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertFalse(enriched.has_enrichment())

    def test_match_ssh_root_login(self):
        finding = make_finding(
            title="SSH root login is permitted",
            severity="high",
            category="misconfiguration",
            source_stage="ssh",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("PermitRootLogin", enriched.remediation)

    def test_match_docker_socket(self):
        finding = make_finding(
            title="Docker socket is world-writable",
            severity="critical",
            category="misconfiguration",
            source_stage="docker",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertEqual(enriched.confidence_score, 0.95)
        self.assertIn("chmod", enriched.remediation)

    def test_match_aslr_disabled(self):
        finding = make_finding(
            title="ASLR is disabled",
            severity="high",
            category="misconfiguration",
            source_stage="kernel",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("randomize_va_space", enriched.remediation)

    def test_match_writable_path(self):
        finding = make_finding(
            title="Writable PATH entries (2)",
            severity="high",
            category="misconfiguration",
            source_stage="environment",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertEqual(enriched.confidence_score, 0.9)

    def test_match_cron_writable(self):
        finding = make_finding(
            title="Writable files in /etc/cron.d",
            severity="high",
            category="misconfiguration",
            source_stage="cron",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertEqual(enriched.confidence_score, 0.9)

    def test_match_systemd_writable(self):
        finding = make_finding(
            title="Writable systemd unit: /etc/systemd/system/test.service",
            severity="high",
            category="misconfiguration",
            source_stage="systemd",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())

    def test_match_suid_binary(self):
        finding = make_finding(
            title="SUID binary: /usr/bin/pkexec",
            severity="high",
            category="privilege_escalation",
            source_stage="privilege_escalation",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("SUID", enriched.explanation)

    def test_match_docker_group(self):
        finding = make_finding(
            title="Users in docker group: bob, alice",
            severity="high",
            category="misconfiguration",
            source_stage="docker",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("docker group", enriched.explanation.lower())

    def test_match_sensitive_env_var(self):
        finding = make_finding(
            title="Sensitive env variable: AWS_SECRET_ACCESS_KEY",
            severity="medium",
            category="exposure",
            source_stage="environment",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertEqual(enriched.confidence_score, 0.7)

    def test_match_failed_logins(self):
        finding = make_finding(
            title="Failed logins: 50",
            severity="medium",
            category="authentication",
            source_stage="logs",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("brute-force", enriched.explanation.lower())

    def test_match_credentials_in_config(self):
        finding = make_finding(
            title="Credentials in config: /root/.my.cnf",
            severity="critical",
            category="secret",
            source_stage="secrets",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertEqual(enriched.confidence_score, 0.9)

    def test_match_suspicious_process(self):
        finding = make_finding(
            title="Suspicious process: xmrig",
            severity="high",
            category="process",
            source_stage="processes",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("suspicious", enriched.explanation.lower())

    def test_mitre_attack_mapping_included(self):
        finding = make_finding(
            title="NOPASSWD sudo: ALL commands",
            severity="critical",
            category="misconfiguration",
            source_stage="sudo",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(len(enriched.mitre_attack) > 0)
        self.assertIn("T1548", enriched.mitre_attack[0])

    def test_cis_control_mapping_included(self):
        finding = make_finding(
            title="SSH root login is permitted",
            severity="high",
            category="misconfiguration",
            source_stage="ssh",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.cis_control.startswith("CIS"))

    def test_cwe_included(self):
        finding = make_finding(
            title="Docker socket is world-writable",
            severity="critical",
            category="misconfiguration",
            source_stage="docker",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertEqual(enriched.cwe, "CWE-732: Incorrect Permission Assignment for Critical Resource")

    def test_priviledged_container(self):
        finding = make_finding(
            title="Privileged container: nginx:latest",
            severity="high",
            category="misconfiguration",
            source_stage="docker",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("privileged", enriched.explanation.lower())

    def test_direct_root_logins(self):
        finding = make_finding(
            title="Direct root logins: 3",
            severity="high",
            category="authentication",
            source_stage="logs",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("root", enriched.explanation.lower())

    def test_ssh_key_found(self):
        finding = make_finding(
            title="SSH key found: /root/.ssh/id_rsa",
            severity="high",
            category="secret",
            source_stage="secrets",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())

    def test_env_file_found(self):
        finding = make_finding(
            title=".env file found: /root/.env",
            severity="high",
            category="secret",
            source_stage="secrets",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("credentials", enriched.explanation.lower())

    def test_suspicious_exec_start(self):
        finding = make_finding(
            title="Suspicious ExecStart: /tmp/malware.sh",
            severity="high",
            category="misconfiguration",
            source_stage="systemd",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("writable", enriched.explanation.lower())

    def test_writable_system_directories(self):
        finding = make_finding(
            title="Writable system directories (5 found)",
            severity="medium",
            category="misconfiguration",
            source_stage="privilege_escalation",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())

    def test_capability_finding(self):
        finding = make_finding(
            title="Capability: /usr/bin/python3",
            severity="high",
            category="privilege_escalation",
            source_stage="capabilities",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("capabilities", enriched.explanation.lower())

    def test_root_cron_job(self):
        finding = make_finding(
            title="Root cron job: /usr/bin/backup.sh",
            severity="medium",
            category="scheduled_task",
            source_stage="cron",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("cron", enriched.explanation.lower())

    def test_unstable_apt_source(self):
        finding = make_finding(
            title="Potentially unstable apt source: deb http://deb.debian.org/debian sid main",
            severity="medium",
            category="misconfiguration",
            source_stage="packages",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertEqual(enriched.confidence_score, 0.75)

    def test_password_sudo_all(self):
        finding = make_finding(
            title="Password sudo: ALL commands",
            severity="high",
            category="misconfiguration",
            source_stage="sudo",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertIn("ALL", enriched.explanation)


class EnrichmentEngineEdgeCaseTests(unittest.TestCase):
    """Edge cases for the enrichment engine."""

    def setUp(self):
        self.engine = EnrichmentEngine()

    def test_engine_with_empty_rules(self):
        engine = EnrichmentEngine(rules=[])
        finding = make_finding(
            title="NOPASSWD sudo: ALL commands",
            severity="critical",
            category="misconfiguration",
            source_stage="sudo",
            target="localhost",
        )
        enriched = engine.enrich_finding(finding)
        self.assertFalse(enriched.has_enrichment())

    def test_engine_with_custom_rules(self):
        custom_rule = KnowledgeRule(
            rule_id="CUSTOM-001",
            title_patterns=["custom pattern"],
            explanation="Custom explanation",
            security_impact="Custom impact",
            remediation="Custom remediation",
        )
        engine = EnrichmentEngine(rules=[custom_rule])
        matching = make_finding(
            title="This contains custom pattern in it",
            severity="info",
            category="other",
            source_stage="test",
            target="localhost",
        )
        enriched = engine.enrich_finding(matching)
        self.assertTrue(enriched.has_enrichment())
        self.assertEqual(enriched.explanation, "Custom explanation")

        non_matching = make_finding(
            title="This does not match",
            severity="info",
            category="other",
            source_stage="test",
            target="localhost",
        )
        enriched2 = engine.enrich_finding(non_matching)
        self.assertFalse(enriched2.has_enrichment())

    def test_enrich_all(self):
        findings = [
            make_finding(
                title="NOPASSWD sudo: ALL commands",
                severity="critical",
                category="misconfiguration",
                source_stage="sudo",
                target="localhost",
            ),
            make_finding(
                title="Unknown finding", severity="info", category="other", source_stage="test", target="localhost"
            ),
            make_finding(
                title="ASLR is disabled",
                severity="high",
                category="misconfiguration",
                source_stage="kernel",
                target="localhost",
            ),
        ]
        enriched = self.engine.enrich_all(findings)
        self.assertEqual(len(enriched), 3)
        self.assertTrue(enriched[0].has_enrichment())
        self.assertFalse(enriched[1].has_enrichment())
        self.assertTrue(enriched[2].has_enrichment())

    def test_case_insensitive_matching(self):
        finding = make_finding(
            title="nopasswd sudo: all commands",
            severity="critical",
            category="misconfiguration",
            source_stage="sudo",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())

    def test_enrich_with_evidence_containing_gtfo_path(self):
        finding = make_finding(
            title="SUID binary: /usr/bin/find",
            severity="high",
            category="privilege_escalation",
            source_stage="privilege_escalation",
            target="localhost",
            evidence="/usr/bin/find",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertTrue(len(enriched.gtfo_bins) > 0)
        self.assertEqual(enriched.gtfo_bins[0]["binary"], "find")

    def test_confidence_score_highest_wins(self):
        # Both DOCKER-001 (0.95) and general pattern matching the title should produce 0.95
        finding = make_finding(
            title="Docker socket is world-writable",
            severity="critical",
            category="misconfiguration",
            source_stage="docker",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        self.assertEqual(enriched.confidence_score, 0.95)

    def test_source_stage_filter_respected(self):
        # Rule KERNEL-003 has source_stages=["kernel"]
        # A finding from another stage with "expected" in title should not match KERNEL-003
        finding = make_finding(
            title="Some expected value not found",
            severity="info",
            category="other",
            source_stage="test",
            target="localhost",
        )
        enriched = self.engine.enrich_finding(finding)
        # It may match other rules if they have "expected", but not KERNEL-003
        if enriched.explanation:
            self.assertNotIn("kernel", enriched.explanation.lower())
        else:
            self.assertFalse(enriched.has_enrichment())


class ConvenienceFunctionTests(unittest.TestCase):
    """Default engine convenience functions."""

    def test_enrich_finding(self):
        finding = make_finding(
            title="NOPASSWD sudo: ALL commands",
            severity="critical",
            category="misconfiguration",
            source_stage="sudo",
            target="localhost",
        )
        enriched = enrich_finding(finding)
        self.assertTrue(enriched.has_enrichment())
        self.assertEqual(enriched.confidence_score, 0.95)

    def test_enrich_all(self):
        findings = [
            make_finding(
                title="ASLR is disabled",
                severity="high",
                category="misconfiguration",
                source_stage="kernel",
                target="localhost",
            ),
            make_finding(title="Unknown", severity="info", category="other", source_stage="t", target="localhost"),
        ]
        enriched = enrich_all(findings)
        self.assertEqual(len(enriched), 2)

    def test_reuses_default_engine(self):
        f1 = make_finding(
            title="ASLR is disabled",
            severity="high",
            category="misconfiguration",
            source_stage="kernel",
            target="localhost",
        )
        f2 = make_finding(
            title="ASLR is disabled",
            severity="high",
            category="misconfiguration",
            source_stage="kernel",
            target="localhost",
        )
        e1 = enrich_finding(f1)
        e2 = enrich_finding(f2)
        self.assertEqual(e1.explanation, e2.explanation)


if __name__ == "__main__":
    unittest.main()
