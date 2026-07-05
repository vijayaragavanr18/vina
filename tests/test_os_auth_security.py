"""Tests for PS-02: Authentication, Access Control, and Privilege Management."""

from __future__ import annotations

import unittest
from dataclasses import fields


class AuthSecurityPackageTests(unittest.TestCase):
    """Test that auth_security package and modules can be imported."""

    def test_import_package(self) -> None:
        from vina.scanners.os.auth_security import AuthSecurityModule, AuthSecurityResult

        self.assertTrue(AuthSecurityModule)
        self.assertTrue(AuthSecurityResult)

    def test_import_pam(self) -> None:
        from vina.scanners.os.auth_security.pam import PamModule, PamResult, PamRule

        self.assertTrue(PamModule)
        self.assertTrue(PamResult)
        self.assertTrue(PamRule)

    def test_import_password(self) -> None:
        from vina.scanners.os.auth_security.password import PasswordEntry, PasswordModule, PasswordResult

        self.assertTrue(PasswordModule)
        self.assertTrue(PasswordResult)
        self.assertTrue(PasswordEntry)

    def test_import_credentials(self) -> None:
        from vina.scanners.os.auth_security.credentials import CredentialMatch, CredentialsModule, CredentialsResult

        self.assertTrue(CredentialsModule)
        self.assertTrue(CredentialsResult)
        self.assertTrue(CredentialMatch)

    def test_import_sessions(self) -> None:
        from vina.scanners.os.auth_security.sessions import SessionInfo, SessionsModule, SessionsResult

        self.assertTrue(SessionsModule)
        self.assertTrue(SessionsResult)
        self.assertTrue(SessionInfo)

    def test_import_polkit(self) -> None:
        from vina.scanners.os.auth_security.polkit import PolkitModule, PolkitResult, PolkitRuleFile

        self.assertTrue(PolkitModule)
        self.assertTrue(PolkitResult)
        self.assertTrue(PolkitRuleFile)

    def test_import_privesc_enhanced(self) -> None:
        from vina.scanners.os.auth_security.privesc_enhanced import PrivescEnhancedModule, PrivescEnhancedResult

        self.assertTrue(PrivescEnhancedModule)
        self.assertTrue(PrivescEnhancedResult)


class AuthSecurityResultTests(unittest.TestCase):
    """Test that AuthSecurityResult has the expected fields."""

    def test_result_has_findings(self) -> None:
        from vina.scanners.os.auth_security import AuthSecurityResult

        fnames = {f.name for f in fields(AuthSecurityResult)}
        self.assertIn("findings", fnames)
        self.assertIn("command_result", fnames)
        self.assertIn("warnings", fnames)
        self.assertIn("output_file", fnames)
        self.assertIn("execution_time_seconds", fnames)


class PamResultTests(unittest.TestCase):
    def test_result_fields(self) -> None:
        from vina.scanners.os.auth_security.pam import PamResult

        fnames = {f.name for f in fields(PamResult)}
        self.assertIn("findings", fnames)
        self.assertIn("command_result", fnames)

    def test_pam_rule(self) -> None:
        from vina.scanners.os.auth_security.pam import PamRule

        rule = PamRule(service="common-auth", type="auth", control="required", module="pam_unix.so", args="sha512", line=10)
        self.assertEqual(rule.module, "pam_unix.so")
        self.assertEqual(rule.service, "common-auth")
        self.assertEqual(rule.args, "sha512")

    def test_parse_pam(self) -> None:
        from vina.scanners.os.auth_security.pam import PamModule

        content = """# comment
auth    required        pam_unix.so nullok
auth    required        pam_faillock.so deny=5 unlock_time=900
account required        pam_unix.so
password requisite      pam_pwquality.so retry=3 minlen=14
password requisite      pam_unix.so sha512
session required        pam_unix.so
"""
        rules = PamModule._parse_pam_file("common-password", content)
        self.assertEqual(len(rules), 6)

    def test_pam_pwquality_args(self) -> None:
        from vina.scanners.os.auth_security.pam import PamModule

        parsed = PamModule._parse_pam_pwquality_args("retry=3 minlen=14 dcredit=-1")
        self.assertEqual(parsed["retry"], "3")
        self.assertEqual(parsed["minlen"], "14")
        self.assertEqual(parsed["dcredit"], "-1")

    def test_audit_pam_no_pwquality(self) -> None:
        from vina.models.findings import Finding
        from vina.scanners.os.auth_security.pam import PamModule, PamRule

        rules = [PamRule(service="common-auth", type="auth", control="required", module="pam_unix.so", args="sha512", line=1)]
        findings: list[Finding] = []
        PamModule._audit_pam(rules, findings, "testhost")
        self.assertTrue(any("PAM password quality module not configured" in f.title for f in findings))

    def test_audit_pam_no_faillock(self) -> None:
        from vina.models.findings import Finding
        from vina.scanners.os.auth_security.pam import PamModule, PamRule

        rules = [
            PamRule(service="common-password", type="password", control="requisite", module="pam_pwquality.so", args="retry=3", line=1),
            PamRule(service="common-password", type="password", control="requisite", module="pam_unix.so", args="sha512", line=2),
        ]
        findings: list[Finding] = []
        PamModule._audit_pam(rules, findings, "testhost")
        self.assertTrue(any("PAM account lockout not configured" in f.title for f in findings))


class PasswordModuleTests(unittest.TestCase):
    def test_result_fields(self) -> None:
        from vina.scanners.os.auth_security.password import PasswordResult

        fnames = {f.name for f in fields(PasswordResult)}
        self.assertIn("findings", fnames)
        self.assertIn("entries", fnames)

    def test_password_entry(self) -> None:
        from vina.scanners.os.auth_security.password import PasswordEntry

        entry = PasswordEntry(username="test", uid=1001, gid=1001, hash_prefix="$6$", hash_type="SHA-512")
        self.assertEqual(entry.hash_type, "SHA-512")

    def test_parse_passwd_shadow(self) -> None:
        from vina.scanners.os.auth_security.password import PasswordModule

        passwd_text = "root:x:0:0:root:/root:/bin/bash\nvijay:x:1000:1000:User:/home/vijay:/bin/bash\n"
        shadow_text = "root:$y$abc:19600:0:99999:7:::\nvijay:$6$xyz:19600:0:99999:7:::\n"
        mod = PasswordModule.__new__(PasswordModule)
        entries = mod._parse(passwd_text, shadow_text)
        self.assertEqual(len(entries), 2)
        entry_map = {e.username: e for e in entries}
        self.assertEqual(entry_map["root"].hash_type, "yescrypt")
        self.assertEqual(entry_map["vijay"].hash_type, "SHA-512")


class CredentialsModuleTests(unittest.TestCase):
    def test_result_fields(self) -> None:
        from vina.scanners.os.auth_security.credentials import CredentialsResult

        fnames = {f.name for f in fields(CredentialsResult)}
        self.assertIn("findings", fnames)
        self.assertIn("matches", fnames)

    def test_credential_match(self) -> None:
        from vina.scanners.os.auth_security.credentials import CredentialMatch

        m = CredentialMatch(path="/root/.env", pattern_name="aws_key", description="AWS Key", severity="high")
        self.assertEqual(m.severity, "high")


class SessionsModuleTests(unittest.TestCase):
    def test_result_fields(self) -> None:
        from vina.scanners.os.auth_security.sessions import SessionsResult

        fnames = {f.name for f in fields(SessionsResult)}
        self.assertIn("findings", fnames)
        self.assertIn("active_sessions", fnames)

    def test_session_info(self) -> None:
        from vina.scanners.os.auth_security.sessions import SessionInfo

        s = SessionInfo(user="root", tty="pts/0", from_addr="192.168.1.1")
        self.assertEqual(s.user, "root")


class PolkitModuleTests(unittest.TestCase):
    def test_result_fields(self) -> None:
        from vina.scanners.os.auth_security.polkit import PolkitResult

        fnames = {f.name for f in fields(PolkitResult)}
        self.assertIn("findings", fnames)
        self.assertIn("rule_files", fnames)

    def test_polkit_rule_file(self) -> None:
        from vina.scanners.os.auth_security.polkit import PolkitRuleFile

        rf = PolkitRuleFile(path="/etc/polkit-1/rules.d/test.rules", is_writable=True)
        self.assertTrue(rf.is_writable)


class PrivescEnhancedModuleTests(unittest.TestCase):
    def test_result_fields(self) -> None:
        from vina.scanners.os.auth_security.privesc_enhanced import PrivescEnhancedResult

        fnames = {f.name for f in fields(PrivescEnhancedResult)}
        self.assertIn("findings", fnames)
        self.assertIn("command_result", fnames)


class KnowledgeRulesTests(unittest.TestCase):
    def test_auth_security_rules_defined(self) -> None:
        from vina.core.knowledge import AUTH_SECURITY_RULES

        self.assertGreater(len(AUTH_SECURITY_RULES), 0)

    def test_auth_security_rules_in_all(self) -> None:
        from vina.core.knowledge import ALL_RULES, AUTH_SECURITY_RULES

        for rule in AUTH_SECURITY_RULES:
            self.assertIn(rule, ALL_RULES, f"{rule.rule_id} not in ALL_RULES")

    def test_rules_have_source_stages(self) -> None:
        from vina.core.knowledge import AUTH_SECURITY_RULES

        for rule in AUTH_SECURITY_RULES:
            self.assertIsNotNone(rule.source_stages, f"{rule.rule_id} missing source_stages")
            if rule.source_stages:
                self.assertIn("auth_security", rule.source_stages)


class CorrelationRulesTests(unittest.TestCase):
    def test_auth_correlation_rules_exist(self) -> None:
        from vina.core.correlation import _CORRELATION_RULES

        auth_rules = [r for r in _CORRELATION_RULES if r.rule_id.startswith("AP-AUTH-")]
        self.assertGreater(len(auth_rules), 0)

    def test_auth_correlation_rules_have_required(self) -> None:
        from vina.core.correlation import _CORRELATION_RULES

        for rule in _CORRELATION_RULES:
            if rule.rule_id.startswith("AP-AUTH-"):
                self.assertGreater(len(rule.required_findings), 0, f"{rule.rule_id} has no required findings")


class PipelineIntegrationTests(unittest.TestCase):
    def test_auth_security_in_stage_deps(self) -> None:
        from vina.scanners.os.os_pipeline import _STAGE_DEPS

        self.assertIn("auth_security", _STAGE_DEPS)

    def test_auth_security_in_os_tools(self) -> None:
        from vina.scanners.os.os_pipeline import _OS_TOOLS

        for tool in ("who", "w", "echo", "id"):
            self.assertIn(tool, _OS_TOOLS, f"{tool} not in _OS_TOOLS")


class FindingCategoryTests(unittest.TestCase):
    def test_finding_categories(self) -> None:
        from vina.models.findings import FindingCategory

        self.assertIn("misconfiguration", FindingCategory.__members__.values())
        self.assertIn("information", FindingCategory.__members__.values())


class MitreTechniqueTests(unittest.TestCase):
    def test_new_techniques(self) -> None:
        from vina.core.knowledge import MitreTechnique

        self.assertTrue(hasattr(MitreTechnique, "T1556_003"))
        self.assertTrue(hasattr(MitreTechnique, "T1552"))
        self.assertTrue(hasattr(MitreTechnique, "T1484"))


class CisControlTests(unittest.TestCase):
    def test_new_cis_controls(self) -> None:
        from vina.core.knowledge import CisControl

        self.assertTrue(hasattr(CisControl, "ubuntu_5_4_1_1"))
        self.assertTrue(hasattr(CisControl, "ubuntu_5_4_1_2"))
        self.assertTrue(hasattr(CisControl, "ubuntu_5_4_1_4"))
        self.assertTrue(hasattr(CisControl, "ubuntu_5_5_1_1"))
        self.assertTrue(hasattr(CisControl, "ubuntu_5_7_1"))


if __name__ == "__main__":
    unittest.main()
