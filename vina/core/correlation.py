"""Correlation & Attack Path Engine for VINA.

Correlates individual findings into realistic attack paths, privilege
escalation chains, persistence opportunities, credential exposure
scenarios, and lateral movement opportunities.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, cast

from ..core.knowledge import EnrichedFinding
from ..models.findings import Finding, severity_key

_SEVERITY_WEIGHTS: dict[str, float] = {
    "info": 5,
    "low": 20,
    "medium": 45,
    "high": 70,
    "critical": 90,
}

# ---------------------------------------------------------------------------
#  AttackPath model
# ---------------------------------------------------------------------------


@dataclass
class AttackPath:
    """A correlated attack path built from multiple findings.

    All attributes are plain strings / lists for direct serialisation.
    ``findings`` holds the matched :class:`Finding` objects.
    """

    id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.5
    likelihood: float = 0.5
    impact: float = 0.5
    score: float = 0.0
    attack_type: str = "unknown"
    findings: list[Finding] = field(default_factory=list)
    explanation: str = ""
    attack_chain: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)
    cwe: str = ""
    cis_controls: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "score": self.score,
            "attack_type": self.attack_type,
            "findings": [f.to_dict() for f in self.findings],
            "explanation": self.explanation,
            "attack_chain": self.attack_chain,
            "remediation": self.remediation,
            "references": self.references,
            "mitre_attack": self.mitre_attack,
            "cwe": self.cwe,
            "cis_controls": self.cis_controls,
            "prerequisites": self.prerequisites,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
#  Correlation rule model
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class FindingMatcher:
    """Describes a finding pattern to match in a correlation rule.

    A finding matches if *all* non-empty fields match.
    """

    title_contains: str = ""
    source_stage: str = ""
    category: str = ""
    severity_min: str = ""


@dataclass(slots=True)
class CorrelationRule:
    """A rule that correlates multiple findings into an attack path."""

    rule_id: str
    title: str
    description: str
    attack_type: str
    severity: str
    required_findings: list[FindingMatcher] = field(default_factory=list)
    optional_findings: list[FindingMatcher] = field(default_factory=list)
    minimum_confidence: float = 0.0
    explanation: str = ""
    attack_chain: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)
    cwe: str = ""
    cis_controls: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    exploitability_bonus: float = 0.0
    credential_bonus: float = 0.0
    persistence_bonus: float = 0.0
    gtfo_bonus: float = 0.0


# ---------------------------------------------------------------------------
#  All correlation rules
# ---------------------------------------------------------------------------

_CORRELATION_RULES: list[CorrelationRule] = [
    # --- Privilege Escalation chain 1: passwordless sudo + writable cron ---
    CorrelationRule(
        rule_id="AP-PE-001",
        title="Passwordless sudo + Writable cron → Root shell",
        description="A user with passwordless sudo access and writable cron files can "
        "modify a cron script to execute arbitrary code as root.",
        attack_type="privilege_escalation",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="NOPASSWD sudo"),
            FindingMatcher(title_contains="Writable files in /etc/cron.", source_stage="cron"),
        ],
        attack_chain=[
            "User",
            "↓",
            "Passwordless sudo (any command)",
            "↓",
            "Writable cron file modified with malicious payload",
            "↓",
            "Cron runs as root",
            "↓",
            "Root shell",
        ],
        remediation="Remove NOPASSWD sudo rules and ensure cron files are owned by root with 644 permissions.",
        mitre_attack=["T1548.003 - Abuse Elevation Control Mechanism: Sudo", "T1053.003 - Scheduled Task/Job: Cron"],
        cwe="CWE-276: Incorrect Default Permissions",
        cis_controls=["CIS Control 5: Account Management", "CIS Control 4: Secure Configuration"],
        exploitability_bonus=15,
        persistence_bonus=10,
    ),
    # --- Privilege Escalation chain 2: passwordless sudo + writable systemd ---
    CorrelationRule(
        rule_id="AP-PE-002",
        title="Passwordless sudo + Writable systemd unit → Root shell",
        description="A user with passwordless sudo can modify a world-writable systemd "
        "unit file to execute arbitrary code as root on service restart.",
        attack_type="privilege_escalation",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="NOPASSWD sudo"),
            FindingMatcher(title_contains="Writable systemd unit"),
        ],
        attack_chain=[
            "User",
            "↓",
            "Passwordless sudo (any command)",
            "↓",
            "Writable systemd unit modified with ExecStart payload",
            "↓",
            "systemctl restart triggers root execution",
            "↓",
            "Root shell",
        ],
        remediation="Remove NOPASSWD sudo rules. Restrict systemd unit permissions: chmod 644 && chown root:root.",
        mitre_attack=[
            "T1548.003 - Abuse Elevation Control Mechanism: Sudo",
            "T1569.002 - System Services: Service Execution",
        ],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        cis_controls=["CIS Control 5: Account Management", "CIS Control 4: Secure Configuration"],
        exploitability_bonus=15,
        persistence_bonus=10,
    ),
    # --- Privilege Escalation chain 3: passwordless sudo + writable PATH ---
    CorrelationRule(
        rule_id="AP-PE-003",
        title="Passwordless sudo + Writable PATH → Root shell",
        description="A user with passwordless sudo can place a malicious executable in a "
        "world-writable PATH directory. When root runs any command resolved to that PATH, "
        "the malicious binary executes as root.",
        attack_type="privilege_escalation",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="NOPASSWD sudo"),
            FindingMatcher(title_contains="Writable PATH entries"),
        ],
        attack_chain=[
            "User",
            "↓",
            "Passwordless sudo (any command)",
            "↓",
            "Place malicious binary in writable PATH directory",
            "↓",
            "Root executes affected command",
            "↓",
            "Root shell",
        ],
        remediation="Remove NOPASSWD sudo rules and fix world-writable PATH directories.",
        mitre_attack=[
            "T1548.003 - Abuse Elevation Control Mechanism: Sudo",
            "T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking",
        ],
        cwe="CWE-426: Untrusted Search Path",
        cis_controls=["CIS Control 5: Account Management", "CIS Control 4: Secure Configuration"],
        exploitability_bonus=15,
        persistence_bonus=5,
    ),
    # --- Privilege Escalation chain 4: SUID + GTFOBins ---
    CorrelationRule(
        rule_id="AP-PE-004",
        title="SUID binary + GTFOBins → Privilege escalation",
        description="A SUID binary that is listed on GTFOBins can be used to escalate "
        "privileges to the owner of the binary (typically root).",
        attack_type="privilege_escalation",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="SUID binary"),
        ],
        optional_findings=[
            FindingMatcher(title_contains="SUID binary"),
        ],
        attack_chain=[
            "User",
            "↓",
            "SUID binary identified",
            "↓",
            "Execute GTFOBins technique",
            "↓",
            "Privileged shell",
        ],
        remediation="Remove the SUID bit if not required. Monitor GTFOBins-listed SUID binaries.",
        references=["https://gtfobins.github.io/"],
        mitre_attack=["T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid"],
        cwe="CWE-250: Execution with Unnecessary Privileges",
        cis_controls=["CIS Control 4: Secure Configuration"],
        gtfo_bonus=15,
        exploitability_bonus=10,
    ),
    # --- Privilege Escalation chain 5: capabilities + GTFOBins ---
    CorrelationRule(
        rule_id="AP-PE-005",
        title="Linux capabilities + GTFOBins → Privilege escalation",
        description="A binary with dangerous Linux capabilities (cap_setuid, cap_dac_override, etc.) "
        "that is also listed on GTFOBins can be used to escalate privileges.",
        attack_type="privilege_escalation",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="Capability:"),
        ],
        attack_chain=[
            "User",
            "↓",
            "Dangerous capability on binary identified",
            "↓",
            "Execute GTFOBins technique with capability",
            "↓",
            "Privileged shell",
        ],
        remediation="Remove unnecessary capabilities: setcap -r <path>. Review capability assignments.",
        references=["https://gtfobins.github.io/"],
        mitre_attack=["T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid"],
        cwe="CWE-250: Execution with Unnecessary Privileges",
        cis_controls=["CIS Control 4: Secure Configuration"],
        gtfo_bonus=10,
        exploitability_bonus=10,
    ),
    # --- Persistence chain 1: writable cron + root cron job ---
    CorrelationRule(
        rule_id="AP-PERSIST-001",
        title="Writable cron + Root cron job → Persistence",
        description="A root cron job exists and the cron directory has writable files. "
        "An attacker can modify an existing cron script to maintain persistence as root.",
        attack_type="persistence",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="Writable files in /etc/cron."),
            FindingMatcher(title_contains="Root cron job:"),
        ],
        attack_chain=[
            "Attacker",
            "↓",
            "Identify writable cron file",
            "↓",
            "Inject persistence payload into root cron script",
            "↓",
            "Cron executes payload as root",
            "↓",
            "Persistent root access",
        ],
        remediation="Restrict cron file permissions. Audit root cron jobs and remove unnecessary ones.",
        mitre_attack=["T1053.003 - Scheduled Task/Job: Cron"],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        cis_controls=["CIS Control 4: Secure Configuration"],
        persistence_bonus=15,
        exploitability_bonus=10,
    ),
    # --- Container escape chain 1: docker group + writable socket ---
    CorrelationRule(
        rule_id="AP-CONTAINER-001",
        title="Docker group + World-writable docker.sock → Host root",
        description="Users in the docker group and a world-writable Docker socket allow "
        "any user to execute Docker commands, which grants root-level host access.",
        attack_type="container_escape",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="Users in docker group"),
            FindingMatcher(title_contains="Docker socket is world-writable"),
        ],
        attack_chain=[
            "Docker group user",
            "↓",
            "docker.sock is world-writable",
            "↓",
            "Run privileged container with host mount",
            "↓",
            "Access host filesystem as root",
            "↓",
            "Host root",
        ],
        remediation="Remove users from docker group. Restrict socket permissions: chmod 660.",
        mitre_attack=["T1611 - Escape to Host"],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        cis_controls=["CIS Control 5: Account Management", "CIS Control 6: Access Control Management"],
        exploitability_bonus=15,
    ),
    # --- Container escape chain 2: privileged container + writable socket ---
    CorrelationRule(
        rule_id="AP-CONTAINER-002",
        title="Privileged container + World-writable docker.sock → Host root",
        description="A privileged container with access to the world-writable Docker socket "
        "can be used to escape the container and gain root access on the host.",
        attack_type="container_escape",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="Privileged container:"),
            FindingMatcher(title_contains="Docker socket is world-writable"),
        ],
        attack_chain=[
            "Privileged container",
            "↓",
            "docker.sock mounted or host socket accessible",
            "↓",
            "Run new container with host root mount",
            "↓",
            "Access host filesystem",
            "↓",
            "Host root",
        ],
        remediation="Avoid privileged containers. Restrict socket permissions.",
        mitre_attack=["T1611 - Escape to Host"],
        cwe="CWE-250: Execution with Unnecessary Privileges",
        cis_controls=["CIS Control 4: Secure Configuration"],
        exploitability_bonus=15,
    ),
    # --- Lateral movement chain 1: secrets + SSH ---
    CorrelationRule(
        rule_id="AP-LM-001",
        title="Secrets discovered + SSH enabled → Lateral movement",
        description="Exposed credentials (SSH keys, .env files, hardcoded passwords) combined "
        "with SSH access allow lateral movement to other systems.",
        attack_type="lateral_movement",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="SSH key found", source_stage="secrets"),
        ],
        optional_findings=[
            FindingMatcher(title_contains="Credentials in config:"),
            FindingMatcher(title_contains=".env file found"),
            FindingMatcher(title_contains="private-key:"),
        ],
        attack_chain=[
            "Attacker",
            "↓",
            "Extract SSH keys / credentials from files",
            "↓",
            "Use credentials to SSH to other hosts",
            "↓",
            "Pivot to additional target systems",
        ],
        remediation="Rotate exposed keys immediately. Use a secrets manager. Disable SSH password auth.",
        mitre_attack=["T1552.004 - Unsecured Credentials: Private Keys", "T1021.004 - Remote Services: SSH"],
        cwe="CWE-312: Cleartext Storage of Sensitive Information",
        cis_controls=["CIS Control 3: Data Protection"],
        credential_bonus=12,
        exploitability_bonus=8,
    ),
    # --- Lateral movement chain 2: SSH root login + password auth ---
    CorrelationRule(
        rule_id="AP-LM-002",
        title="SSH root login + PasswordAuthentication → Credential brute-force",
        description="SSH allows direct root login with password authentication, making the "
        "system highly susceptible to credential brute-force attacks.",
        attack_type="lateral_movement",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="SSH root login is permitted"),
            FindingMatcher(title_contains="SSH password authentication is enabled"),
        ],
        attack_chain=[
            "Internet / Network",
            "↓",
            "Brute-force root password via SSH",
            "↓",
            "Direct root access",
            "↓",
            "Full system compromise",
        ],
        remediation="Set PermitRootLogin no and PasswordAuthentication no in sshd_config.",
        mitre_attack=["T1021.004 - Remote Services: SSH", "T1110 - Brute Force"],
        cwe="CWE-287: Improper Authentication",
        cis_controls=["CIS Control 5: Account Management"],
        exploitability_bonus=12,
    ),
    # --- Lateral movement chain 3: SSH root login + failed logins ---
    CorrelationRule(
        rule_id="AP-LM-003",
        title="SSH root login + Failed logins → Active brute-force",
        description="SSH root login is enabled and there are repeated failed login attempts, "
        "indicating an active or prior brute-force attack against the root account.",
        attack_type="lateral_movement",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="SSH root login is permitted"),
            FindingMatcher(title_contains="Failed logins:"),
        ],
        attack_chain=[
            "Internet / Attacker",
            "↓",
            "Brute-force root password (multiple failures)",
            "↓",
            "Successful root login (if password guessed)",
            "↓",
            "Full system compromise",
        ],
        remediation="Disable SSH root login. Implement fail2ban. Review auth.log for breach indicators.",
        mitre_attack=["T1021.004 - Remote Services: SSH", "T1110 - Brute Force"],
        cwe="CWE-307: Improper Restriction of Excessive Authentication Attempts",
        cis_controls=["CIS Control 8: Audit Log Management"],
        exploitability_bonus=10,
    ),
    # --- Kernel hardening chain 1: disabled Secure Boot + SELinux/AppArmor ---
    CorrelationRule(
        rule_id="AP-KH-001",
        title="Disabled Secure Boot + Disabled MAC → Persistent tampering",
        description="Secure Boot is disabled and Mandatory Access Control (SELinux/AppArmor) "
        "is not enforcing, allowing persistent kernel-level tampering without detection.",
        attack_type="privilege_escalation",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="Secure Boot is disabled"),
        ],
        optional_findings=[
            FindingMatcher(title_contains="SELinux is permissive", source_stage="kernel_hardening"),
            FindingMatcher(title_contains="SELinux is disabled", source_stage="kernel_hardening"),
            FindingMatcher(title_contains="AppArmor is disabled", source_stage="kernel_hardening"),
        ],
        attack_chain=[
            "Attacker gains initial access",
            "↓",
            "Secure Boot disabled — unsigned kernel modules can be loaded",
            "↓",
            "MAC not enforcing — no containment on compromised processes",
            "↓",
            "Attacker loads rootkit as unsigned kernel module, persists across reboots",
        ],
        remediation="Enable Secure Boot in UEFI and enforce SELinux or AppArmor.",
        mitre_attack=["T1542 - Boot or Logon Autostart Execution", "T1562.001 - Impair Defenses: Disable or Modify Tools"],
        cwe="CWE-284: Improper Access Control",
        cis_controls=["CIS Control 4: Secure Configuration"],
        persistence_bonus=7,
    ),
    # --- Kernel hardening chain 2: CPU vulnerabilities + disabled MAC ---
    CorrelationRule(
        rule_id="AP-KH-002",
        title="CPU vulnerabilities + Disabled MAC → Memory leak exploitation",
        description="The system has unmitigated CPU vulnerabilities (Spectre/Meltdown) and "
        "no MAC enforcement, making memory disclosure attacks more impactful.",
        attack_type="exploitation",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="CPU vulnerable to", source_stage="kernel_hardening"),
        ],
        optional_findings=[
            FindingMatcher(title_contains="SELinux is disabled", source_stage="kernel_hardening"),
            FindingMatcher(title_contains="AppArmor is disabled", source_stage="kernel_hardening"),
            FindingMatcher(title_contains="SELinux is permissive", source_stage="kernel_hardening"),
        ],
        attack_chain=[
            "Attacker runs unprivileged code on the system",
            "↓",
            "CPU side-channel vulnerability unmitigated — kernel memory leak possible",
            "↓",
            "MAC disabled — leaked data not contained",
            "↓",
            "Attacker extracts secrets from kernel memory",
        ],
        remediation="Apply CPU microcode updates, enable kernel mitigations, and enforce MAC.",
        mitre_attack=["T1068 - Exploitation for Privilege Escalation"],
        cwe="CWE-200: Exposure of Sensitive Information",
        cis_controls=["CIS Control 4: Secure Configuration"],
        exploitability_bonus=5,
    ),
    # --- Kernel hardening chain 3: unprivileged BPF + disabled MAC ---
    CorrelationRule(
        rule_id="AP-KH-003",
        title="Unprivileged eBPF + Disabled MAC → Kernel exploit chain",
        description="Unprivileged eBPF is enabled and MAC is disabled, creating a "
        "direct path for kernel privilege escalation using BPF exploits.",
        attack_type="privilege_escalation",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="eBPF is accessible", source_stage="kernel_hardening"),
        ],
        optional_findings=[
            FindingMatcher(title_contains="SELinux is disabled", source_stage="kernel_hardening"),
            FindingMatcher(title_contains="SELinux is permissive", source_stage="kernel_hardening"),
            FindingMatcher(title_contains="AppArmor is disabled", source_stage="kernel_hardening"),
        ],
        attack_chain=[
            "Attacker runs unprivileged code",
            "↓",
            "Unprivileged eBPF enabled — can load BPF programs into kernel",
            "↓",
            "MAC disabled — BPF program execution not constrained",
            "↓",
            "Known eBPF exploits (CVE-2020-8835, CVE-2021-3490) grant root",
        ],
        remediation="Set kernel.unprivileged_bpf_disabled=1 and enforce SELinux or AppArmor.",
        mitre_attack=["T1068 - Exploitation for Privilege Escalation"],
        cwe="CWE-693: Protection Mechanism Failure",
        cis_controls=["CIS Control 4: Secure Configuration"],
        exploitability_bonus=9,
    ),
    # --- Auth chain 1: password auth + root login + no PAM lockout → Remote root compromise ---
    CorrelationRule(
        rule_id="AP-AUTH-001",
        title="SSH PasswordAuthentication + PermitRootLogin + No PAM lockout → Remote root compromise",
        description="SSH allows password authentication and root login, and PAM account lockout "
        "is not configured. An attacker can brute-force the root password without being locked out.",
        attack_type="lateral_movement",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="SSH password authentication is enabled"),
            FindingMatcher(title_contains="SSH root login is permitted"),
            FindingMatcher(title_contains="PAM account lockout not configured"),
        ],
        attack_chain=[
            "External attacker",
            "↓",
            "SSH root login enabled (PermitRootLogin yes)",
            "↓",
            "Password authentication enabled",
            "↓",
            "No PAM account lockout — unlimited brute-force attempts",
            "↓",
            "Root password guessed via brute-force",
            "↓",
            "Full remote root compromise",
        ],
        remediation="Set PermitRootLogin no, PasswordAuthentication no, and configure pam_faillock.so with deny=5.",
        mitre_attack=["T1021.004 - Remote Services: SSH", "T1110 - Brute Force"],
        cwe="CWE-307: Improper Restriction of Excessive Authentication Attempts",
        cis_controls=["CIS Control 5: Account Management", "CIS Control 4: Secure Configuration"],
        exploitability_bonus=15,
    ),
    # --- Auth chain 2: NOPASSWD sudo + GTFOBins binary → Instant root shell ---
    CorrelationRule(
        rule_id="AP-AUTH-002",
        title="NOPASSWD sudo + GTFOBins binary → Instant root shell",
        description="A user has NOPASSWD sudo access to a command that is listed on GTFOBins. "
        "GTFOBins-listed commands have known shell-escape techniques that bypass command restrictions.",
        attack_type="privilege_escalation",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="NOPASSWD sudo"),
            FindingMatcher(title_contains="GTFOBins"),
        ],
        attack_chain=[
            "Low-privilege user",
            "↓",
            "User has NOPASSWD sudo access",
            "↓",
            "sudo -l reveals GTFOBins-listed binary",
            "↓",
            "Execute GTFOBins shell-escape technique via sudo",
            "↓",
            "Root shell",
        ],
        remediation="Remove NOPASSWD from sudo rules. Restrict sudo to only non-GTFOBins commands.",
        mitre_attack=["T1548.003 - Abuse Elevation Control Mechanism: Sudo"],
        cwe="CWE-250: Execution with Unnecessary Privileges",
        cis_controls=["CIS Control 5: Account Management"],
        gtfo_bonus=15,
        exploitability_bonus=15,
    ),
    # --- Auth chain 3: weak PAM password + empty password → Account compromise ---
    CorrelationRule(
        rule_id="AP-AUTH-003",
        title="Weak PAM password policy + Empty passwords → Account compromise",
        description="PAM password quality checks are not configured and user accounts have "
        "empty or weak passwords, allowing trivial account compromise.",
        attack_type="privilege_escalation",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="PAM password quality module not configured"),
            FindingMatcher(title_contains="Empty password for user"),
        ],
        attack_chain=[
            "Attacker with local access",
            "↓",
            "No password complexity requirements (PAM pwquality missing)",
            "↓",
            "User account has empty password",
            "↓",
            "Login without password",
            "↓",
            "Account compromise (potential privilege escalation)",
        ],
        remediation="Configure pam_pwquality.so and set passwords for all accounts.",
        cis_controls=["CIS Control 5: Account Management"],
        cwe="CWE-521: Weak Password Requirements",
        exploitability_bonus=10,
    ),
    # --- Auth chain 4: exposed credentials + SSH → Credential reuse attack ---
    CorrelationRule(
        rule_id="AP-AUTH-004",
        title="Exposed credentials + SSH service → Credential reuse attack",
        description="Credentials (API keys, private keys, passwords) were found on the "
        "filesystem and SSH is enabled, allowing credential reuse for lateral movement.",
        attack_type="lateral_movement",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="Credential exposure:"),
        ],
        optional_findings=[
            FindingMatcher(title_contains="SSH password authentication is enabled"),
            FindingMatcher(title_contains="SSH key found", source_stage="secrets"),
        ],
        attack_chain=[
            "Attacker with file read access",
            "↓",
            "Discover exposed credentials on filesystem",
            "↓",
            "SSH is enabled — test credentials against local/network hosts",
            "↓",
            "Credential reuse grants access to additional systems",
            "↓",
            "Lateral movement successful",
        ],
        remediation="Remove exposed credentials, rotate all affected keys/tokens, use a secrets manager.",
        mitre_attack=["T1552.001 - Unsecured Credentials: Credentials In Files", "T1021.004 - Remote Services: SSH"],
        cwe="CWE-312: Cleartext Storage of Sensitive Information",
        cis_controls=["CIS Control 3: Data Protection"],
        credential_bonus=12,
        exploitability_bonus=8,
    ),
    # --- Auth chain 5: writable PATH + SSH root → Full host takeover ---
    CorrelationRule(
        rule_id="AP-AUTH-005",
        title="PATH hijacking + SSH root → Full host takeover",
        description="PATH contains world-writable directories and SSH root login is enabled, "
        "allowing an attacker who gains a foothold to escalate via PATH hijacking.",
        attack_type="privilege_escalation",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="PATH contains world-writable directories"),
            FindingMatcher(title_contains="SSH root login is permitted"),
        ],
        attack_chain=[
            "Attacker with low-privilege SSH access",
            "↓",
            "PATH contains writable directory",
            "↓",
            "Place malicious binary in writable PATH",
            "↓",
            "Root executes command that resolves to malicious binary",
            "↓",
            "Root shell",
        ],
        remediation="Remove writable directories from PATH. Set PermitRootLogin no.",
        mitre_attack=["T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking"],
        cwe="CWE-426: Untrusted Search Path",
        cis_controls=["CIS Control 5: Account Management"],
        exploitability_bonus=10,
    ),
    # --- Auth chain 6: LD_PRELOAD + SUID binary → Privilege escalation ---
    CorrelationRule(
        rule_id="AP-AUTH-006",
        title="LD_PRELOAD + SUID binary → Privilege escalation",
        description="LD_PRELOAD is set globally and SUID binaries are present. If a SUID binary "
        "honors LD_PRELOAD (some older or custom binaries do), library injection is possible.",
        attack_type="privilege_escalation",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="LD_PRELOAD environment variable is set"),
            FindingMatcher(title_contains="SUID binary"),
        ],
        attack_chain=[
            "Low-privilege user",
            "↓",
            "LD_PRELOAD is set globally",
            "↓",
            "SUID binary identified",
            "↓",
            "Compile malicious shared library",
            "↓",
            "SUID binary loads malicious library",
            "↓",
            "Privilege escalation to binary owner (root)",
        ],
        remediation="Unset LD_PRELOAD in privileged contexts. Remove unnecessary SUID binaries.",
        mitre_attack=["T1574.001 - Hijack Execution Flow", "T1548.001 - Abuse Elevation Control: Setuid"],
        cwe="CWE-114: Process Control",
        cis_controls=["CIS Control 4: Secure Configuration"],
        exploitability_bonus=10,
    ),
    # --- Auth chain 7: weak password hash + shadow exposure → Offline cracking ---
    CorrelationRule(
        rule_id="AP-AUTH-007",
        title="Weak password hashes + Exposed shadow → Credential compromise",
        description="User accounts use weak password hashing (MD5/DES) and /etc/shadow has "
        "incorrect permissions, enabling offline password cracking attacks.",
        attack_type="credential_exposure",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="Weak password hash for user"),
            FindingMatcher(title_contains="Incorrect permissions on /etc/shadow"),
        ],
        attack_chain=[
            "Attacker with low-privilege access",
            "↓",
            "/etc/shadow is world-readable",
            "↓",
            "Password hashes use weak algorithm (MD5/DES)",
            "↓",
            "Download hashes for offline cracking",
            "↓",
            "Passwords cracked at high speed",
            "↓",
            "Credential compromise (may lead to lateral movement)",
        ],
        remediation="Fix /etc/shadow permissions (chmod 0). Force password changes to upgrade hash.",
        mitre_attack=["T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow"],
        cwe="CWE-328: Use of Weak Hash",
        cis_controls=["CIS Control 3: Data Protection"],
        credential_bonus=15,
        exploitability_bonus=10,
    ),
    # --- Auth chain 8: writable polkit rules + passwordless sudo → Full system compromise ---
    CorrelationRule(
        rule_id="AP-AUTH-008",
        title="Writable polkit rules + NOPASSWD sudo → Full system compromise",
        description="Polkit rule files are world-writable and users have passwordless sudo access, "
        "allowing an attacker to create persistent privileged access via both mechanisms.",
        attack_type="privilege_escalation",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="Writable polkit rule file"),
            FindingMatcher(title_contains="NOPASSWD sudo"),
        ],
        attack_chain=[
            "Attacker with local access",
            "↓",
            "Polkit rules are world-writable",
            "↓",
            "Modify polkit rules to grant admin access without auth",
            "↓",
            "Use passwordless sudo for immediate root access",
            "↓",
            "Persistent root access via polkit + sudo",
        ],
        remediation="Restrict polkit file permissions. Remove NOPASSWD sudo rules.",
        cis_controls=["CIS Control 5: Account Management", "CIS Control 4: Secure Configuration"],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        persistence_bonus=15,
        exploitability_bonus=15,
    ),
    # --- Exploitation chain 1: disabled ASLR + weak sysctl ---
    CorrelationRule(
        rule_id="AP-EXPLOIT-001",
        title="Disabled ASLR + Weak sysctl values → Exploit mitigation bypass",
        description="ASLR is disabled and other sysctl security settings are weak, "
        "making memory corruption exploits significantly more reliable.",
        attack_type="exploitation",
        severity="medium",
        required_findings=[
            FindingMatcher(title_contains="ASLR is disabled"),
        ],
        optional_findings=[
            FindingMatcher(title_contains="expected", source_stage="kernel", category="security_control"),
        ],
        attack_chain=[
            "Attacker",
            "↓",
            "ASLR disabled — predictable memory layout",
            "↓",
            "Weak sysctl values — reduced exploit mitigations",
            "↓",
            "Memory corruption exploit succeeds reliably",
        ],
        remediation="Enable ASLR: kernel.randomize_va_space=2. Harden sysctl settings per CIS benchmarks.",
        mitre_attack=["T1068 - Exploitation for Privilege Escalation"],
        cwe="CWE-754: Improper Check for Unusual or Exceptional Conditions",
        cis_controls=["CIS Control 4: Secure Configuration"],
        exploitability_bonus=8,
    ),
    # --- Credential exposure chain 1: sensitive env vars + writable PATH ---
    CorrelationRule(
        rule_id="AP-CRED-001",
        title="Sensitive env variables + Writable PATH → Credential capture",
        description="Sensitive environment variables (API keys, tokens, passwords) are exposed "
        "and world-writable PATH entries allow an attacker to capture them via a modified executable.",
        attack_type="credential_exposure",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="Sensitive env variable:"),
            FindingMatcher(title_contains="Writable PATH entries"),
        ],
        attack_chain=[
            "Attacker with low-privilege access",
            "↓",
            "Writable PATH directory identified",
            "↓",
            "Place credential-stealing binary in writable PATH",
            "↓",
            "Wait for privileged user to execute affected command",
            "↓",
            "Credentials captured from environment",
        ],
        remediation="Remove sensitive data from environment variables. Fix world-writable PATH directories.",
        mitre_attack=["T1552.001 - Unsecured Credentials: Credentials In Files"],
        cwe="CWE-200: Exposure of Sensitive Information",
        cis_controls=["CIS Control 3: Data Protection"],
        credential_bonus=12,
        persistence_bonus=5,
    ),
    # --- Lateral movement chain 4: private keys + SSH ---
    CorrelationRule(
        rule_id="AP-LM-004",
        title="Private keys found + SSH → Lateral movement",
        description="Private key files discovered on the filesystem can be used to "
        "authenticate to other systems via SSH, enabling lateral movement.",
        attack_type="lateral_movement",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="private-key:"),
        ],
        optional_findings=[
            FindingMatcher(title_contains="SSH key found"),
        ],
        attack_chain=[
            "Attacker",
            "↓",
            "Discover private key files",
            "↓",
            "Identify target hosts from key metadata / known_hosts",
            "↓",
            "SSH to remote systems using discovered keys",
            "↓",
            "Lateral movement achieved",
        ],
        remediation="Rotate all exposed keys. Use ssh-keygen -p to add passphrases. Audit key file permissions.",
        mitre_attack=["T1552.004 - Unsecured Credentials: Private Keys", "T1021.004 - Remote Services: SSH"],
        cwe="CWE-312: Cleartext Storage of Sensitive Information",
        cis_controls=["CIS Control 3: Data Protection"],
        credential_bonus=10,
        exploitability_bonus=8,
    ),
    # --- Privilege Escalation chain 6: writable dirs + SUID ---
    CorrelationRule(
        rule_id="AP-PE-006",
        title="World-writable directories + SUID binaries → Privilege escalation",
        description="World-writable directories combined with SUID binaries allow an attacker "
        "to place a malicious library or executable that gets loaded by a SUID binary.",
        attack_type="privilege_escalation",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="Writable system directories"),
            FindingMatcher(title_contains="SUID binary"),
        ],
        attack_chain=[
            "User",
            "↓",
            "World-writable system directory identified",
            "↓",
            "SUID binary that loads from writable path identified",
            "↓",
            "Inject malicious shared library / binary",
            "↓",
            "SUID binary executes payload as root",
            "↓",
            "Root shell",
        ],
        remediation="Restrict permissions on writable system directories. Review SUID binaries.",
        mitre_attack=[
            "T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid",
            "T1574.001 - Hijack Execution Flow",
        ],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        cis_controls=["CIS Control 4: Secure Configuration"],
        exploitability_bonus=8,
    ),
    # --- Vulnerability + SSH: OpenSSH CVE + password auth → Remote root compromise ---
    CorrelationRule(
        rule_id="AP-VULN-SSH-001",
        title="OpenSSH CVE + PasswordAuthentication → Remote root compromise",
        description="A known vulnerability in OpenSSH combined with password authentication "
        "and root login enabled creates a high-risk remote compromise path.",
        attack_type="lateral_movement",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="CVE-", source_stage="vuln_intel"),
            FindingMatcher(title_contains="SSH password authentication is enabled"),
            FindingMatcher(title_contains="SSH root login is permitted"),
        ],
        attack_chain=[
            "External attacker",
            "↓",
            "OpenSSH vulnerability (CVE) identified",
            "↓",
            "Password authentication + root login enabled",
            "↓",
            "Exploit CVE or brute-force credentials",
            "↓",
            "Remote root compromise",
        ],
        remediation="Patch OpenSSH, set PermitRootLogin no, disable PasswordAuthentication.",
        mitre_attack=["T1021.004 - Remote Services: SSH", "T1190 - Exploit Public-Facing Application"],
        cwe="CWE-1104: Use of Unmaintained Third-Party Components",
        exploitability_bonus=15,
        credential_bonus=10,
    ),
    # --- Vulnerability + Docker: Docker CVE + writable socket → Host compromise ---
    CorrelationRule(
        rule_id="AP-VULN-DOCKER-001",
        title="Docker CVE + World-writable socket → Host compromise",
        description="A known Docker engine vulnerability combined with a world-writable "
        "Docker socket allows complete host compromise.",
        attack_type="container_escape",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="CVE-", source_stage="vuln_intel"),
            FindingMatcher(title_contains="Docker socket is world-writable"),
        ],
        attack_chain=[
            "Attacker with low-privilege access",
            "↓",
            "Docker engine CVE identified",
            "↓",
            "World-writable Docker socket",
            "↓",
            "Exploit CVE to escape container or execute privileged containers",
            "↓",
            "Host root compromise",
        ],
        remediation="Patch Docker engine, restrict Docker socket permissions.",
        mitre_attack=["T1611 - Escape to Host"],
        cwe="CWE-1104: Use of Unmaintained Third-Party Components",
        exploitability_bonus=15,
        gtfo_bonus=5,
    ),
    # --- Vulnerability + Kernel: Kernel CVE + capabilities → Privilege escalation ---
    CorrelationRule(
        rule_id="AP-VULN-KERNEL-001",
        title="Kernel CVE + Dangerous capabilities → Privilege escalation",
        description="A known kernel vulnerability combined with dangerous Linux "
        "capabilities allows local privilege escalation to root.",
        attack_type="privilege_escalation",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="CVE-", source_stage="vuln_intel"),
            FindingMatcher(title_contains="Capability:"),
        ],
        attack_chain=[
            "Low-privilege user",
            "↓",
            "Vulnerable kernel identified (CVE)",
            "↓",
            "Dangerous capability on binary",
            "↓",
            "Exploit kernel CVE with capability",
            "↓",
            "Root shell",
        ],
        remediation="Apply kernel patches, remove unnecessary capabilities.",
        mitre_attack=["T1068 - Exploitation for Privilege Escalation"],
        cwe="CWE-1104: Use of Unmaintained Third-Party Components",
        exploitability_bonus=15,
        gtfo_bonus=10,
    ),
    # --- Vulnerability + Secrets: CVE + exposed credentials → Full compromise ---
    CorrelationRule(
        rule_id="AP-VULN-CRED-001",
        title="Software CVE + Exposed credentials → Full system compromise",
        description="A vulnerable software package combined with exposed credentials "
        "creates a direct path to full system compromise.",
        attack_type="exploitation",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="CVE-", source_stage="vuln_intel"),
            FindingMatcher(title_contains="SSH key found", source_stage="secrets"),
        ],
        optional_findings=[
            FindingMatcher(title_contains="Credentials in config:"),
            FindingMatcher(title_contains=".env file found"),
        ],
        attack_chain=[
            "Attacker",
            "↓",
            "Vulnerable software identified (CVE)",
            "↓",
            "Exposed credentials discovered",
            "↓",
            "Exploit CVE and use credentials for lateral movement",
            "↓",
            "Full system compromise",
        ],
        remediation="Patch vulnerable software, rotate all exposed credentials, use secrets manager.",
        mitre_attack=["T1190 - Exploit Public-Facing Application", "T1552 - Unsecured Credentials"],
        cwe="CWE-1104: Use of Unmaintained Third-Party Components",
        exploitability_bonus=15,
        credential_bonus=15,
    ),
    # --- Supply Chain / Outdated package correlation 1: OpenSSH ---
    CorrelationRule(
        rule_id="AP-PKG-001",
        title="Outdated OpenSSH + SSH service enabled → Remote code execution",
        description="The installed OpenSSH package is outdated/vulnerable and the SSH service is enabled on the target, allowing remote exploitation.",
        attack_type="lateral_movement",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="openssh-server", source_stage="packages_security"),
            FindingMatcher(title_contains="SSH service is active", source_stage="services"),
        ],
        attack_chain=[
            "External attacker",
            "↓",
            "SSH service is active",
            "↓",
            "Outdated OpenSSH server installed",
            "↓",
            "Target is vulnerable to remote exploit (e.g. regreSSHion)",
            "↓",
            "Remote Code Execution (Root compromised)",
        ],
        remediation="Upgrade the openssh-server package to the latest secure version.",
        mitre_attack=["T1190 - Exploit Public-Facing Application", "T1021.004 - Remote Services: SSH"],
        cwe="CWE-1395: Dependency on Vulnerable Third-Party Component",
        cis_controls=["CIS Control 2: Inventory and Control of Software Assets"],
        exploitability_bonus=12,
    ),
    # --- Supply Chain / Outdated package correlation 2: Sudo ---
    CorrelationRule(
        rule_id="AP-PKG-002",
        title="Outdated Sudo + Sudo configured → Privilege escalation",
        description="An outdated/vulnerable sudo package is installed and sudo rules are configured, allowing local users to escalate privileges.",
        attack_type="privilege_escalation",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="sudo", source_stage="packages_security"),
            FindingMatcher(title_contains="sudo is available", source_stage="sudo"),
        ],
        attack_chain=[
            "Low-privilege user",
            "↓",
            "Sudo binary is available",
            "↓",
            "Outdated/vulnerable sudo version installed",
            "↓",
            "Exploit local sudo vulnerability (e.g. Baron Samedit)",
            "↓",
            "Privilege escalation to Root",
        ],
        remediation="Upgrade the sudo package to the latest secure version.",
        mitre_attack=["T1068 - Exploitation for Privilege Escalation", "T1548.003 - Abuse Elevation Control Mechanism: Sudo"],
        cwe="CWE-250: Execution with Unnecessary Privileges",
        cis_controls=["CIS Control 5: Account Management"],
        exploitability_bonus=12,
    ),
    # --- Supply Chain / Outdated package correlation 3: Kernel ---
    CorrelationRule(
        rule_id="AP-PKG-003",
        title="Vulnerable Kernel package + Running kernel mismatch → Kernel exploit",
        description="A vulnerable kernel package is installed but the running kernel version mismatch indicates the system has not been rebooted or is using an outdated kernel.",
        attack_type="privilege_escalation",
        severity="medium",
        required_findings=[
            FindingMatcher(title_contains="kernel", source_stage="packages_security"),
            FindingMatcher(title_contains="Kernel version mismatch", source_stage="kernel"),
        ],
        attack_chain=[
            "Low-privilege user",
            "↓",
            "Vulnerable kernel package installed",
            "↓",
            "Running kernel mismatch / reboot pending",
            "↓",
            "Kernel privilege escalation exploit",
            "↓",
            "Full host compromise",
        ],
        remediation="Reboot the system to load the updated kernel version and ensure no outdated kernels are active.",
        mitre_attack=["T1068 - Exploitation for Privilege Escalation"],
        cwe="CWE-1395: Dependency on Vulnerable Third-Party Component",
        cis_controls=["CIS Control 2: Inventory and Control of Software Assets"],
        exploitability_bonus=8,
    ),
    # --- Supply Chain / Outdated package correlation 4: Exposed Service ---
    CorrelationRule(
        rule_id="AP-PKG-004",
        title="Vulnerable package + Exposed service → Remote compromise",
        description="A vulnerable package (e.g. web server, database) is installed and the corresponding network service is exposed.",
        attack_type="lateral_movement",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="openssl", source_stage="packages_security"),
            FindingMatcher(title_contains="service is active", source_stage="services"),
        ],
        attack_chain=[
            "External attacker",
            "↓",
            "Exposed network service active",
            "↓",
            "Service runs a vulnerable software package",
            "↓",
            "Exploit service vulnerability",
            "↓",
            "Service compromise",
        ],
        remediation="Upgrade the vulnerable package and verify firewall restrictions on the exposed service.",
        mitre_attack=["T1190 - Exploit Public-Facing Application"],
        cwe="CWE-1395: Dependency on Vulnerable Third-Party Component",
        cis_controls=["CIS Control 2: Inventory and Control of Software Assets"],
        exploitability_bonus=10,
    ),
    # --- Network / Service Correlation 1: Exposed database + weak auth ---
    CorrelationRule(
        rule_id="AP-NET-001",
        title="Exposed database + weak/no password → Database compromise",
        description="A database service is listening on all interfaces and weak/no password rules are configured, permitting remote database compromise.",
        attack_type="lateral_movement",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="Exposed database service:", source_stage="network_security"),
            FindingMatcher(title_contains="password", source_stage="auth_security"),
        ],
        attack_chain=[
            "External attacker",
            "↓",
            "Exposed database service identified",
            "↓",
            "Weak password policy/rules configured",
            "↓",
            "Remote brute-force or credential guessing",
            "↓",
            "Database compromise",
        ],
        remediation="Bind database to localhost or configure strict firewall rules, and enforce strong authentication rules.",
        mitre_attack=["T1190 - Exploit Public-Facing Application", "T1110 - Brute Force"],
        cwe="CWE-306: Missing Authentication for Critical Function",
        cis_controls=["CIS Control 4: Secure Configuration"],
        credential_bonus=15,
    ),
    # --- Network / Service Correlation 2: SSH + password login ---
    CorrelationRule(
        rule_id="AP-NET-002",
        title="Exposed SSH + Password login enabled → SSH brute force",
        description="SSH service is exposed publicly and password authentication is enabled instead of forcing SSH keys, raising risk of SSH brute forcing.",
        attack_type="lateral_movement",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="Exposed remote service: SSH", source_stage="network_security"),
            FindingMatcher(title_contains="PasswordAuthentication", source_stage="ssh"),
        ],
        attack_chain=[
            "External attacker",
            "↓",
            "Exposed SSH port",
            "↓",
            "Password authentication is enabled",
            "↓",
            "Brute-force password guessing",
            "↓",
            "System access",
        ],
        remediation="Disable PasswordAuthentication in /etc/ssh/sshd_config and require SSH key-based authentication.",
        mitre_attack=["T1021.004 - Remote Services: SSH", "T1110.001 - Brute Force: Password Guessing"],
        cwe="CWE-287: Improper Authentication",
        cis_controls=["CIS Control 5: Account Management"],
        exploitability_bonus=12,
    ),
    # --- Network / Service Correlation 3: Firewall disabled + exposed service ---
    CorrelationRule(
        rule_id="AP-NET-003",
        title="Disabled Firewall + Exposed service → Direct network compromise",
        description="No active firewall configuration detected while one or more sensitive services are exposed, enabling direct connections from arbitrary network hosts.",
        attack_type="lateral_movement",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="Firewall is disabled or has no rules", source_stage="network_security"),
            FindingMatcher(title_contains="Exposed", source_stage="network_security"),
        ],
        attack_chain=[
            "External attacker",
            "↓",
            "Host has disabled/inactive firewall",
            "↓",
            "Service exposed to wildcard bind",
            "↓",
            "Direct network access and connection",
            "↓",
            "Host exploitation",
        ],
        remediation="Enable local firewall (e.g. UFW, Firewalld) and define inbound filter policies.",
        mitre_attack=["T1190 - Exploit Public-Facing Application"],
        cwe="CWE-284: Improper Access Control",
        cis_controls=["CIS Control 4: Secure Configuration"],
        exploitability_bonus=10,
    ),
    # --- Boot Security Correlation 1: Insecure boot + disabled MAC ---
    CorrelationRule(
        rule_id="AP-BOOT-001",
        title="Insecure Boot + Disabled MAC → Full system compromise",
        description="The system is booted without Secure Boot and Mandatory Access Controls (SELinux/AppArmor) are disabled in boot parameters, permitting rootkits and bootkits to run with no confinement.",
        attack_type="root_compromise",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="Secure Boot", source_stage="boot_security"),
            FindingMatcher(title_contains="disabled in kernel boot parameters", source_stage="boot_security"),
        ],
        attack_chain=[
            "Attacker with local/root privileges",
            "↓",
            "Secure Boot is inactive or bypassed",
            "↓",
            "Mandatory Access Controls are disabled via kernel arguments",
            "↓",
            "Load unsigned kernel modules or tamper with system binaries",
            "↓",
            "Persistent kernel-level rootkit execution",
        ],
        remediation="Enable UEFI Secure Boot and enforce SELinux/AppArmor MAC enforcement.",
        mitre_attack=["T1542.001 - Pre-OS Boot: System Firmware", "T1562.001 - Impair Defenses: Disable or Modify Tools"],
        cwe="CWE-284: Improper Access Control",
        cis_controls=["CIS Control 4: Secure Configuration"],
        exploitability_bonus=15,
    ),
    # --- Boot Security Correlation 2: Writable GRUB + root compromise ---
    CorrelationRule(
        rule_id="AP-BOOT-002",
        title="Writable GRUB config + World-writable boot files → Bootloader persistence",
        description="GRUB configurations or files in /boot are world-writable or have loose permissions, allowing local attackers to modify boot configuration to inject malware or gain root shell persistence.",
        attack_type="persistence",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="GRUB configuration file permissions are too open", source_stage="boot_security"),
            FindingMatcher(title_contains="World-writable files detected in /boot", source_stage="boot_security"),
        ],
        attack_chain=[
            "Low-privilege local user",
            "↓",
            "GRUB config file has permissive write access",
            "↓",
            "Overwrite /boot configuration with custom init parameter (e.g. init=/bin/sh)",
            "↓",
            "Reboot system",
            "↓",
            "System boots directly into unauthenticated root shell",
        ],
        remediation="Secure /boot directory permissions (chmod 700 /boot) and make GRUB configuration root-only writable.",
        mitre_attack=["T1542.003 - Pre-OS Boot: Bootkit", "T1222.002 - File and Directory Permissions Modification: Linux File and Directory Permissions Modification"],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        cis_controls=["CIS Control 4: Secure Configuration"],
        persistence_bonus=15,
    ),
    # --- Boot Security Correlation 3: Disabled Secure Boot + Unsigned RPM packages ---
    CorrelationRule(
        rule_id="AP-BOOT-003",
        title="Disabled Secure Boot + Unsigned Packages → Boot integrity bypass",
        description="Secure Boot is disabled and unsigned packages or modules are present, allowing the bootloader to load untrusted drivers or components.",
        attack_type="root_compromise",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="UEFI Secure Boot is disabled", source_stage="boot_security"),
            FindingMatcher(title_contains="Unsigned", source_stage="packages_security"),
        ],
        attack_chain=[
            "Attacker",
            "↓",
            "Secure Boot verification is disabled",
            "↓",
            "Install unsigned or untrusted RPM/kernel modules",
            "↓",
            "Unsigned driver executes in Ring 0",
            "↓",
            "Complete host compromise",
        ],
        remediation="Enable UEFI Secure Boot and enforce module signature verification.",
        mitre_attack=["T1542 - Pre-OS Boot", "T1072 - Software Deployment"],
        cwe="CWE-347: Improper Verification of Cryptographic Signature",
        cis_controls=["CIS Control 2: Inventory and Control of Software Assets"],
        exploitability_bonus=12,
    ),
    # --- GUI / Session Correlation 1: Auto-login + Exposed Remote Desktop ---
    CorrelationRule(
        rule_id="AP-GUI-001",
        title="Display autologin + Exposed Remote Desktop → Session takeover",
        description="Automatic user login is enabled at boot time and a remote desktop server is active/exposed, allowing remote attackers to hijack the active GUI session without authentication.",
        attack_type="lateral_movement",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="automatic login", source_stage="gui_security"),
            FindingMatcher(title_contains="VNC server", source_stage="gui_security"),
        ],
        attack_chain=[
            "External attacker",
            "↓",
            "Remote Desktop (VNC) is active",
            "↓",
            "Display manager automatically logs in a default user session",
            "↓",
            "Attacker connects to VNC port",
            "↓",
            "Direct graphical session takeover as default user",
        ],
        remediation="Disable GDM/LightDM/SDDM automatic logins and enforce secure RDP or tunneled VNC authentication.",
        mitre_attack=["T1021.005 - Remote Services: VNC", "T1563 - Remote Service Session Hijacking"],
        cwe="CWE-306: Missing Authentication for Critical Function",
        cis_controls=["CIS Control 4: Secure Configuration"],
        credential_bonus=15,
    ),
    # --- GUI / Session Correlation 2: X11 windowing + passwordless privilege escalation ---
    CorrelationRule(
        rule_id="AP-GUI-002",
        title="Legacy X11 + Polkit override → Local privilege escalation",
        description="Legacy X11 server is running with no graphical boundary containment and a Polkit rule allows passwordless privilege elevation, enabling local GUI sessions to capture keystrokes or run administrative commands.",
        attack_type="privilege_escalation",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="Legacy X11 windowing", source_stage="gui_security"),
            FindingMatcher(title_contains="Polkit rule", source_stage="gui_security"),
        ],
        attack_chain=[
            "Local unprivileged program/attacker",
            "↓",
            "Legacy X11 windowing system active",
            "↓",
            "Polkit rule allows passwordless privilege escalation",
            "↓",
            "Inject inputs or abuse passwordless polkit authorizations",
            "↓",
            "Administrative privilege escalation (Root shell)",
        ],
        remediation="Migrate from X11 to Wayland and clean up permissive Polkit policy rules.",
        mitre_attack=["T1059 - Command and Scripting Interpreter", "T1068 - Exploitation for Privilege Escalation"],
        cwe="CWE-250: Execution with Unnecessary Privileges",
        cis_controls=["CIS Control 5: Account Management"],
        exploitability_bonus=10,
    ),
    # --- Filesystem / Storage Correlation 1: Writable PATH + SUID binary ---
    CorrelationRule(
        rule_id="AP-FS-001",
        title="Writable PATH + SUID/SGID files → Local Privilege Escalation",
        description="The user environment has writable directories in the execution PATH, and SUID/SGID binaries are present. Local attackers can place spoofed binaries in the writable PATH to hijack SUID execution flows.",
        attack_type="privilege_escalation",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="Writable PATH", source_stage="privilege_escalation"),
            FindingMatcher(title_contains="SUID/SGID", source_stage="storage_security"),
        ],
        attack_chain=[
            "Local unprivileged user",
            "↓",
            "Environment PATH includes a directory writable by the current user",
            "↓",
            "Place a Trojan executable (e.g. cat, ls) in the writable PATH directory",
            "↓",
            "SUID binary executes and invokes the hijacked command name without absolute path",
            "↓",
            "Trojan executes with elevated SUID privileges",
            "↓",
            "Host compromise",
        ],
        remediation="Ensure PATH only contains directories owned and writable exclusively by root.",
        mitre_attack=["T1574.007 - Hijack Execution Flow: Path Privilege Escalation", "T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid"],
        cwe="CWE-427: Uncontrolled Search Path Element",
        cis_controls=["CIS Control 4: Secure Configuration"],
        exploitability_bonus=12,
    ),
    # --- Filesystem / Storage Correlation 2: Open shadow/passwd + SUID ---
    CorrelationRule(
        rule_id="AP-FS-002",
        title="Loose sensitive file permissions + SUID binary → Root compromise",
        description="The system passwd or shadow file has insecure write or read access, and SUID binaries are present, creating multiple avenues for a local user to hijack system authorization settings or credentials to escalate to root.",
        attack_type="root_compromise",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="permissions are too open", source_stage="storage_security"),
            FindingMatcher(title_contains="SUID/SGID", source_stage="storage_security"),
        ],
        attack_chain=[
            "Local attacker",
            "↓",
            "Passwd or shadow file permissions are insecurely open",
            "↓",
            "Read password hashes (/etc/shadow) or inject a root-equivalent account (/etc/passwd)",
            "↓",
            "Abuse system SUID helper binaries to verify or enforce the modification",
            "↓",
            "Complete unauthenticated root privilege escalation",
        ],
        remediation="Strictly restrict permissions on /etc/passwd (644) and /etc/shadow (600).",
        mitre_attack=["T1068 - Exploitation for Privilege Escalation", "T1083 - File and Directory Discovery"],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        cis_controls=["CIS Control 4: Secure Configuration"],
        exploitability_bonus=15,
    ),
    # --- Monitoring Correlation 1: auditd disabled + privilege escalation ---
    CorrelationRule(
        rule_id="AP-MON-001",
        title="Disabled auditd + Privilege Escalation → Undetected system takeover",
        description="The kernel-level auditing daemon (auditd) is disabled and privilege escalation vectors are present on the host, enabling attackers to exploit the SUID/PATH vulnerabilities with zero log trail.",
        attack_type="root_compromise",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="auditd", source_stage="monitoring_security"),
            FindingMatcher(title_contains="SUID/SGID", source_stage="storage_security"),
        ],
        attack_chain=[
            "Local attacker",
            "↓",
            "auditd auditing service is disabled/inactive",
            "↓",
            "Exploit SUID/SGID privilege escalation binary",
            "↓",
            "Execute arbitrary system calls as root",
            "↓",
            "Complete root compromise with no kernel audit logs recorded",
        ],
        remediation="Start auditd service and configure restrictive SUID/SGID binary controls.",
        mitre_attack=["T1562.001 - Impair Defenses: Disable or Modify Tools", "T1548.001 - Setuid and Setgid"],
        cwe="CWE-778: Insufficient Logging",
        cis_controls=["CIS Control 8: Audit Log Management"],
        exploitability_bonus=15,
    ),
    # --- Monitoring Correlation 2: syslog forwarding disabled + exposed services ---
    CorrelationRule(
        rule_id="AP-MON-002",
        title="Local-only syslog + Exposed services → Covert exploit targeting",
        description="Logging is restricted to local storage only, and network services are exposed to wildcard binds. Attackers exploiting the services can delete local files to hide active presence.",
        attack_type="lateral_movement",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="syslog", source_stage="monitoring_security"),
            FindingMatcher(title_contains="Exposed", source_stage="network_security"),
        ],
        attack_chain=[
            "Remote attacker",
            "↓",
            "Exposed network service on wildcard bind is scanned",
            "↓",
            "Exploit exposed service to gain initial access",
            "↓",
            "Delete or truncate /var/log/auth.log or syslog files",
            "↓",
            "Local-only syslog architecture ensures no log backups exist remotely",
            "↓",
            "Persistence with zero traces",
        ],
        remediation="Enable centralized log forwarding via Rsyslog/Syslog-ng and lock down service firewall rules.",
        mitre_attack=["T1562.003 - Impair Defenses: Impair Command History Logging", "T1021 - Remote Services"],
        cwe="CWE-778: Insufficient Logging",
        cis_controls=["CIS Control 8: Audit Log Management"],
        exploitability_bonus=10,
    ),
    # --- Cryptographic Correlation 1: weak SSH ciphers + SSH service ---
    CorrelationRule(
        rule_id="AP-CRYPT-001",
        title="Weak SSH Cryptography + Exposed SSH Service → Session hijacking",
        description="SSH server allows weak or legacy ciphers (CBC or 3DES) and is exposed on a public or wildcard bind, leaving active sessions open to cryptographic decryption and man-in-the-middle hijacking.",
        attack_type="lateral_movement",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="SSH Ciphers", source_stage="crypto_security"),
            FindingMatcher(title_contains="Exposed", source_stage="network_security"),
        ],
        attack_chain=[
            "Network attacker",
            "↓",
            "Identify exposed SSH service binding",
            "↓",
            "Initiate connection offering CBC or legacy 3DES ciphers",
            "↓",
            "Target SSH server configuration permits insecure negotiations",
            "↓",
            "Sniff active sessions or perform active injection on the SSH session",
            "↓",
            "Gain unauthorized remote access",
        ],
        remediation="Enforce strong modern ciphers (AES-GCM, ChaCha20-Poly1305) in /etc/ssh/sshd_config.",
        mitre_attack=["T1562 - Impair Defenses", "T1021.004 - SSH"],
        cwe="CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        cis_controls=["CIS Control 3: Data Protection"],
        exploitability_bonus=12,
    ),
    # --- Cryptographic Correlation 2: legacy SSL/TLS + exposed service ---
    CorrelationRule(
        rule_id="AP-CRYPT-002",
        title="Legacy OpenSSL protocols + Exposed service → TLS downgrade",
        description="OpenSSL system config permits insecure legacy protocols, and web or other network services are bound publicly, enabling remote network-level protocol downgrade and session eavesdropping.",
        attack_type="lateral_movement",
        severity="medium",
        required_findings=[
            FindingMatcher(title_contains="OpenSSL configured with legacy TLS/SSL", source_stage="crypto_security"),
            FindingMatcher(title_contains="Exposed", source_stage="network_security"),
        ],
        attack_chain=[
            "Network attacker",
            "↓",
            "Discover exposed service requiring TLS transport security",
            "↓",
            "Force TLS handshake negotiation downgrade to TLS 1.0 or SSLv3",
            "↓",
            "OpenSSL configuration allows processing legacy protocols",
            "↓",
            "Decrypt session cookies or sensitive transit parameters",
        ],
        remediation="Enforce MinProtocol TLSv1.2 or TLSv1.3 in system-wide OpenSSL options.",
        mitre_attack=["T1040 - Network Sniffing"],
        cwe="CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        cis_controls=["CIS Control 3: Data Protection"],
        exploitability_bonus=8,
    ),
    # --- Container Correlation 1: docker socket + privilege escalation ---
    CorrelationRule(
        rule_id="AP-CONT-001",
        title="Exposed Docker Socket + Local Sudo Privilege Escalation → Complete escape to host",
        description="The host has an exposed/writable Docker socket or docker group memberships and loose sudo configuration rules, enabling local attackers to leverage Docker to run containers with root privileges on the host.",
        attack_type="root_compromise",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="docker", source_stage="docker"),
            FindingMatcher(title_contains="sudo", source_stage="privilege_escalation"),
        ],
        attack_chain=[
            "Local attacker",
            "↓",
            "Leverage sudo access to run commands",
            "↓",
            "Interact with the exposed Docker socket or docker binary",
            "↓",
            "Start a container mapping the host root filesystem",
            "↓",
            "Achieve unrestricted root privilege escalation on the host",
        ],
        remediation="Strictly limit docker group membership and restrict permissions on /var/run/docker.sock.",
        mitre_attack=["T1611 - Escape to Host", "T1548.003 - Sudo and Sudo Caching"],
        cwe="CWE-250: Execution with Unnecessary Privileges",
        cis_controls=["CIS Control 18: Penetration Testing"],
        exploitability_bonus=20,
    ),
    # --- Container Correlation 2: privileged container + host mount ---
    CorrelationRule(
        rule_id="AP-CONT-002",
        title="Privileged Container + Insecure Host Mounts → Host takeover",
        description="A container runs in privileged mode and the host configuration permits insecure mount operations, facilitating quick escaping to root on the host node.",
        attack_type="root_compromise",
        severity="critical",
        required_findings=[
            FindingMatcher(title_contains="Privileged container", source_stage="docker"),
            FindingMatcher(title_contains="mount options", source_stage="storage_security"),
        ],
        attack_chain=[
            "Container-compromised attacker",
            "↓",
            "Establish shell inside a privileged container",
            "↓",
            "Locate and mount the host disk (/dev/sda or equivalent) inside the container",
            "↓",
            "Write payload to host cron/init script",
            "↓",
            "Execute arbitrary code on the host as root",
        ],
        remediation="Disable privileged container modes. Use specific kernel capabilities instead.",
        mitre_attack=["T1611 - Escape to Host"],
        cwe="CWE-269: Improper Privilege Management",
        cis_controls=["CIS Control 18: Penetration Testing"],
        exploitability_bonus=18,
    ),
    # --- Container Correlation 3: CAP_SYS_ADMIN + host namespace ---
    CorrelationRule(
        rule_id="AP-CONT-003",
        title="LSM disabled + SUID binary presence → Sandbox escape",
        description="Neither AppArmor nor SELinux is active (disabling mandatory security controls), and SUID/SGID helper binaries are present on the host, exposing namespaces to manipulation.",
        attack_type="root_compromise",
        severity="high",
        required_findings=[
            FindingMatcher(title_contains="No active Linux Security Module", source_stage="container_security"),
            FindingMatcher(title_contains="SUID/SGID", source_stage="storage_security"),
        ],
        attack_chain=[
            "Unprivileged local user",
            "↓",
            "No active LSM (SELinux/AppArmor) profiles enforce host boundaries",
            "↓",
            "Run vulnerable SUID binary using host namespaces",
            "↓",
            "Perform sandbox escape or local root privilege escalation",
        ],
        remediation="Enable SELinux or AppArmor and audit SUID binaries.",
        mitre_attack=["T1611 - Escape to Host", "T1548.001 - Setuid and Setgid"],
        cwe="CWE-250: Execution with Unnecessary Privileges",
        cis_controls=["CIS Control 18: Penetration Testing"],
        exploitability_bonus=15,
    ),
]


# ---------------------------------------------------------------------------
#  Risk scoring
# ---------------------------------------------------------------------------


def _compute_risk_score(
    severity: str,
    confidence: float,
    matched_count: int,
    has_gtfo: bool,
    has_exploitability_bonus: bool,
    has_credential_bonus: bool,
    has_persistence_bonus: bool,
    rule_bonuses: dict[str, float] | None = None,
) -> float:
    """Compute a 0-100 risk score for an attack path."""
    base = _SEVERITY_WEIGHTS.get(severity, 45)
    score = base
    score += confidence * 15  # 0-15 points from confidence
    score += min(matched_count * 3, 10)  # 0-10 points for supporting findings

    if has_gtfo:
        score += 10
    if has_exploitability_bonus:
        score += 8
    if has_credential_bonus:
        score += 8
    if has_persistence_bonus:
        score += 6

    if rule_bonuses:
        score += rule_bonuses.get("gtfo_bonus", 0)
        score += rule_bonuses.get("exploitability_bonus", 0)
        score += rule_bonuses.get("credential_bonus", 0)
        score += rule_bonuses.get("persistence_bonus", 0)

    return min(max(score, 0), 100)


# ---------------------------------------------------------------------------
#  Correlation Engine
# ---------------------------------------------------------------------------


class CorrelationEngine:
    """Correlates findings into attack paths using correlation rules.

    Usage::

        engine = CorrelationEngine()
        paths = engine.run(enriched_findings)
    """

    def __init__(self, rules: list[CorrelationRule] | None = None) -> None:
        self._rules = _CORRELATION_RULES if rules is None else rules

    def run(self, findings: Sequence[Finding | EnrichedFinding]) -> list[AttackPath]:
        """Correlate a list of (enriched) findings into attack paths."""
        paths: list[AttackPath] = []
        used_path_ids: set[str] = set()

        for rule in self._rules:
            matched, optional_matched = self._match_rule(rule, findings)
            if not self._all_required_matched(rule, matched):
                continue

            path = self._build_path(rule, matched, optional_matched, findings)
            if path.id in used_path_ids:
                continue
            used_path_ids.add(path.id)
            paths.append(path)

        return paths

    def _match_rule(
        self,
        rule: CorrelationRule,
        findings: Sequence[Finding | EnrichedFinding],
    ) -> tuple[dict[int, list[Finding]], dict[int, list[Finding]]]:
        """Match a rule's required and optional patterns against findings.

        Returns ``(required_matches, optional_matches)`` as dicts mapping
        matcher index to list of matching findings.
        """
        required_matches: dict[int, list[Finding]] = {}
        for idx, matcher in enumerate(rule.required_findings):
            matches = [f for f in findings if self._finding_matches(matcher, f)]
            if matches:
                required_matches[idx] = cast(list[Finding], matches)

        optional_matches: dict[int, list[Finding]] = {}
        for idx, matcher in enumerate(rule.optional_findings):
            matches = [f for f in findings if self._finding_matches(matcher, f)]
            if matches:
                optional_matches[idx] = cast(list[Finding], matches)

        return required_matches, optional_matches

    @staticmethod
    def _finding_matches(matcher: FindingMatcher, finding: Finding | EnrichedFinding) -> bool:
        """Check if a single finding matches a FindingMatcher."""
        if matcher.title_contains and matcher.title_contains.lower() not in finding.title.lower():
            return False
        if matcher.source_stage and finding.source_stage.lower() != matcher.source_stage.lower():
            return False
        if matcher.category and finding.category.lower() != matcher.category.lower():
            return False
        if matcher.severity_min:
            min_key = severity_key(matcher.severity_min)
            f_key = severity_key(finding.severity)
            if f_key < min_key:
                return False
        return True

    @staticmethod
    def _all_required_matched(rule: CorrelationRule, matched: dict[int, list[Finding]]) -> bool:
        """Check that every required matcher has at least one finding."""
        return len(matched) == len(rule.required_findings)

    @staticmethod
    def _collect_matched_findings(
        required_matches: dict[int, list[Finding]],
        optional_matches: dict[int, list[Finding]],
    ) -> list[Finding]:
        """Gather all matched findings (required + optional) without duplicates."""
        seen_ids: set[str] = set()
        all_findings: list[Finding] = []
        for flist in required_matches.values():
            for f in flist:
                if f.id not in seen_ids:
                    seen_ids.add(f.id)
                    all_findings.append(f)
        for flist in optional_matches.values():
            for f in flist:
                if f.id not in seen_ids:
                    seen_ids.add(f.id)
                    all_findings.append(f)
        return all_findings

    @staticmethod
    def _compute_average_confidence(findings: list[Finding]) -> float:
        """Compute the average confidence across findings."""
        confidences: list[float] = []
        for f in findings:
            if hasattr(f, "confidence_score") and f.confidence_score:
                confidences.append(f.confidence_score)
            elif f.confidence is not None:
                confidences.append(f.confidence)
        return sum(confidences) / len(confidences) if confidences else 0.5

    @staticmethod
    def _check_attack_indicators(
        findings: list[Finding],
    ) -> tuple[bool, bool, bool, bool]:
        """Check for GTFOBins, exploitability, credential, and persistence indicators."""
        has_gtfo = any(hasattr(f, "gtfo_bins") and f.gtfo_bins for f in findings)
        has_exploit = any(hasattr(f, "mitre_attack") and f.mitre_attack for f in findings)
        has_cred = any(
            hasattr(f, "enriched_tags") and any(t in {"credential", "secret", "password"} for t in f.enriched_tags)
            for f in findings
        )
        has_persist = any(
            hasattr(f, "enriched_tags") and any(t in {"persistence", "cron", "systemd"} for t in f.enriched_tags)
            for f in findings
        )
        return has_gtfo, has_exploit, has_cred, has_persist

    @staticmethod
    def _build_evidence_str(findings: list[Finding]) -> str:
        """Build a newline-separated evidence string from matched findings."""
        parts = [f"{f.title} [{f.source_stage}]" for f in findings]
        return "\n".join(parts) if parts else ""

    @staticmethod
    def _get_target_str(findings: list[Finding]) -> str:
        """Derive a single target string from matched findings."""
        targets = {f.target for f in findings if f.target}
        return next(iter(targets)) if targets else "localhost"

    def _build_path(
        self,
        rule: CorrelationRule,
        required_matches: dict[int, list[Finding]],
        optional_matches: dict[int, list[Finding]],
        _all_findings: Sequence[Finding | EnrichedFinding],
    ) -> AttackPath:
        """Build an AttackPath from matched findings."""
        all_matched_findings = self._collect_matched_findings(required_matches, optional_matches)
        total_matched = len(all_matched_findings)
        avg_confidence = self._compute_average_confidence(all_matched_findings)
        has_gtfo, has_exploit, has_cred, has_persist = self._check_attack_indicators(all_matched_findings)
        evidence = self._build_evidence_str(all_matched_findings)
        target_str = self._get_target_str(all_matched_findings)

        rule_bonuses = {
            "gtfo_bonus": rule.gtfo_bonus,
            "exploitability_bonus": rule.exploitability_bonus,
            "credential_bonus": rule.credential_bonus,
            "persistence_bonus": rule.persistence_bonus,
        }

        score = _compute_risk_score(
            severity=rule.severity,
            confidence=avg_confidence,
            matched_count=total_matched,
            has_gtfo=has_gtfo,
            has_exploitability_bonus=has_exploit or rule.exploitability_bonus > 0,
            has_credential_bonus=has_cred or rule.credential_bonus > 0,
            has_persistence_bonus=has_persist or rule.persistence_bonus > 0,
            rule_bonuses=rule_bonuses,
        )

        return AttackPath(
            id=f"{rule.rule_id}/{target_str}",
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            confidence=round(avg_confidence, 2),
            likelihood=round(min(avg_confidence + 0.1, 1.0), 2),
            impact=_SEVERITY_WEIGHTS.get(rule.severity, 45) / 100,
            score=round(score, 1),
            attack_type=rule.attack_type,
            findings=all_matched_findings,
            explanation=rule.explanation,
            attack_chain=list(rule.attack_chain),
            remediation=rule.remediation,
            references=list(rule.references),
            mitre_attack=list(rule.mitre_attack),
            cwe=rule.cwe,
            cis_controls=list(rule.cis_controls),
            prerequisites=list(rule.prerequisites),
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
#  Correlation statistics
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CorrelationStats:
    """Aggregated statistics over a list of AttackPaths."""

    total_paths: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    highest_severity: str = ""
    highest_score: float = 0.0
    average_confidence: float = 0.0
    critical_chains: int = 0
    high_chains: int = 0
    overall_risk_score: float = 0.0


def compute_correlation_stats(paths: list[AttackPath]) -> CorrelationStats:
    """Produce summary statistics from a list of AttackPaths."""
    if not paths:
        return CorrelationStats(
            by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        )

    sev_counter: dict[str, int] = {}
    total_conf = 0.0
    highest_sev = "info"
    highest_sev_key = 0
    highest_score = 0.0
    critical = 0
    high = 0

    for p in paths:
        sev = p.severity.lower()
        sev_counter[sev] = sev_counter.get(sev, 0) + 1
        total_conf += p.confidence
        sk = severity_key(sev)
        if sk > highest_sev_key:
            highest_sev = sev
            highest_sev_key = sk
        if p.score > highest_score:
            highest_score = p.score
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1

    avg_conf = total_conf / len(paths) if paths else 0.0

    # Overall risk: weighted average across paths
    ordered_sev: dict[str, int] = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        ordered_sev[sev] = sev_counter.get(sev, 0)

    weights_sum = sum(_SEVERITY_WEIGHTS.get(s, 0) * c for s, c in ordered_sev.items())
    total_weighted = sum(ordered_sev.values())
    overall_risk = (weights_sum / (total_weighted * 100) * 100) if total_weighted else 0

    return CorrelationStats(
        total_paths=len(paths),
        by_severity=ordered_sev,
        highest_severity=highest_sev,
        highest_score=round(highest_score, 1),
        average_confidence=round(avg_conf, 2),
        critical_chains=critical,
        high_chains=high,
        overall_risk_score=round(min(overall_risk, 100), 1),
    )


# ---------------------------------------------------------------------------
#  Default engine convenience
# ---------------------------------------------------------------------------

_default_engine = CorrelationEngine()


def correlate(findings: list[Finding]) -> list[AttackPath]:
    """Correlate findings using the default engine."""
    return _default_engine.run(findings)


__all__ = [
    "_CORRELATION_RULES",
    "AttackPath",
    "CorrelationEngine",
    "CorrelationRule",
    "CorrelationStats",
    "FindingMatcher",
    "compute_correlation_stats",
    "correlate",
]
