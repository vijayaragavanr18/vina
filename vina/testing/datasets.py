"""Benchmark datasets and mock feed data for deterministic testing."""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
#  Mock CVE database (subset for benchmark scenarios)
# ---------------------------------------------------------------------------

MOCK_CVES: list[dict[str, Any]] = [
    {
        "cve": "CVE-2024-0001",
        "title": "OpenSSL Buffer Overflow",
        "description": "Buffer overflow in OpenSSL 1.1.1",
        "severity": "critical",
        "cvss_v3": 9.8,
        "cvss_v4": 9.8,
        "epss": 0.95,
        "kev": True,
        "exploited": True,
        "vendor": "openssl",
        "product": "openssl",
        "affected_versions": ["< 1.1.1w"],
        "fixed_versions": ["1.1.1w"],
    },
    {
        "cve": "CVE-2024-0002",
        "title": "sudo Privilege Escalation",
        "description": "Heap overflow in sudo's qualifier parsing",
        "severity": "high",
        "cvss_v3": 7.8,
        "cvss_v4": 7.8,
        "epss": 0.85,
        "kev": False,
        "exploited": True,
        "vendor": "sudo_project",
        "product": "sudo",
        "affected_versions": ["< 1.9.15"],
        "fixed_versions": ["1.9.15"],
    },
    {
        "cve": "CVE-2024-0003",
        "title": "Apache HTTP Server Directory Traversal",
        "description": "Directory traversal in Apache HTTP Server 2.4.x",
        "severity": "high",
        "cvss_v3": 7.5,
        "cvss_v4": 7.5,
        "epss": 0.75,
        "kev": False,
        "exploited": False,
        "vendor": "apache",
        "product": "httpd",
        "affected_versions": ["< 2.4.58"],
        "fixed_versions": ["2.4.58"],
    },
    {
        "cve": "CVE-2024-0004",
        "title": "Linux Kernel Local Privilege Escalation",
        "description": "Use-after-free in Linux kernel's io_uring",
        "severity": "high",
        "cvss_v3": 7.0,
        "cvss_v4": 7.0,
        "epss": 0.65,
        "kev": True,
        "exploited": True,
        "vendor": "linux",
        "product": "linux_kernel",
        "affected_versions": [">= 5.15, < 6.1.76"],
        "fixed_versions": ["6.1.76"],
    },
    {
        "cve": "CVE-2024-0005",
        "title": "Docker Engine Privilege Escalation",
        "description": "Improper access control in Docker Engine",
        "severity": "medium",
        "cvss_v3": 6.5,
        "cvss_v4": 6.5,
        "epss": 0.45,
        "kev": False,
        "exploited": False,
        "vendor": "docker",
        "product": "docker",
        "affected_versions": ["< 24.0.7"],
        "fixed_versions": ["24.0.7"],
    },
    {
        "cve": "CVE-2024-0006",
        "title": "systemd Information Disclosure",
        "description": "Information disclosure via systemd-resolved",
        "severity": "medium",
        "cvss_v3": 5.5,
        "cvss_v4": 5.5,
        "epss": 0.3,
        "kev": False,
        "exploited": False,
        "vendor": "systemd_project",
        "product": "systemd",
        "affected_versions": [">= 248, < 255"],
        "fixed_versions": ["255"],
    },
    {
        "cve": "CVE-2024-0007",
        "title": "Python Standard Library Vulnerability",
        "description": "XML processing vulnerability in Python's xml.etree",
        "severity": "medium",
        "cvss_v3": 5.0,
        "cvss_v4": 5.0,
        "epss": 0.2,
        "kev": False,
        "exploited": False,
        "vendor": "python",
        "product": "python",
        "affected_versions": ["< 3.12.1"],
        "fixed_versions": ["3.12.1"],
    },
    {
        "cve": "CVE-2024-0008",
        "title": "OpenSSH Vulnerability",
        "description": "Double-free in OpenSSH's ssh-agent",
        "severity": "high",
        "cvss_v3": 7.5,
        "cvss_v4": 7.5,
        "epss": 0.6,
        "kev": False,
        "exploited": False,
        "vendor": "openbsd",
        "product": "openssh",
        "affected_versions": ["< 9.6"],
        "fixed_versions": ["9.6"],
    },
    {
        "cve": "CVE-2024-0009",
        "title": "Nginx HTTP Request Smuggling",
        "description": "HTTP request smuggling in nginx",
        "severity": "high",
        "cvss_v3": 7.4,
        "cvss_v4": 7.4,
        "epss": 0.55,
        "kev": False,
        "exploited": False,
        "vendor": "nginx",
        "product": "nginx",
        "affected_versions": ["< 1.25.3"],
        "fixed_versions": ["1.25.3"],
    },
    {
        "cve": "CVE-2024-0010",
        "title": "MySQL Server Buffer Overflow",
        "description": "Buffer overflow in MySQL Server",
        "severity": "high",
        "cvss_v3": 7.2,
        "cvss_v4": 7.2,
        "epss": 0.5,
        "kev": False,
        "exploited": False,
        "vendor": "oracle",
        "product": "mysql",
        "affected_versions": ["< 8.0.36"],
        "fixed_versions": ["8.0.36"],
    },
]

# ---------------------------------------------------------------------------
#  Mock feed responses (for feed manager benchmarks)
# ---------------------------------------------------------------------------

MOCK_NVD_RESPONSE: dict[str, Any] = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-0001",
                "descriptions": [{"lang": "en", "value": "Test CVE 0001"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            }
        },
        {
            "cve": {
                "id": "CVE-2024-0002",
                "descriptions": [{"lang": "en", "value": "Test CVE 0002"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.8, "baseSeverity": "HIGH"}}]},
            }
        },
    ],
    "totalResults": 2,
    "format": "NVD_CVE",
    "version": "2.0",
}

MOCK_CISA_KEV_RESPONSE: dict[str, Any] = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "openssl",
            "product": "openssl",
            "shortDescription": "Test KEV entry",
            "dateAdded": "2024-01-15",
            "dueDate": "2024-07-15",
            "requiredAction": "Apply patch",
        }
    ]
}

MOCK_EPSS_CSV: str = "model_version,score,percentile\ntest_v1,0.95,0.999\n"

MOCK_OSV_RESPONSE: dict[str, Any] = {
    "vulns": [
        {
            "id": "CVE-2024-0001",
            "summary": "Test OSV entry",
            "aliases": ["CVE-2024-0001"],
            "affected": [{"package": {"name": "openssl", "ecosystem": "PyPI"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.1.1w"}]}]}],
        }
    ]
}

MOCK_GITHUB_ADVISORY_RESPONSE: list[dict[str, Any]] = [
    {
        "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
        "summary": "Test GitHub Advisory",
        "description": "A test advisory",
        "severity": "CRITICAL",
        "identifiers": [{"value": "CVE-2024-0001", "type": "CVE"}],
        "published_at": "2024-01-01T00:00:00Z",
        "vulnerabilities": [{"package": {"name": "openssl", "ecosystem": "PyPI"}, "severity": "CRITICAL", "vulnerable_version_range": "< 1.1.1w", "first_patched_version": "1.1.1w"}],
    }
]

# ---------------------------------------------------------------------------
#  Benchmark scenario definitions
# ---------------------------------------------------------------------------

DVWA_SCENARIO: dict[str, Any] = {
    "name": "DVWA (Damn Vulnerable Web Application)",
    "target": "http://localhost:4280",
    "pipeline": "web",
    "expected_findings": [
        {"title_contains": "SQL Injection", "severity": "high"},
        {"title_contains": "Command Injection", "severity": "high"},
        {"title_contains": "File Inclusion", "severity": "medium"},
    ],
    "min_findings": 10,
    "max_runtime_seconds": 300,
}

JUICE_SHOP_SCENARIO: dict[str, Any] = {
    "name": "OWASP Juice Shop",
    "target": "http://localhost:3000",
    "pipeline": "web",
    "expected_findings": [
        {"title_contains": "XSS", "severity": "medium"},
        {"title_contains": "SQL Injection", "severity": "high"},
        {"title_contains": "Broken Authentication", "severity": "high"},
    ],
    "min_findings": 20,
    "max_runtime_seconds": 600,
}

METASPLOITABLE_OS_SCENARIO: dict[str, Any] = {
    "name": "Metasploitable 2 (OS Enumeration)",
    "target": "localhost",
    "pipeline": "os",
    "expected_findings": [
        {"title_contains": "SUID", "severity": "medium"},
        {"title_contains": "NOPASSWD", "severity": "high"},
        {"title_contains": "writable", "severity": "high"},
    ],
    "expected_cves": ["CVE-2024-0002"],
    "expected_attack_paths": [{"title_contains": "Passwordless sudo", "severity": "critical"}],
    "expected_exploitability_min_score": 50,
    "min_findings": 15,
    "max_runtime_seconds": 120,
}


__all__ = [
    "MOCK_CVES",
    "MOCK_NVD_RESPONSE",
    "MOCK_CISA_KEV_RESPONSE",
    "MOCK_EPSS_CSV",
    "MOCK_OSV_RESPONSE",
    "MOCK_GITHUB_ADVISORY_RESPONSE",
    "DVWA_SCENARIO",
    "JUICE_SHOP_SCENARIO",
    "METASPLOITABLE_OS_SCENARIO",
]
