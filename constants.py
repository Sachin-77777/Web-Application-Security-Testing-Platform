# Account roles. "admin" runs the platform, "user" is the security team
# (owns applications, conducts tests) and "client" only submits applications
# and reads the resulting reports.
USER_ROLES = ("admin", "user", "client")

TEST_CATEGORIES = [
    "Injection",
    "Broken Authentication",
    "Sensitive Data Exposure",
    "Broken Access Control",
    "Security Misconfiguration",
    "Cross-Site Scripting (XSS)",
    "Insecure Deserialization",
    "Using Components with Known Vulnerabilities",
    "Insufficient Logging & Monitoring",
    "CSRF",
    "SSRF",
    "Other",
]

TEST_STATUSES = ["Pending", "Passed", "Failed"]
VULN_SEVERITIES = ["Low", "Medium", "High", "Critical"]
VULN_STATUSES = ["Open", "Fixed"]

# OWASP Top 10 (2021). Optional classification stored on each finding so the
# report can point a reader at the wider risk category, not just the bug.
OWASP_TOP10 = [
    "A01:2021 Broken Access Control",
    "A02:2021 Cryptographic Failures",
    "A03:2021 Injection",
    "A04:2021 Insecure Design",
    "A05:2021 Security Misconfiguration",
    "A06:2021 Vulnerable and Outdated Components",
    "A07:2021 Identification and Authentication Failures",
    "A08:2021 Software and Data Integrity Failures",
    "A09:2021 Security Logging and Monitoring Failures",
    "A10:2021 Server-Side Request Forgery (SSRF)",
]

CVSS_RANGES = (
    (9.0, 10.0, "Critical"),
    (7.0, 8.9, "High"),
    (4.0, 6.9, "Medium"),
    (0.0, 3.9, "Low"),
)


def severity_from_cvss(score):
    if score is None:
        return None
    value = float(score)
    if value >= 9.0:
        return "Critical"
    if value >= 7.0:
        return "High"
    if value >= 4.0:
        return "Medium"
    return "Low"


# How many points each *unresolved* finding subtracts from a 100 point score.
SEVERITY_WEIGHTS = {"Critical": 25, "High": 10, "Medium": 4, "Low": 1}

SCORE_GRADES = (
    (90, "A", "Strong"),
    (75, "B", "Good"),
    (60, "C", "Fair"),
    (40, "D", "Weak"),
    (0, "F", "Critical risk"),
)


def security_score(vulnerabilities):
    """Return a 0-100 score for an application (higher is safer).

    Every finding still marked ``Open`` subtracts its ``SEVERITY_WEIGHTS``
    value, so fixing a finding immediately improves the score. The result is
    clamped so a very vulnerable application never goes below 0.
    """
    penalty = sum(
        SEVERITY_WEIGHTS.get(item.severity, 0)
        for item in vulnerabilities
        if item.status != "Fixed"
    )
    return max(0, 100 - penalty)


def grade_from_score(score):
    """Map a 0-100 score to a ``(grade, verdict)`` pair such as ``("A", "Strong")``."""
    for threshold, grade, verdict in SCORE_GRADES:
        if score >= threshold:
            return grade, verdict
    return "F", "Critical risk"
