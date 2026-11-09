"""One-shot fix script — delete after running."""
with open('report_service.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Normalise to LF for matching, then restore original endings afterwards
crlf = '\r\n' in content
text = content.replace('\r\n', '\n')

old = (
    'def application_score(application):\n'
    '    """Return ``(score, grade, verdict)`` for one application.\n'
    '\n'
    '    Shared by the report, the dashboard and the applications list so the number\n'
    '    is always calculated the same way. Returns (None, "N/A", "Pending") if\n'
    '    no tests have been recorded yet.\n'
    '    """\n'
    '    if not application.test_cases:\n'
    '        return None, "N/A", "Pending"\n'
    '    score = security_score(application.vulnerabilities)\n'
    '    grade, verdict = grade_from_score(score)\n'
    '    return score, grade, verdict'
)

new = (
    'def application_score(application):\n'
    '    """Return ``(score, grade, verdict)`` for one application.\n'
    '\n'
    '    Shared by the report, the dashboard and the applications list so the number\n'
    '    is always calculated the same way. Returns (None, "N/A", "Pending") only\n'
    '    when the engagement has not started at all - no test cases AND no\n'
    '    vulnerabilities have been recorded. As soon as any finding exists the\n'
    '    score is meaningful, so it is always computed from the vulnerabilities list.\n'
    '    """\n'
    '    if not application.test_cases and not application.vulnerabilities:\n'
    '        return None, "N/A", "Pending"\n'
    '    score = security_score(application.vulnerabilities)\n'
    '    grade, verdict = grade_from_score(score)\n'
    '    return score, grade, verdict'
)

if old in text:
    text = text.replace(old, new)
    print('Replaced application_score successfully.')
else:
    print('ERROR: pattern not found!')

if crlf:
    text = text.replace('\n', '\r\n')

with open('report_service.py', 'w', encoding='utf-8') as f:
    f.write(text)
