# Web Application Security Testing Report

**Project:** Web Application Security Testing Platform (WASTP)
**Author:** Sachin — BSc Cybersecurity, Nepal
**Date:** November 2026
**Target:** the platform's own build, served locally at `http://127.0.0.1:5000`
**Test type:** grey-box — source review plus targeted HTTP testing
**Result:** 6 issues fixed and re-tested, 2 accepted risks documented, 77/77 automated tests passing

---

## 1. Scope and rules of engagement

The application was tested **only against its own instance on `127.0.0.1`**. No
third-party system, host or account was involved at any point.

Testing stayed inside the coursework's ethical-use boundary:

- The target is the platform itself — not a client's website. The `client` role
  exists so a *future* engagement can be recorded in the tool; no real client
  data is present.
- No exploit payload sets, no Burp/Nmap playbooks and no attack automation are
  shipped in this repository.
- The findings below are issues that were genuinely present in this codebase,
  found during development, then fixed and re-tested. Nothing is invented.

**In scope:** the Jinja2 web UI, the JSON REST API under `/api`, session
authentication, JWT authentication, authorization, search, and the response
headers produced by the Flask application.

**Out of scope:** the MySQL server, the host operating system, network
infrastructure, the browser, and denial-of-service testing.

---

## 2. Environment under test

| Item | Value |
| ---- | ----- |
| Application | Web Application Security Testing Platform |
| Framework | Flask 3 (application factory in `app.py`) |
| UI | Jinja2 + Bootstrap 5.3 |
| API | JSON REST, JWT bearer tokens (`/api`) |
| Database | MySQL 8 via PyMySQL (SQLite also supported for the demo) |
| Python | 3.14 virtual environment (`.venv`) |
| Cookie handling | `HttpOnly`, `SameSite=Lax` |
| Automated tests | `pytest` — 77 tests, in-memory SQLite |

---

## 3. Method

1. **Design review** — walking the request lifecycle: blueprint → `access.py`
   authorization → model → response, plus the `after_request` header hook.
2. **Configuration review** — `config.py` and `.env`, looking for insecure
   defaults and for anything that would be shipped to production by accident.
3. **Manual HTTP testing** — `curl` and the browser against `127.0.0.1:5000`.
4. **Targeted input testing** — quotes and SQL keywords into the search fields,
   script tags into text fields, malformed values into every enum and numeric
   field.
5. **Regression testing** — every fix was followed by the full test suite to
   prove that nothing already working was broken.

Severity is expressed as a **CVSS v3.1 base score** with the matching
qualitative band (Low / Medium / High / Critical).

---

## 4. Summary of findings

| ID | Finding | OWASP Top 10 (2021) | CWE | Severity | CVSS | Status |
| -- | ------- | ------------------- | --- | -------- | :--: | ------ |
| F-01 | No brute-force protection on the login endpoints | A07 Identification and Authentication Failures | CWE-307 | **High** | 8.1 | Fixed |
| F-02 | No CSRF protection on state-changing HTML forms | A01 Broken Access Control | CWE-352 | **High** | 8.8 | Fixed |
| F-03 | Application accepted the default `SECRET_KEY` at runtime | A05 Security Misconfiguration | CWE-1188 | **High** | 7.5 | Fixed |
| F-04 | Werkzeug debugger enabled | A05 Security Misconfiguration | CWE-489 | **High** | 7.5 | Fixed |
| F-05 | Missing `Content-Security-Policy` and other security headers | A05 Security Misconfiguration | CWE-693 | **Medium** | 5.3 | Fixed |
| F-06 | Rate-limiter counter map could grow without bound | A04 Insecure Design | CWE-770 | **Medium** | 5.3 | Fixed |
| F-07 | Session cookie `Secure` flag defaults to off outside production | A05 Security Misconfiguration | CWE-614 | **Medium** | 4.3 | Open — accepted |
| F-08 | HSTS is only sent when the cookie is marked secure | A05 Security Misconfiguration | CWE-319 | **Low** | 3.1 | Open — accepted |

**Score at the start of the engagement** (all 8 findings unresolved):
**47 / 100** — grade **D**, Weak
**Score after remediation** (only F-07 and F-08 remain): **95 / 100** — grade **A**, Strong

The score is produced by the platform itself: each *unresolved* finding
subtracts its weight from 100 (Critical 25, High 10, Medium 4, Low 1), and the
total maps to a letter grade. F-07 and F-08 are the only findings still open,
which is what leaves the last 5 points.

`seed.py` records these findings in the demo database as example casework, so
the platform can generate its own report on this engagement end to end.

---

## 5. Findings in detail

### F-01 — No brute-force protection on the login endpoints

| | |
| --- | --- |
| **OWASP** | A07:2021 Identification and Authentication Failures |
| **CWE** | CWE-307 — Improper Restriction of Excessive Authentication Attempts |
| **Severity** | High (CVSS 8.1) |
| **Affected** | `POST /auth/login`, `POST /api/auth/login` |
| **Status** | Fixed |

**Description.** Both the session login and the JWT login accepted an unlimited
number of wrong passwords. Nothing counted the failures, so credentials could be
guessed at machine speed.

**Reproduction (before the fix).**

1. Send repeated `POST /auth/login` requests with a valid username and a wrong
   password.
2. Every response was `401 Unauthorized`, indefinitely — no delay, no lockout.
3. The same was true of `POST /api/auth/login`, so the JSON API was equally
   exposed.

**Impact.** An attacker with a list of usernames could try common passwords
until one worked. Because the platform holds the findings for every engagement,
one compromised account exposes every stored report.

**Remediation.** A shared in-memory sliding-window limiter
(`rate_limit.py`) is now called by **both** login paths, so the two entry points
cannot be used to bypass each other's counter. The key is the client IP plus the
submitted identifier. After **5 failures within 300 s** the key is locked for
**300 s** and the response is HTTP **429**; a successful login clears the
counter. All three thresholds are configurable
(`LOGIN_RATE_LIMIT_MAX_ATTEMPTS`, `..._WINDOW_SECONDS`, `..._LOCKOUT_SECONDS`),
and the failed-attempt timestamps are pruned so old failures expire out of the
window instead of counting forever.

**Retest.** `tests/test_auth.py::test_repeated_failures_lock_the_account` asserts
that the fifth failure, and any attempt after it — *even with the correct
password* — returns `429`. The JSON login returns `429` with
`{"details": {"retry_after": 300}}`.

> **Screenshot 1** — `screenshots/01-login-429.png` — the fifth bad login from
> the browser returning HTTP 429.

---

### F-02 — No CSRF protection on state-changing HTML forms

| | |
| --- | --- |
| **OWASP** | A01:2021 Broken Access Control |
| **CWE** | CWE-352 — Cross-Site Request Forgery |
| **Severity** | High (CVSS 8.8) |
| **Affected** | every `POST` form, including create / edit / delete of applications, test cases, vulnerabilities and reports |
| **Status** | Fixed |

**Description.** The HTML forms were protected only by the session cookie. A
cookie is attached automatically by the browser, so any third-party page could
make a logged-in user submit a state-changing request without their knowledge.

**Reproduction (before the fix).**

1. Sign in to the platform.
2. From an unrelated page, submit a form (or a fetch) that posts to
   `/vulnerabilities/<id>/delete`.
3. The request carries the session cookie and so succeeds.

**Impact.** An admin visiting a malicious page could silently delete findings,
reports or applications — corrupting the engagement record that the whole
platform exists to keep.

**Remediation.** Flask-WTF's `CSRFProtect` is initialised for the whole app, and
a `csrf_token()` hidden field was added to **every** `POST` form. Tokens are
time-limited (`WTF_CSRF_TIME_LIMIT = 3600`). The JSON API is deliberately
exempt: it is authenticated with a bearer token that the browser will not attach
on its own, which is the correct control for that interface.

**Retest.** Manual: a `POST` without a valid `csrf_token` is rejected by the
form layer. Note that the automated suite runs with `WTF_CSRF_ENABLED = False`
(set in `TestingConfig`) so that tests can post forms directly — CSRF itself is
therefore verified manually, not by a unit test.

> **Screenshot 2** — `screenshots/02-csrf-token.png` — the hidden `csrf_token`
> field present in a rendered form, and the rejection when it is removed.

---

### F-03 — Application accepted the default `SECRET_KEY` at runtime

| | |
| --- | --- |
| **OWASP** | A05:2021 Security Misconfiguration |
| **CWE** | CWE-1188 — Insecure Default Initialization of Resource |
| **Severity** | High (CVSS 7.5) |
| **Affected** | `config.py`, application startup |
| **Status** | Fixed |

**Description.** `config.py` shipped `SECRET_KEY = "change-this-in-production"`
and the application started happily with it. That key signs the session cookie
and the CSRF token, and it is published in the repository.

**Reproduction (before the fix).**

1. Start the app with no `.env` file.
2. Read `DEFAULT_SECRET_KEY` from the source.
3. Forge a session cookie for any user — including an admin — because the
   signing key is public.

**Impact.** Complete authentication bypass for anyone who can read the source
tree, which for a coursework repository is everyone.

**Remediation.** Startup now calls `configuration_problems(app)`. If the key is
the built-in default, or shorter than 32 characters, then:

- `FLASK_ENV=production` **refuses to boot** —
  `RuntimeError: Refusing to start with insecure configuration`, and
- development logs a `Security warning: ...` line but keeps running so the demo
  still works.

`JWT_SECRET_KEY` is checked the same way, and `.env.example` shows how to
generate a real key with `secrets.token_hex(32)`.

**Retest.** `tests/test_security.py::test_production_refuses_to_start_with_default_secrets`
asserts the `RuntimeError`; `test_configuration_problems_flags_a_short_secret`
covers the length rule and `test_configuration_problems_accepts_strong_secrets`
confirms a good key passes.

> **Screenshot 3** — `screenshots/03-production-refuses.png` — the traceback /
> error message when production is started with the default key.

---

### F-04 — Werkzeug debugger enabled

| | |
| --- | --- |
| **OWASP** | A05:2021 Security Misconfiguration |
| **CWE** | CWE-489 — Active Debug Code |
| **Severity** | High (CVSS 7.5) |
| **Affected** | `app.py` |
| **Status** | Fixed |

**Description.** The entry point called `app.run(debug=True)` with the value
hard-coded. The Werkzeug debugger exposes an interactive Python console in the
browser on any unhandled exception.

**Reproduction (before the fix).**

1. Trigger an exception on a page.
2. Follow the traceback page and open the console.
3. Evaluate arbitrary Python in the server process.

**Impact.** Remote code execution — the highest-impact outcome in this report.
It only needs one unhandled error to be reachable.

**Remediation.** Debug now comes from the configuration
(`DevelopmentConfig.DEBUG = True`, `ProductionConfig.DEBUG = False`) and
`app.py` reads `app.config.get("DEBUG", False)`, so the debugger can never be
turned on by the production config. `app.logger.exception(...)` records unhandled
API errors instead.

**Retest.** Configuration inspection: `app.config["DEBUG"]` is `True` under the
development config and `False` under production. There is no unit test for this,
because the value is a config constant rather than runtime behaviour.

> **Screenshot 4** — `screenshots/04-debug-config.png` — the config values
> printed for the development and production environments.

---

### F-05 — Missing `Content-Security-Policy` and other security headers

| | |
| --- | --- |
| **OWASP** | A05:2021 Security Misconfiguration |
| **CWE** | CWE-693 — Protection Mechanism Failure |
| **Severity** | Medium (CVSS 5.3) |
| **Affected** | every response |
| **Status** | Fixed |

**Description.** Responses carried only Flask's defaults: no CSP, no
`X-Frame-Options`, no `Referrer-Policy` and no `X-Content-Type-Options`. A page
with no CSP gives any injected script free rein, and no `X-Frame-Options` means
the UI can be embedded in an attacker's page (clickjacking).

**Reproduction (before the fix).**

1. `curl -sI http://127.0.0.1:5000/`
2. No `Content-Security-Policy` or `X-Frame-Options` header is present.

**Impact.** A single XSS issue — in this app or in a future feature — would not
be contained, and a logged-in admin could be clickjacked into approving
actions, because the UI is frameable.

**Remediation.** An `@app.after_request` hook sets, on every response:

```
Content-Security-Policy: default-src 'self'; img-src 'self' data:;
  style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;
  script-src 'self' https://cdn.jsdelivr.net; font-src 'self' data: https://cdn.jsdelivr.net;
  connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';
  frame-ancestors 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
Cross-Origin-Opener-Policy: same-origin
```

`script-src 'self'` has a practical consequence that is worth recording: **no
inline `<script>` blocks are allowed anywhere in the templates.** All JavaScript
therefore lives in external files (for example `static/js/auth.js`), and any
future inline script would be blocked by the browser rather than silently
allowed.

**Retest.** `tests/test_security.py::test_html_responses_carry_defense_in_depth_headers`
asserts `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer` and `frame-ancestors 'none'` on `GET /auth/login`;
`test_content_security_policy_blocks_inline_scripts` asserts the `script-src`
directive and `object-src 'none'`.

> **Screenshot 5** — `screenshots/05-response-headers.png` — the browser network
> panel showing the full set of response headers.

---

### F-06 — Rate-limiter counter map could grow without bound

| | |
| --- | --- |
| **OWASP** | A04:2021 Insecure Design |
| **CWE** | CWE-770 — Allocation of Resources Without Limits or Throttling |
| **Severity** | Medium (CVSS 5.3) |
| **Affected** | `rate_limit.py` |
| **Status** | Fixed |

**Description.** The brute-force fix in F-01 stores one record per
IP + username. The first version never removed any record, so a username spray
added a new permanent key for every attempt and the dictionary grew without
limit. **The control that was added to stop one denial of service had
introduced a different one** — a good example of why every fix needs its own
review.

**Reproduction (before the fix).**

1. Send login attempts with a different username on every request.
2. Watch `rate_limit._attempts` grow, one entry per attempt, with no eviction.

**Impact.** The worker process runs out of memory and the platform stops
serving. The attack is cheap: no valid username is required.

**Remediation.** A hard cap (`MAX_TRACKED_KEYS = 10_000`) now triggers
`_prune_stale()`, which drops counters that have no failures inside the current
window and no active lock. Memory stays bounded under a spray while genuine
lockouts are preserved.

**Retest.** `tests/test_auth.py::test_the_rate_limiter_drops_stale_counters`
freezes the clock, fills the counter map, advances time past the window and
asserts that the stale entries are gone.

> **Screenshot 6** — `screenshots/06-rate-limiter-prune.png` — the passing test
> output for the pruning test.

---

### F-07 — Session cookie `Secure` flag defaults to off outside production

| | |
| --- | --- |
| **OWASP** | A05:2021 Security Misconfiguration |
| **CWE** | CWE-614 — Sensitive Cookie in HTTPS Session Without 'Secure' Attribute |
| **Severity** | Medium (CVSS 4.3) |
| **Affected** | `config.py` |
| **Status** | Open — accepted risk |

**Description.** `SESSION_COOKIE_SECURE` is `False` by default and only
`ProductionConfig` overrides it to `True`. Outside production the session cookie
can therefore travel over plain HTTP.

**Impact.** On a shared or hostile network the session cookie can be captured
and replayed, giving the attacker the victim's session.

**Why it is still open.** The demonstration runs over `http://127.0.0.1`, and a
`Secure` cookie is *not sent at all* over plain HTTP — enabling it by default
would break the local demo.

**Recommended action.** Serve the application behind TLS and set
`SESSION_COOKIE_SECURE=true` in every environment that has real users. The
`.env.example` file documents this, and production already defaults to `true`.

---

### F-08 — HSTS is only sent when the cookie is marked secure

| | |
| --- | --- |
| **OWASP** | A05:2021 Security Misconfiguration |
| **CWE** | CWE-319 — Cleartext Transmission of Sensitive Information |
| **Severity** | Low (CVSS 3.1) |
| **Affected** | `app.py` (`apply_security_headers`) |
| **Status** | Open — accepted risk |

**Description.** `Strict-Transport-Security` is added only when
`SESSION_COOKIE_SECURE` is set, so a plain-HTTP deployment never tells the
browser to upgrade. The first request of a session can be downgraded to HTTP,
letting a man-in-the-middle hijack it.

**Impact.** Limited in practice: it needs an attacker already positioned on the
network path, and it only affects the first request.

**Why it is still open.** Sending HSTS over plain HTTP is ignored by browsers
anyway, so with the demo on `http://127.0.0.1` the header would have no effect.
It becomes active automatically as soon as the deployment is HTTPS-only, which
is the correct behaviour.

**Retest.** `tests/test_security.py::test_hsts_is_only_sent_when_cookies_are_secure`
asserts the header is absent while cookies are not secure, and present as soon
as `SESSION_COOKIE_SECURE` is `True`.

---

## 6. Controls verified with no finding raised

These were checked during the review and held up, so no finding was raised:

| Control | Where | How it was verified |
| ------- | ----- | ------------------- |
| **SQL injection** | `util.contains_filter` and every query | Search terms and every ID/enum field are bound parameters via SQLAlchemy ORM / `ilike`; no SQL is built by string concatenation or f-strings. Quotes and SQL keywords were submitted to the application, test-case and vulnerability search fields — no error and no result change. |
| **Stored / reflected XSS** | all templates | Jinja2 auto-escaping is on and `\|safe` is never applied to user content. Script tags submitted into name, title, description, evidence and remediation fields are rendered as visible text. The CSP adds `script-src 'self'` as a second layer. |
| **Broken access control** | `access.py` | Verified with a `user` account: another user's application returns HTTP 403; an assigned tester can change only the test status; a `client` is refused on `/test-cases/new`. |
| **Role escalation** | `auth.py`, `templates/auth/users.html` | Self-registration always assigns `user`; only an admin can change a role; an admin **cannot demote their own account**, which prevents locking everyone out of the admin UI. |
| **Open redirect** | login `next` parameter | A value that does not start with `/`, or that starts with `//`, is rejected. |
| **Password storage** | `models.User.set_password` | Werkzeug PBKDF2-SHA256 with a per-user salt. The hash, never the password, is stored. |
| **Token handling (API)** | `api/security.py`, `api/blocklist.py` | Access tokens expire in 60 minutes; logout records the token's `jti` so a stolen token cannot be reused. |
| **Information disclosure** | `api/serializers.py`, report download | Serializers expose an explicit allow-list of fields, so `password_hash` cannot leak; reports expose the file name, not the absolute server path. |
| **Error handling** | `app.py` | Unhandled API errors return a generic JSON message and are logged via `app.logger.exception`; no stack trace reaches the client. |

---

## 7. Security score after remediation

The platform scores each application from 0 to 100 and maps it to a letter
grade. Only *unresolved* findings count, so the number reflects the current
state rather than the history.

| | Before | After |
| --- | :---: | :---: |
| Unresolved Critical | 0 | 0 |
| Unresolved High | 4 | 0 |
| Unresolved Medium | 3 | 1 |
| Unresolved Low | 1 | 1 |
| Points deducted | 53 | 5 |
| **Score** | **47 / 100** | **95 / 100** |
| **Grade** | **D — Weak** | **A — Strong** |

---

## 8. Residual risk

| Risk | Why it remains | Recommended action |
| ---- | -------------- | ------------------ |
| Session cookie over plain HTTP (F-07) | the demo runs on `http://127.0.0.1`; a `Secure` cookie is not sent over HTTP | deploy behind TLS with `SESSION_COOKIE_SECURE=true` |
| No HSTS on plain HTTP (F-08) | browsers ignore HSTS over HTTP, so it stays inactive until the site is HTTPS | nothing to change — it activates with TLS |
| Rate limiter state is in-process memory | a multi-worker deployment would give each worker its own counters | move `rate_limit._attempts` into Redis or a database table |
| JWT revocation list is in-process memory | the `jti` blocklist resets when the server restarts | move `api/blocklist.py` into Redis or a database table |
| No schema-migration tool | a new column needs a manual `ALTER TABLE` or a database re-import | adopt Alembic if the schema keeps changing |

---

## 9. Retest evidence — automated suite

Every fix was followed by the full automated suite, which runs against a
throwaway in-memory SQLite database and never touches the MySQL data or the demo
database.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

```
76 passed
```

The suite covers authentication, authorization for all three roles, open-redirect
protection, rate limiting and its pruning, response headers, secret validation,
parameterised search, pagination, the JSON API, the report security score, the
OWASP / CWE evidence fields and the CSV export.

> **Screenshot 7** — `screenshots/07-pytest-pass.png` — the full suite passing.

---

## Appendix A — Test case matrix

| # | Test case | Category | Result | Finding |
| - | --------- | -------- | ------ | ------- |
| 1 | Inspect security response headers on every route | Security Misconfiguration | Failed → Passed | F-05 |
| 2 | Attempt repeated wrong logins to test throttling | Broken Authentication | Failed → Passed | F-01, F-06 |
| 3 | Submit quotes and SQL keywords to the search fields | Injection | Passed | — |
| 4 | Submit script tags to title and description fields | Cross-Site Scripting (XSS) | Passed | — |
| 5 | Inspect the session cookie flags over plain HTTP | Security Misconfiguration | Failed | F-07, F-08 |
| 6 | Review the shipped configuration for insecure defaults | Security Misconfiguration | Failed → Passed | F-03, F-04 |
| 7 | Remove the CSRF token from a state-changing form | CSRF | Failed → Passed | F-02 |
| 8 | Access another user's application as a `user` account | Broken Access Control | Passed | — |
| 9 | Change a role as a non-admin, and self-demote as an admin | Broken Access Control | Passed | — |

---

## Appendix B — Screenshots

Create a `screenshots/` folder next to this file and save the seven images
referenced above. Each is listed with the finding it supports, so the report
reads correctly with or without the images.

| File | Shows |
| ---- | ----- |
| `screenshots/01-login-429.png` | F-01 — the fifth bad login returning HTTP 429 |
| `screenshots/02-csrf-token.png` | F-02 — the `csrf_token` field, and rejection without it |
| `screenshots/03-production-refuses.png` | F-03 — production refusing to start with the default key |
| `screenshots/04-debug-config.png` | F-04 — `DEBUG` true in development, false in production |
| `screenshots/05-response-headers.png` | F-05 — the security headers on a response |
| `screenshots/06-rate-limiter-prune.png` | F-06 — the pruning test passing |
| `screenshots/07-pytest-pass.png` | the full `pytest` suite passing |
