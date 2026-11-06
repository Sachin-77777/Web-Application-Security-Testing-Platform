# WASTP — Complete Project Handoff & Continuation Prompt

> **How to use this file:** paste this **entire file** as the first message in a
> new chat/account. It is written to be self-contained — a new assistant with
> zero prior context should be able to read it and continue the project
> immediately.
>
> Last updated: **1 November 2026**

---

## 1. Who I am and how I like to work

- **Name:** Sachin. Call me **bro** — treat me as a friend, not a client.
- **Location:** Nepal. **Timezone:** Asia/Katmandu.
- **Language:** simple English mixed with Nepali. Explain jargon briefly.
- **Occupation:** Cybersecurity student. **Level:** intermediate learner.
- **Stack I know:** HTML/CSS/JS, Tailwind, React, Next.js, Node/Express,
  Python/Flask/FastAPI, MySQL, PostgreSQL, MongoDB, SQLite, Git, Docker.
- **How I learn:** complete working examples, not fragments. Give me the whole
  file / the whole command, plus why it works.

**My standing instructions (these still apply):**

1. **Finish the code first, write documentation later.** (This is now satisfied —
   we are past the code stage.)
2. **Do not worry about Git.** I will `git init` / commit / push myself at the very
   end. Never run git commands for me unless I ask.
3. **Never break what already works.** Every time you add a feature, re-run the
   test suite afterwards and tell me the result. I said this explicitly:
   *"dherai jasto kaila kai new kura add garda old feature lai harm garna sakxa or
   removed pani huna sakxa so just check it bro while adding new"*.
4. **You have autonomy.** I have said *"do as your choice bro"* and *"you can just
   start the things as you wish"*. Pick the sensible next step, but always check
   for regressions.
5. **Never hardcode secrets or API keys.** Use `.env`.
6. **Production-ready code**, clean and readable, minimal but useful comments,
   proper error handling, OWASP-aware.
7. **Design taste** (for any UI work): Apple-inspired, modern SaaS/dashboard,
   minimal, glassmorphism, dark cybersecurity theme — dark blue / black / white /
   purple, and **dark mode preferred**.

**Why I need this document:** my current account will hit its usage limit for
about a month, and my project deadline falls inside that window. So this file is
my memory handoff.

---

## 2. The project in one paragraph

**WASTP — Web Application Security Testing Platform.** My college coursework
project for the brief *"5. Web Application Security Testing Platform — Manage
applications, security test cases, test results, vulnerabilities and reports."*

The idea: a **client** submits a website for testing → the **security team**
records test cases and the vulnerabilities they find → the platform generates a
**report with a 0–100 security score** that the client can download.

It is a Flask 3 app with **two interfaces over one codebase**: a server-rendered
Jinja2 + Bootstrap 5 UI, and a **JSON REST API** under `/api` authenticated with
JWT bearer tokens. The UI uses session cookies + Flask-Login. Both interfaces
share the same authorisation code (`access.py`) and the same models.

**Ethical scope (important, and non-negotiable):** this tool is only ever pointed
at `127.0.0.1` / systems I own or have written permission to test. There are **no
exploit payloads and no attack automation** in the repo — it is a recording and
reporting tool, not a scanner.

---

## 3. Paths and every command you need

**Project root:** `C:\Users\sachi\webapp-security-platform`

> Note: earlier sessions had this project at
> `C:\Users\sachi\OneDrive\Documents\Trae\temp\20261029-01\p2`. The current,
> authoritative location is `C:\Users\sachi\webapp-security-platform`.
> If a path from an old note does not exist, this is the new one.

**The Python interpreter must be the project venv.** Bare `python` on this
machine has no dependencies installed — pytest and Flask will be "not found".

| Task | Command (run from the project root) |
| ---- | ----------------------------------- |
| Run the app | `.\.venv\Scripts\python.exe app.py` |
| Open in browser | `http://127.0.0.1:5000` |
| Seed demo data | `.\.venv\Scripts\python.exe seed.py` |
| Run all tests | `.\.venv\Scripts\python.exe -m pytest -q` |
| Run one test file | `.\.venv\Scripts\python.exe -m pytest tests\test_auth.py -q` |
| Run one test | `.\.venv\Scripts\python.exe -m pytest -q -k filters` |
| Create the MySQL schema | `mysql -u root -p < schema.sql` |

**Environment config:** copy `.env.example` → `.env` and fill it in. `.env` is
gitignored and already exists locally. Key variables:

```
FLASK_ENV=development            # development | production | testing
SECRET_KEY=<32+ random chars>    # python -c "import secrets;print(secrets.token_hex(32))"
JWT_SECRET_KEY=<32+ random chars>
MYSQL_HOST / MYSQL_PORT / MYSQL_USER / MYSQL_PASSWORD / MYSQL_DB   (default db: wastp)
# or override everything with:  DATABASE_URL=mysql+pymysql://user:pass@host:port/db
SESSION_COOKIE_SECURE=false      # true only when served over HTTPS
LOGIN_RATE_LIMIT_MAX_ATTEMPTS=5
LOGIN_RATE_LIMIT_WINDOW_SECONDS=300
LOGIN_RATE_LIMIT_LOCKOUT_SECONDS=300
PER_PAGE=10
SEED_DEMO_DATA=1                 # seed.py: 0 = create only the accounts
```

**Git status: not initialised.** I will do it myself. `requirements.txt`,
`.env.example` and `.gitignore` are already in place and ready for it.

---

## 4. Hard rules — never break these

1. **Ethical testing only** — tests run against `127.0.0.1` / this project only.
2. **No live vulnerabilities in the code.** No raw SQL string building (use
   SQLAlchemy bound parameters / `ilike`), no stored XSS, never `|safe` on
   user-controlled fields.
3. **No exploit payloads** in the repo (no Burp/Nmap playbooks, no attack scripts).
4. **CSP is `script-src 'self'`.** This means **no inline `<script>` blocks in
   templates, ever.** All JavaScript must live in `static/js/*.js`. Inline
   handlers (`onclick="..."`) are blocked too.
5. **Production must refuse to start** if `SECRET_KEY` / `JWT_SECRET_KEY` is the
   built-in default or shorter than 32 characters. This already works — do not
   weaken it.
6. **Never hardcode secrets.**
7. **Regression safety:** after every change run
   `.\.venv\Scripts\python.exe -m pytest -q` and report the count. The suite is
   currently at **77 passed**. Keep it green and growing.
8. **Do not rewrite working modules** unless a functional change actually
   requires it.
9. **Report findings must be real.** The vulnerabilities recorded in the demo data
   are issues that genuinely existed in *this* codebase, were fixed, and were
   re-tested. Do not invent findings or copy generic OWASP examples into the demo
   data.

---

## 5. File map — what every file does

```
webapp-security-platform/
├── app.py                 entry point + create_app() factory. Fail-closed config
│                          check, blueprint registration, the @app.after_request
│                          security-header hook, 403/HTTPException/500 handlers,
│                          and the application_score Jinja global.
├── config.py              Config classes (Base/Development/Production/Testing),
│                          env parsing helpers, DEFAULT_SECRET_KEY, and
│                          configuration_problems() — the fail-closed check.
├── extensions.py          The shared extension objects: db, csrf, login_manager, jwt
├── constants.py           USER_ROLES, TEST_CATEGORIES, TEST_STATUSES,
│                          VULN_SEVERITIES, VULN_STATUSES, OWASP_TOP10,
│                          CVSS_RANGES, severity_from_cvss(), SEVERITY_WEIGHTS,
│                          SCORE_GRADES, security_score(), grade_from_score()
├── models.py              User, Application, TestCase, Vulnerability, Report
├── access.py              ALL authorisation. Single source of truth, shared by
│                          the HTML UI and the API. Never duplicate these rules.
├── util.py                form_str(), search_query(), paginate(),
│                          contains_filter(), is_http_url()
├── rate_limit.py          In-memory sliding-window brute-force limiter with
│                          a MAX_TRACKED_KEYS cap and stale-key pruning
├── report_service.py      reports_dir(), visible_reports(), can_view_report(),
│                          application_score(), report_summary(), generate_report()
│
├── auth.py                Blueprint /auth — register, login, logout, admin user
│                          list, admin role change
├── dashboard.py           Blueprint — /dashboard summary counts
├── applications.py        Blueprint /applications — CRUD + search + pagination
├── test_cases.py          Blueprint /test-cases — CRUD
├── vulnerabilities.py     Blueprint /vulnerabilities — CRUD + search + filters
│                          + CSV export
├── reports.py             Blueprint /reports — index, generate, detail,
│                          download, delete
│
├── api/
│   ├── __init__.py        api_bp mounted at /api; registers the sub-blueprints
│   │                      and csrf.exempt()s them (bearer tokens instead);
│   │                      JSON error handler
│   ├── security.py        register_jwt_callbacks() — JSON 401/403 for bad tokens
│   ├── blocklist.py       jti revocation list so logout really invalidates tokens
│   ├── helpers.py         json_body(), field_str(), error()
│   ├── serializers.py     application_dict / test_case_dict / vulnerability_dict /
│   │                      report_dict / user_dict — explicit field allow-lists
│   ├── auth.py            /api/auth login, refresh, me, logout
│   ├── applications.py    /api/applications CRUD
│   ├── test_cases.py      /api/test-cases CRUD
│   ├── vulnerabilities.py /api/vulnerabilities CRUD
│   └── reports.py         /api/reports
│
├── templates/
│   ├── base.html          layout, navbar, flash messages
│   ├── auth/              login.html, register.html, users.html (admin role UI)
│   └── dashboard/         _macros.html (severity_badge, status_badge, score_badge,
│                          empty_row, pagination_footer),
│                          home.html, applications.html, application_form.html,
│                          application_detail.html, test_cases.html,
│                          test_case_form.html, test_case_detail.html,
│                          vulnerabilities.html, vulnerability_form.html,
│                          vulnerability_detail.html, reports.html,
│                          report_detail.html, report_document.html
│
├── static/css/style.css   custom styling on top of Bootstrap 5.3
├── static/js/auth.js      ALL page JavaScript lives here (CSP requirement)
│
├── tests/
│   ├── conftest.py        app/db/client fixtures + factories (make_user,
│   │                      make_application, make_test_case, make_vulnerability),
│   │                      login() and api_headers() helpers. PASSWORD="password123"
│   ├── test_auth.py             (15 tests) registration (including a forced-role
│   │                            escalation attempt), login, lockout, logout,
│   │                            open-redirect protection, limiter pruning
│   ├── test_api.py              (13 tests) JWT flow, API CRUD, validation
│   ├── test_rbac.py             (22 tests) all three roles, ownership, admin
│   │                            role change, self-demotion block
│   ├── test_security.py         (8 tests)  headers, CSP, HSTS, secret validation
│   ├── test_pagination.py       (4 tests)  page size, empty states
│   ├── test_vulnerabilities.py  (7 tests)  OWASP/CWE/evidence/remediation fields,
│   │                            report score + evidence rendering
│   └── test_filters_and_export.py (8 tests) list filters, CSV export, score badges
│
├── schema.sql             MySQL schema for the `wastp` database
├── seed.py                Demo accounts (admin1/owner1/client1) + one example
│                          engagement with 5 test cases and 7 findings
├── requirements.txt       Flask 3, Flask-SQLAlchemy, Flask-Login, Flask-WTF,
│                          Flask-JWT-Extended, PyMySQL, python-dotenv, Werkzeug,
│                          pytest
├── pytest.ini             testpaths = tests
├── README.md              Full project documentation (roles, score tables,
│                          install, tests, roadmap)
├── report.md              The graded security-testing report — 8 findings with
│                          OWASP/CWE/CVSS, reproduction, mitigation, retest
├── HANDOFF.md             This file
├── .env / .env.example    configuration (`.env` is gitignored)
└── instance/              SQLite db + generated report HTML (gitignored)
```

---

## 6. Database schema

Five tables. Defined in `models.py` (SQLAlchemy) and mirrored in `schema.sql`
(MySQL).

**users** — `id`, `username` (unique), `email` (unique), `password_hash`
(PBKDF2-SHA256 via Werkzeug), `role` enum(`admin`,`user`,`client`), `created_at`.
Properties: `is_admin`, `is_client`. Methods: `set_password`, `check_password`.

**applications** — `id`, `name`, `target_url`, `description`, `owner_id` →
users.id, `created_at`. Cascades to test cases, vulnerabilities and reports.

**test_cases** — `id`, `app_id` → applications.id, `test_name`, `category`,
`status` enum(`Pending`,`Passed`,`Failed`), `assigned_to` → users.id (nullable).

**vulnerabilities** — `id`, `app_id` → applications.id, `title`, `severity`
enum(`Low`,`Medium`,`High`,`Critical`), `cvss_score` Numeric(3,1) nullable,
`status` enum(`Open`,`Fixed`), `owasp_category`, `cwe_id`, `evidence`,
`remediation`, `description`.

**reports** — `id`, `app_id` → applications.id, `generated_by` → users.id,
`report_path`, `created_at`.

> **Migration gotcha:** there is no Alembic. If you add a column, existing MySQL
> databases need a manual `ALTER TABLE`, or a drop-and-reimport of `schema.sql`.
> I have already had to do this once for `owasp_category`, `cwe_id`, `evidence`
> and `remediation` on the `vulnerabilities` table.

---

## 7. Roles and permissions

`admin` runs the platform · `user` is the security team · `client` submits
applications and reads reports but never records findings.

**Public signup creates a `client` — never `user` or `admin`.** The role is
hardcoded server-side in `auth.py` so it cannot be forced through the signup
form. The security team and admins are provisioned deliberately: by `seed.py`, or
by an admin promoting an existing account at `/auth/users`. Do not change this
default back: a public signup must never be able to record findings.

| Action | admin | `user` owning the app | `user` assigned tester | `client` owning the app |
| --- | :-: | :-: | :-: | :-: |
| View application | yes | yes | yes | yes |
| Create application | yes | – | – | yes |
| Edit / delete application | yes | yes | no | yes |
| Create test case | yes | yes | no | no |
| Update test case | yes | yes | status only | no |
| Delete test case | yes | yes | no | no |
| Log / edit vulnerability | yes | yes | no | no |
| Generate / view / download report | yes | yes | no | yes |
| View findings list / export CSV | yes | yes | yes | yes |
| Delete report | yes | if author | no | if author |
| View user list `/auth/users` | yes | no | no | no |
| Change a user's role | yes | no | no | no |

Extra rule: **an admin cannot demote their own account** — this blocks the
"nobody can administer the platform any more" lockout. Implemented in `auth.py`
and exercised by `test_rbac.py::test_an_admin_cannot_demote_themselves`.

All of this lives in `access.py`. If you change a permission, change it there
once — both the UI and the API read from it.

---

## 8. What is already built — full route inventory

### HTML UI (Jinja2 + Bootstrap 5.3)

| Method | Route | Notes |
| --- | --- | --- |
| GET | `/` | redirects to dashboard or login |
| GET/POST | `/auth/register` | always creates role `client` (least privilege) |
| GET/POST | `/auth/login` | rate-limited, safe `next` redirect |
| POST | `/auth/logout` | |
| GET | `/auth/users` | admin only — user list + role dropdowns |
| POST | `/auth/users/<id>/role` | admin only — role change (no self-demotion) |
| GET | `/dashboard` | counts + per-application security score |
| GET | `/applications/` | list, `?q=` search, `?page=`, score column |
| GET/POST | `/applications/new` | |
| GET | `/applications/<id>` | |
| GET/POST | `/applications/<id>/edit` | owner or admin |
| POST | `/applications/<id>/delete` | owner or admin |
| GET | `/test-cases/` | list, `?q=`, `?page=` |
| GET/POST | `/test-cases/new` | admin/owner only |
| GET | `/test-cases/<id>` | |
| GET/POST | `/test-cases/<id>/edit` | owner/admin full, assigned tester status only |
| POST | `/test-cases/<id>/delete` | |
| GET | `/vulnerabilities/` | list, `?q=`, `?severity=`, `?status=`, `?owasp=`, `?page=` |
| GET | `/vulnerabilities/export.csv` | CSV of the **filtered** findings, visibility-scoped |
| GET/POST | `/vulnerabilities/new` | |
| GET | `/vulnerabilities/<id>` | |
| GET/POST | `/vulnerabilities/<id>/edit` | |
| POST | `/vulnerabilities/<id>/delete` | |
| GET | `/reports/` | list |
| POST | `/reports/generate` | renders + saves HTML + creates the DB row |
| GET | `/reports/<id>` | on-screen summary incl. score and grade |
| GET | `/reports/<id>/download` | serves the saved HTML file |
| POST | `/reports/<id>/delete` | admin or author |

### JSON REST API (`/api`, JWT bearer tokens)

```
POST   /api/auth/login      POST /api/auth/refresh
GET    /api/auth/me         POST /api/auth/logout     (revokes the token's jti)

GET    /api/applications            POST   /api/applications
GET    /api/applications/<id>       PUT/PATCH/DELETE /api/applications/<id>
...identical shape for /api/test-cases, /api/vulnerabilities, /api/reports
```

List endpoints support `?q=`. `PUT` replaces, `PATCH` edits only the sent keys.
Validation failures return **422** with an `errors` array; bad tokens return
JSON 401/403/404 (never an HTML error page).

**Feature checklist:**

- [x] Four CRUD modules — applications, test cases, vulnerabilities, reports
- [x] Two auth mechanisms — session cookie (UI) + JWT (API)
- [x] 3-role RBAC + record-level rules (owner vs assigned tester)
- [x] Admin role-management UI with self-demotion protection
- [x] Parameterised search (applications, test cases, vulnerabilities)
- [x] Filters on the findings list — severity / status / OWASP category
- [x] CVSS score → automatic qualitative severity
- [x] OWASP Top 10 (2021) category, CWE id, evidence and remediation per finding
- [x] 0–100 security score + letter grade, on the dashboard, apps list and report
- [x] Report generation → HTML document saved to disk + DB row, view/download
- [x] CSV export of findings, honouring the active filters
- [x] Pagination + empty states in every list view
- [x] Login rate limiting / temporary lockout shared by UI and API
- [x] Production fail-closed secret validation
- [x] Seed script with demo accounts and honest example casework
- [x] 77-test pytest suite

---

## 9. Security controls already implemented

Do not remove or weaken any of these.

| Control | Where |
| --- | --- |
| Password hashing, PBKDF2-SHA256 + per-user salt | `models.User.set_password` |
| Session security — `HttpOnly`, `SameSite=Lax`, `Secure` in production | `config.py` |
| CSRF — Flask-WTF `CSRFProtect` on all HTML forms; API exempt (bearer tokens) | `extensions.py`, all POST forms |
| CSP `script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'` | `app.py` `after_request` |
| `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, `COOP` | `app.py` `after_request` |
| HSTS (only when `SESSION_COOKIE_SECURE`) | `app.py` |
| Brute-force lockout — 5 failures / 300 s → 429 for 300 s, both logins | `rate_limit.py` |
| Bounded limiter memory — `MAX_TRACKED_KEYS = 10_000` + stale pruning | `rate_limit.py` |
| SQL injection — SQLAlchemy ORM + bound `ilike` params only | `util.contains_filter`, all queries |
| XSS — Jinja auto-escaping, `|safe` never used on user content | all templates |
| Open redirect — `next` must start with `/` and not `//` | `auth.py` |
| Fail-closed secrets — production `RuntimeError` on default/short keys | `config.py` + `app.py` |
| JWT — 60 min access / 7 day refresh, `jti` blocklist on logout | `api/auth.py`, `api/blocklist.py` |
| Field allow-list serializers (no `password_hash` leak) | `api/serializers.py` |
| Generic JSON errors, no stack traces to the client | `app.py`, `api/__init__.py` |
| CSV / spreadsheet formula injection guard (`=`, `+`, `-`, `@` prefixed) | `vulnerabilities._csv_cell` |

---

## 10. How the security score works

Defined in `constants.py`, applied by `report_service.application_score()` and
registered as the Jinja global `application_score` in `app.py`.

**Only unresolved findings count**, so fixing something raises the score
immediately:

| Unresolved severity | Points off 100 |
| --- | :-: |
| Critical | 25 |
| High | 10 |
| Medium | 4 |
| Low | 1 |

Score is clamped at 0. Grades: **90+ A (Strong)**, 75+ B (Good), 60+ C (Fair),
40+ D (Weak), below 40 F (Critical risk).

The dashboard, the applications list and the report all call the **same**
`application_score()` helper, so the number can never disagree between views.
If you change the weights, change `SEVERITY_WEIGHTS` in `constants.py` only.

---

## 11. Test suite — 77 passed

Run with `.\.venv\Scripts\python.exe -m pytest -q`. Fixtures live in
`tests/conftest.py`; tests use `create_app("testing")` with an **in-memory
SQLite** database that never touches the real data.

| File | Tests | Covers |
| --- | :-: | --- |
| `test_auth.py` | 15 | register (incl. a forced-role escalation attempt), login, lockout at the 5th failure, logout, open-redirect, limiter pruning |
| `test_rbac.py` | 22 | every role × every action, ownership, admin role change, self-demotion block |
| `test_api.py` | 13 | JWT login/refresh/me/logout, API CRUD, validation errors |
| `test_security.py` | 8 | response headers, CSP, HSTS behaviour, secret validation |
| `test_filters_and_export.py` | 8 | findings filters, CSV export + formula guard, score badges |
| `test_pagination.py` | 4 | page size, out-of-range pages, empty states |
| `test_vulnerabilities.py` | 7 | OWASP/CWE/evidence/remediation, CWE normalisation, report score |

**Known blind spot:** `TestingConfig` sets `WTF_CSRF_ENABLED = False` so tests can
post forms directly. CSRF protection is therefore verified **manually**, not by a
unit test. Say so honestly if asked; do not claim test coverage that does not exist.

---

## 12. Demo / seed data

`seed.py` is **idempotent** — rows are matched on a natural key (owner + name,
app + test name, app + finding title) and updated, not duplicated. Safe to re-run
before every demo; it also refreshes the password hashes.

```
  created  role=admin   admin1     password123
  created  role=user    owner1     password123
  created  role=client  client1    password123

Demo casework: WASTP self-test (127.0.0.1)  — 5 test cases, 7 findings
```

The example engagement is **the platform testing its own running build on
`127.0.0.1`**, which keeps it inside the ethical-use scope. The findings are real:

| Finding | Severity | Status |
| --- | --- | --- |
| No brute-force protection on the login endpoints | High | Fixed |
| Missing Content-Security-Policy and other security headers | Medium | Fixed |
| Application accepted the default `SECRET_KEY` at runtime | High | Fixed |
| Rate-limiter counter map could grow without bound | Medium | Fixed |
| State-changing HTML forms had no CSRF protection | High | Fixed |
| Session cookie `Secure` flag defaults to off outside production | Medium | Open |
| HSTS is only sent when the cookie is marked secure | Low | Open |

That dataset scores **95 / 100, grade A** — 4 + 1 points off for the two open
items — which is exactly what the platform shows on its own dashboard.

> **Consistency note:** `report.md` documents **8** findings. The 8th, the
> Werkzeug debugger (`app.run(debug=True)` hard-coded), is documented in the
> report but is **not** a row in `seed.py`. If you want the app and the report to
> match exactly, add it to `DEMO_APPLICATION["vulnerabilities"]` in `seed.py` as
> `Fixed` (severity High, CVSS 7.5, `CWE-489`, `A05:2021 Security
> Misconfiguration`). Adding a `Fixed` finding does **not** change the 95/A score.

---

## 13. Deliverables — status

| Deliverable | Status |
| --- | --- |
| Working Flask application (UI + API) | **Done** |
| 3-role RBAC + admin role management | **Done** |
| Security score + grade + OWASP/CWE/evidence fields | **Done** |
| Filters, CSV export, pagination | **Done** |
| MySQL schema (`schema.sql`) + idempotent seed | **Done** |
| `README.md` (full docs) | **Done** |
| `report.md` — the graded security testing report | **Done** (needs my screenshots) |
| 77-test pytest suite | **Done, green** |
| Connect MySQL on my laptop | **Pending — my job** |
| Screenshots into `screenshots/` | **Pending — my job** |
| `git init` + commit + push to GitHub | **Pending — my job** |
| Final demo rehearsal / viva prep | **Pending** |

---

## 14. Known gaps and honest limitations

Mention these if asked — do not pretend they do not exist:

1. **Rate limiter state is in-process memory.** It resets on restart and each
   worker would have its own counters. Fine for a single-worker coursework demo.
   Fix: move `rate_limit._attempts` to Redis or a DB table.
2. **JWT blocklist is in-process memory.** `api/blocklist.py` resets on restart,
   so a revoked token becomes valid again after a restart. Same fix path.
3. **No schema-migration tool.** Adding a column needs a manual `ALTER TABLE` or
   a re-import. Fix: Alembic.
4. **CSRF has no automated test** (disabled in the testing config). Verified
   manually only.
5. **`/api/vulnerabilities` has no severity/status/OWASP filters** — only `?q=`.
   The HTML list has the full filter set. This asymmetry is deliberate and
   documented; it was left out because it was not needed.
6. **`SESSION_COOKIE_SECURE` is off outside production** by design, so the
   `http://127.0.0.1` demo works. A `Secure` cookie is not sent over plain HTTP.
7. **HSTS only appears once cookies are secure** — a browser ignores HSTS over
   HTTP anyway, so it activates automatically with TLS.
8. **No password reset / email verification.**
9. **No rate limiting on the API beyond login.**
10. **Report output is HTML only** (no PDF export).
11. **Templates exist for every module but there is no search on the reports
    list**, and reports are not paginated.

---

## 15. Roadmap — what to build next, in priority order

**Tier 1 — most likely to impress the examiner**
1. **PDF export of the report.** The report is already a rendered HTML document;
   add WeasyPrint or `pdfkit` (or keep it dependency-free and use the browser's
   print-to-PDF with a print stylesheet). *This is the single highest-value item.*
2. **Screenshot/attachment upload per finding** so evidence is a real image, not
   just text. Reuse the existing field-allow-list + validation patterns and store
   under `instance/`.
3. **A simple chart on the dashboard** — findings by severity, or score over time
   per application. Plain Chart.js (self-hosted, because CSP blocks inline script
   and external CDNs are already allow-listed for jsdelivr if you prefer).

**Tier 2 — strengthens the "platform" story**
4. **Audit log table** — who changed what, when. Directly addresses
   `A09:2021 Security Logging and Monitoring Failures`, which is the one OWASP
   category the app currently does not exercise. Add `activity_log` model +
   middleware-style hook, then surface it on an admin page.
5. **Porting the in-memory state to the database** (rate limiter + JWT blocklist).
   Removes gaps 1 and 2 at once and shows architectural maturity.
6. **API parity for the filters** — add `?severity=`, `?status=`, `?owasp=` to
   `/api/vulnerabilities`, reusing the same query builder the HTML list uses.
7. **Report templates per engagement type** (quick scan vs full audit) with
   different section layouts.

**Tier 3 — polish**
8. **Dark cybersecurity theme.** I want the UI to match my design taste: dark
   blue / black / white / purple, minimal, glassmorphism, Apple-inspired. This is
   mostly `static/css/style.css` plus a Bootstrap 5.3 colour-mode toggle
   (`data-bs-theme="dark"`). Great value for a demo screenshot.
9. **Bulk actions** on the findings list (mark several as Fixed at once).
10. **Print stylesheet** for the report document.
11. **`GET /api/applications/<id>/score`** endpoint exposing the score in JSON.

**Deliberately NOT to be built** (pollutes the ethical scope):
- Any real vulnerability scanner, crawler, fuzzer, or payload list.
- Burp/Nmap/ZAP automation inside the app.

---

## 16. Environment quirks and gotchas (read this before debugging)

These cost real time in previous sessions. Do not rediscover them.

1. **`python -m pytest` says "No module named pytest"** → you used the system
   Python. Always use `.\.venv\Scripts\python.exe -m pytest`.
2. **pytest sometimes hangs at session finish** in this sandbox
   (`cacheprovider.tempfile.mkdtemp`). Add **`-p no:cacheprovider`** and it
   completes: `.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider`.
3. **A PowerShell `SecurityError` about a "powershell-profile-snapshot.ps1"**
   appears in the command output. **It is harmless** — the command still exits 0.
   Ignore it, do not try to "fix" it.
4. **Flask-SQLAlchemy 3 resolves relative SQLite paths against `instance/`.**
   Use `sqlite:///wastp.db` deliberately; a doubled path means `instance/instance/`.
5. **Files may appear "deleted" in the tool log while actually being present.**
   This has happened repeatedly on this machine (seed.py, vulnerabilities.html,
   README.md and others). **Always verify with a `Glob`/`LS` before re-creating or
   reverting anything.** Never restore a file without checking first.
6. **`Test`-prefixed model names.** `TestCase` is a SQLAlchemy model; `models.py`
   sets `__test__ = False` so pytest does not try to collect it.
7. **Windows PowerShell 5 does not support `&&`.** Chain commands with `;`.

---

## 17. What was done in the most recent sessions (chronology)

So you understand *why* things are the way they are:

1. **Original build** — 4 CRUD modules, session auth, JWT API, RBAC with two
   roles, CVSS-aware severity, report generation, 48 tests passing.
2. **Vision correction.** I explained the real product: a client submits a site,
   the security team tests it, the client downloads a report. The code was missing
   a real *client* role and any *score*. Agreed plan: 3-role RBAC, admin role UI,
   weighted security score.
3. **3-role RBAC** — added `client` to `USER_ROLES` and `User.is_client`; added
   `can_conduct_testing()` to `access.py`; blocked clients from creating test
   cases and findings in both the UI and the API; built the role dropdown in
   `templates/auth/users.html` with the self-demotion guard; added 13 client tests.
   → 61 tests passing.
4. **Security score + rich findings** — added `severity_from_cvss`-style weighted
   scoring (`SEVERITY_WEIGHTS`, `SCORE_GRADES`, `security_score()`,
   `grade_from_score()`), the `OWASP_TOP10` list, regex-validated `CWE-\d+` ids,
   and the `owasp_category` / `cwe_id` / `evidence` / `remediation` columns across
   models, `schema.sql`, both forms, both detail views, the report document and the
   API (with serializers). Added `tests/test_vulnerabilities.py`.
   → 68 tests passing.
5. **Honest demo data** — rewrote `seed.py` to create one account per role plus one
   real example engagement (the platform testing itself), with the issues actually
   found and fixed while hardening this app.
6. **Four polish items I chose** — vulnerability filters, score on the dashboard
   and apps list (via the shared `application_score()` helper + a Jinja global +
   a `score_badge` macro), CSV export (with a formula-injection guard), and a
   README refresh. Added `tests/test_filters_and_export.py`.
   → **76 tests passing**, no regressions.
7. **`report.md`** — the graded security testing report: scope, method, 8 findings
   (identify → reproduce → mitigate → retest), verified controls, residual risk,
   and a test-case matrix. Screenshots still to be added.
8. **Signup role corrected to `client`.** Sachin spotted that public signup was
   granting the security-team role. Changed `auth.py` to hardcode `role="client"`,
   rewrote the register page copy, and added a test proving a `role=admin` posted
   through the form is ignored. → **77 tests passing**, no regressions.

**The single most important habit from all of this:** every change was followed by
a full test run, and the count never went down.

---

## 18. Copy-paste prompts for the next session

Pick one and paste it after this document.

**To get oriented:**
> Read HANDOFF.md fully, then run the test suite with
> `.\.venv\Scripts\python.exe -m pytest -q` and tell me the exact pass count. Then
> give me a short list of the top 3 things you would do next and why. Do not
> change any code yet.

**To continue building (recommended first task):**
> Bro, let's add PDF export for the report. It already renders to HTML in
> `report_service.generate_report()` from `templates/dashboard/report_document.html`.
> Pick the lightest approach, tell me the trade-offs first, then implement it and
> run the full test suite to confirm we are still at 77 passing with no
> regressions.

**To fix the known architectural gaps:**
> Move the rate limiter state and the JWT blocklist from process memory into the
> database so they survive a restart and work across workers. Keep `access.py`
> and the existing public function signatures unchanged, add tests, and show me
> the migration SQL I need to run on MySQL.

**To restyle the UI:**
> Restyle the whole UI to my taste: dark cybersecurity theme, dark blue / black /
> white / purple, glassmorphism, minimal Apple-inspired SaaS look. Keep Bootstrap
> 5.3, keep every existing feature and test passing, remember CSP blocks inline
> scripts so all JS goes in `static/js/`, and show me a before/after screenshot.

**To prepare the demo/viva:**
> Help me rehearse the demo. Write the exact click-through order through the app
> for a 5-minute presentation that shows: the 3 roles, client submitting an
> application, the security team logging a finding with OWASP/CWE/evidence, the
> generated report with the score and grade, the findings filters, and the CSV
> export. Also list the 5 questions an examiner is most likely to ask, with
> short answers.

**When I am ready for Git:**
> Bro, now set up git. Create a sensible `.gitignore` (it already exists — check
> it), write a good first commit message, and walk me through pushing to GitHub.
> Do not commit `.env`.

---

**End of handoff.** Remember: `C:\Users\sachi\webapp-security-platform`, venv at
`.\.venv\Scripts\python.exe`, 77 tests green, never break what works, and check
before you "restore" a file that looks deleted.
