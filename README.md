# Web Application Security Testing Platform

A web application for managing **security testing work**: the applications under
test, the test cases run against them, the vulnerabilities that are found and
the summary reports produced from the results.

This is the coursework project for **"5. Web Application Security Testing
Platform — Manage applications, security test cases, test results,
vulnerabilities and reports."**

> **Ethical use only.** This tool is meant to be run against **`127.0.0.1` and
> other systems you own or have written permission to test**. Do not point it at
> third-party infrastructure. The project intentionally contains **no exploit
> payloads and no attack automation** — it is a record-keeping and reporting tool.

---

## Table of contents

1. [Features](#features)
2. [Tech stack](#tech-stack)
3. [Architecture](#architecture)
4. [Quick start (MySQL)](#quick-start-mysql)
5. [Quick start (SQLite, for a fast demo)](#quick-start-sqlite-for-a-fast-demo)
6. [Environment variables](#environment-variables)
7. [Creating an admin account](#creating-an-admin-account)
8. [Roles and permissions](#roles-and-permissions)
9. [Security score](#security-score)
10. [Modules (HTML UI)](#modules-html-ui)
11. [REST API (`/api`)](#rest-api-api)
12. [Security controls](#security-controls)
13. [Tests](#tests)
14. [Roadmap](#roadmap)

---

## Features

- **Four CRUD modules** — applications, test cases, vulnerabilities, reports.
- **Two interfaces over one codebase** — a server-rendered **Jinja2 + Bootstrap 5**
  UI, and a **JSON REST API** under `/api` for scripts and tooling.
- **Two independent authentication mechanisms** — session cookies for the
  browser UI, **JWT bearer tokens** for the API.
- **Role-based access control** — `admin`, `user` and `client`, plus
  record-level rules (owner vs. assigned tester).
- **Parameterised search** on applications and vulnerabilities, with
  severity / status / OWASP Top 10 filters on the findings list.
- **CVSS-aware severity** — entering a CVSS score derives the qualitative
  severity (Low / Medium / High / Critical) automatically.
- **Actionable findings** — each vulnerability can record its OWASP Top 10
  (2021) category, CWE id, evidence and remediation advice.
- **Security score** — every application gets a 0–100 score and a letter grade
  derived from its *unresolved* findings, shown on the dashboard, the
  applications list and the report.
- **CSV export** of the findings list, honouring the active search and filters.
- **Report generation** — renders a summary document to disk and records it.
- **Defensive defaults** — password hashing, CSRF protection, input validation,
  SQL-injection-safe queries and Jinja auto-escaping.

## Tech stack

| Layer          | Technology                                                        |
| -------------- | ----------------------------------------------------------------- |
| Web framework  | Flask 3 (application factory pattern)                             |
| Templates      | Jinja2 + Bootstrap 5.3                                            |
| ORM            | Flask-SQLAlchemy                                                  |
| Database       | MySQL 8 (via PyMySQL); SQLite is supported for local demos        |
| Auth (UI)      | Flask-Login — session cookies                                   |
| Auth (API)     | Flask-JWT-Extended — access + refresh tokens                     |
| Forms / CSRF   | Flask-WTF                                                         |
| Password hash  | Werkzeug `generate_password_hash` (PBKDF2-SHA256)                 |

## Architecture

```
Browser (Jinja UI)  --session cookie-->  HTML blueprints
                                              |
                                              v
                                        access.py  (shared RBAC)
                                              ^
                                              |
Scripts / curl      --Bearer JWT------->  api/ package
                                              |
                                              v
                                       models.py  ->  MySQL / SQLite
```

`access.py` is the single source of truth for **who may see and change what**.
Both the HTML blueprints and the JSON API call into it, so the two interfaces
can never disagree about permissions.

### Folder structure

```
webapp-security-platform/
├── app.py                 # application factory, blueprint and error-handler wiring
├── config.py              # environment-driven configuration classes
├── extensions.py          # db, csrf, jwt, login_manager singletons
├── models.py              # User, Application, TestCase, Vulnerability, Report
├── constants.py           # roles, test categories, statuses, CVSS bands,
│                          #   OWASP Top 10 and the score / grade tables
├── util.py                # form parsing, URL validation, safe search filters
├── access.py              # role and record-level authorisation rules
├── report_service.py      # report generation, security score, visibility
│
├── auth.py                # /auth  register, login, logout, user list
├── dashboard.py           # /dashboard  counts and recent activity
├── applications.py        # /applications  CRUD
├── test_cases.py          # /test-cases  CRUD
├── vulnerabilities.py     # /vulnerabilities  CRUD
├── reports.py             # /reports  generate, view, download, delete
│
├── api/                   # JSON REST API, mounted at /api
│   ├── __init__.py        # blueprint assembly, JSON error handling, CSRF exemption
│   ├── auth.py            # /api/auth  login, refresh, me, logout
│   ├── applications.py    # /api/applications
│   ├── test_cases.py      # /api/test-cases
│   ├── vulnerabilities.py # /api/vulnerabilities
│   ├── reports.py         # /api/reports
│   ├── helpers.py         # JSON body accessors and consistent error responses
│   ├── serializers.py     # model -> dict conversion (explicit field allow-list)
│   ├── security.py        # JWT user lookup, revocation check, JSON token errors
│   └── blocklist.py       # revoked token ids (in-memory)
│
├── templates/
│   ├── base.html          # navbar, flash messages, role-conditional links
│   ├── auth/              # login, register, users
│   └── dashboard/         # all module pages, forms, details, _macros.html
│
├── tests/                 # pytest suite (auth, RBAC, search, API, exports)
│   ├── conftest.py        # in-memory SQLite fixtures and model factories
│   └── test_*.py
│
├── schema.sql             # MySQL schema for the `wastp` database
├── seed.py                # demo accounts (admin / user / client) + example casework
├── requirements.txt
├── .env.example
└── .gitignore
```

## Quick start (MySQL)

**1. Create and activate a virtual environment**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**2. Create the database**

The schema script creates the `wastp` database, all five tables, foreign keys
and indexes:

```powershell
mysql -u root -p < schema.sql
```

**3. Configure the environment**

```powershell
Copy-Item .env.example .env
```

Then edit `.env` and set `SECRET_KEY`, `MYSQL_PASSWORD` and — for anything other
than local development — a separate `JWT_SECRET_KEY`.

**4. Create the demo accounts**

The seed script inserts one account per role and one example engagement, and is
safe to run again — rows are matched on a natural key and updated instead of
duplicated, which also refreshes the password hashes before a demo:

```powershell
python seed.py
```

```
Database : mysql+pymysql://root:***@localhost:3306/wastp
  created  role=admin  admin1                password123
  created  role=user   owner1                password123
  created  role=client client1               password123

Demo casework (created): WASTP self-test (127.0.0.1)
  5 test cases, 7 findings
```

The example application is the platform testing its own running build on
`127.0.0.1` (see the ethical-use note at the top), with the findings that were
actually found and fixed while hardening this project. Set `SEED_DEMO_DATA=0`
to create only the accounts.

Override the defaults with `SEED_ADMIN_*`, `SEED_USER_*` and `SEED_CLIENT_*`
(`_USERNAME`, `_EMAIL`, `_PASSWORD`) if you want different credentials.

**5. Run**

```powershell
python app.py
```

Open <http://127.0.0.1:5000> and sign in as `admin1`, `owner1` or `client1`
(all with `password123`). Accounts created through the registration form always
get the `user` role.

MySQL is the default connection: [config.py](config.py) builds a
`mysql+pymysql://` URL from the `MYSQL_*` values, so nothing else is needed.

## Quick start (SQLite, for a fast demo)

Set the connection string to SQLite and the tables are created automatically on
startup — no MySQL server required:

```powershell
Add-Content -Path .env -Value "DATABASE_URL=sqlite:///wastp.db" -Encoding ascii
python seed.py
python app.py
```

## Environment variables

All variables are read by [config.py](config.py); see [.env.example](.env.example)
for a commented template.

| Variable             | Default              | Purpose                                                    |
| -------------------- | -------------------- | ---------------------------------------------------------- |
| `FLASK_ENV`          | `development`        | Selects `development` / `production` / `testing` config      |
| `SECRET_KEY`         | insecure placeholder | Signs session cookies and CSRF tokens                        |
| `JWT_SECRET_KEY`     | falls back to `SECRET_KEY` | Signs API access and refresh tokens                   |
| `JWT_ACCESS_MINUTES` | `60`                 | Access token lifetime                                        |
| `JWT_REFRESH_DAYS`   | `7`                  | Refresh token lifetime                                       |
| `MYSQL_HOST`         | `localhost`          | MySQL host                                                   |
| `MYSQL_PORT`         | `3306`               | MySQL port                                                   |
| `MYSQL_USER`         | `root`               | MySQL user                                                   |
| `MYSQL_PASSWORD`     | *(empty)*            | MySQL password                                               |
| `MYSQL_DB`           | `wastp`              | Database name                                                |
| `DATABASE_URL`       | *(empty)*            | Full SQLAlchemy URL; overrides all `MYSQL_*` values          |
| `REPORTS_FOLDER`     | `instance/reports`   | Where generated report documents are written                 |
| `SESSION_COOKIE_SECURE` | `false` (dev) / `true` (production) | Send session and remember-me cookies over HTTPS only |
| `SECURITY_HEADERS_ENABLED` | `true`         | Add CSP, `X-Frame-Options`, `X-Content-Type-Options`, …       |
| `LOGIN_RATE_LIMIT_MAX_ATTEMPTS` | `5`        | Failed logins for one IP + username before a lockout          |
| `LOGIN_RATE_LIMIT_WINDOW_SECONDS` | `300`    | Window in which the failed attempts are counted               |
| `LOGIN_RATE_LIMIT_LOCKOUT_SECONDS` | `300`   | How long a locked key must wait before trying again           |
| `TEST_DATABASE_URI`  | `sqlite:///:memory:` | Database used when `FLASK_ENV=testing`                       |

## Creating an admin account

The easiest way is `python seed.py`, which creates `admin1` (role `admin`),
`owner1` (role `user`) and `client1` (role `client`) — see the quick-start
section.

Registration always assigns the `user` role on purpose, so nobody can promote
themselves through the web form. To change a role, sign in as an administrator
and open `/auth/users`; the role dropdown there is blocked from demoting your
own account, so an admin cannot lock themselves out. The same change can be made
directly in the database:

```sql
UPDATE wastp.users SET role = 'client' WHERE username = 'your_username';
```

Sign out and back in so the new role is loaded into the session.

## Roles and permissions

`admin` runs the platform, `user` is the security team, and `client` submits an
application for testing and reads the report that comes back.

**Signing up always creates a `client`** — the least-privilege role. The security
team (`user`) and admins are provisioned deliberately: by `seed.py`, or by an
admin promoting an existing account at `/auth/users`. The role is decided on the
server, so it cannot be forced through the signup form.

| Action                              | Admin | `user` owning the app | `user` assigned tester | `client` owning the app |
| ----------------------------------- | :---: | :-------------------: | :--------------------: | :---------------------: |
| View application                    |  yes  |          yes          |          yes           |           yes           |
| Create application                  |  yes  |           –           |           –            |           yes           |
| Edit / delete application           |  yes  |          yes          |           no           |           yes           |
| Create test case                    |  yes  |          yes          |           no           |           no            |
| Update test case                    |  yes  |          yes          |     **status only**    |           no            |
| Delete test case                    |  yes  |          yes          |           no           |           no            |
| Log / edit vulnerability            |  yes  |          yes          |           no           |           no            |
| Generate / view / download report   |  yes  |          yes          |           no           |           yes           |
| View findings list / export CSV     |  yes  |          yes          |          yes           |           yes           |
| Delete report                       |  yes  |       if author       |           no           |        if author        |
| View user list (`/auth/users`)      |  yes  |           no          |           no           |           no            |
| Change a user's role                |  yes  |           no          |           no           |           no            |

A `client` can submit an application and read the resulting report, but never
records tests or findings — those are written by the security team.

## Security score

Reports are summarised with a **0–100 score** and a letter grade so the result
is easy to read at a glance. Only **unresolved** findings count, so fixing a
finding immediately raises the score:

| Unresolved severity | Points off the 100 |
| ------------------- | :----------------: |
| Critical            |         25         |
| High                |         10         |
| Medium              |          4         |
| Low                 |          1         |

| Score  | Grade | Verdict        |
| ------ | :---: | -------------- |
| 90–100 |   A   | Strong         |
| 75–89  |   B   | Good           |
| 60–74  |   C   | Fair           |
| 40–59  |   D   | Weak           |
| 0–39   |   F   | Critical risk  |

The weights and grade bands live in [constants.py](constants.py)
(`SEVERITY_WEIGHTS`, `SCORE_GRADES`) and are applied by `security_score()` /
`grade_from_score()`. The dashboard, the applications list and the report all
call the same `application_score()` helper in
[report_service.py](report_service.py), so the number can never disagree between
views.

## Modules (HTML UI)

| Module          | Base URL        | What it manages                                                      |
| --------------- | --------------- | -------------------------------------------------------------------- |
| Authentication  | `/auth`         | register, login, logout, admin user list and role management         |
| Dashboard       | `/dashboard`    | counts of applications, open vulnerabilities, failed tests, and the security score of each application |
| Applications    | `/applications` | the systems under test (name, target URL, description) — with score  |
| Test cases      | `/test-cases`   | OWASP-style test items with `Pending` / `Passed` / `Failed` status   |
| Vulnerabilities | `/vulnerabilities` | findings with severity, CVSS score, OWASP / CWE, evidence, remediation and `Open` / `Fixed` status; filter by severity / status / category and export to CSV |
| Reports         | `/reports`      | generated summary documents with the security score — view, download, delete |

## REST API (`/api`)

The API returns JSON and authenticates with **JWT bearer tokens**. It reuses the
same access rules as the UI, so permissions match exactly.

### Token flow

```
POST /api/auth/login     ->  { access_token, refresh_token, expires_in, user }
POST /api/auth/refresh   ->  { access_token }          (send the refresh token)
GET  /api/auth/me        ->  { user }
POST /api/auth/logout    ->  revokes the token you sent
```

### Endpoints

| Method                    | Path                            | Notes                                  |
| ------------------------- | ------------------------------- | -------------------------------------- |
| `GET`                     | `/api/applications`             | supports `?q=` search                  |
| `POST`                    | `/api/applications`             | create                                 |
| `GET`                     | `/api/applications/<id>`        | read                                   |
| `PUT` / `PATCH`           | `/api/applications/<id>`        | `PUT` replaces, `PATCH` updates fields |
| `DELETE`                  | `/api/applications/<id>`        | delete                                 |
| `GET` / `POST`            | `/api/test-cases`               | list / create                          |
| `GET` / `PUT` / `PATCH` / `DELETE` | `/api/test-cases/<id>` | an assigned tester may PATCH `status` only |
| `GET` / `POST`            | `/api/vulnerabilities`          | supports `?q=` search; accepts `owasp_category`, `cwe_id`, `evidence`, `remediation` |
| `GET` / `PUT` / `PATCH` / `DELETE` | `/api/vulnerabilities/<id>` | CVSS score derives the severity   |
| `GET` / `POST`            | `/api/reports`                  | list / generate                        |
| `GET`                     | `/api/reports/<id>`             | metadata plus the summary counters     |
| `GET`                     | `/api/reports/<id>/download`    | downloads the document                 |
| `DELETE`                  | `/api/reports/<id>`             | delete (author or admin)               |

Status codes: `200` OK, `201` created, `401` missing/expired token,
`403` forbidden, `404` not found, `422` validation failed (with a `details`
array), `500` server error.

### Example session

```bash
# 1. Log in and capture the access token
curl -s -X POST http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"owner1\",\"password\":\"password123\"}"

# 2. Create an application (replace $TOKEN with the access_token value)
curl -s -X POST http://127.0.0.1:5000/api/applications \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Local test site\",\"target_url\":\"http://127.0.0.1:5000\",\"description\":\"Our own app\"}"

# 3. Log a vulnerability; the CVSS score sets the severity to High
curl -s -X POST http://127.0.0.1:5000/api/vulnerabilities \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"app_id\":1,\"title\":\"Debug mode enabled\",\"cvss_score\":7.5}"

# 4. Generate and download the report
curl -s -X POST http://127.0.0.1:5000/api/reports \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d "{\"app_id\":1}"

curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:5000/api/reports/1/download -o report.html

# 5. Revoke the token
curl -s -X POST http://127.0.0.1:5000/api/auth/logout -H "Authorization: Bearer $TOKEN"
```

### API design notes

- **The API is exempt from CSRF protection.** CSRF exists to stop a browser from
  being tricked into sending an authenticated request; the API is authenticated
  by a token the caller has to attach explicitly, which a browser will not do on
  its own. The HTML forms keep full CSRF protection.
- **Logout revokes the token** by recording its `jti` claim. The revocation
  store is in process memory, so it resets when the server restarts. Moving it to
  Redis or a database table is listed in the roadmap.
- **Responses never expose internal fields.** `api/serializers.py` lists every
  field explicitly, so `password_hash` and the server-side report path cannot
  leak.

## Security controls

| Control                        | Where                                                        |
| ------------------------------ | ------------------------------------------------------------ |
| Password hashing (PBKDF2-SHA256, salted) | `models.User.set_password`                         |
| SQL injection prevention       | SQLAlchemy ORM + bound parameters everywhere; `util.contains_filter` uses `ilike` with a parameter, never string concatenation |
| XSS prevention                 | Jinja2 auto-escaping on; no `|safe` on user content           |
| CSRF protection                | Flask-WTF `CSRFProtect` on all HTML forms                    |
| Authentication                 | Flask-Login sessions (UI) and signed JWTs (API)               |
| Authorisation                  | `access.py` role + record-level rules, shared by UI and API   |
| Input validation               | server-side checks in every blueprint and API module (lengths, enums, URL scheme, CVSS range, OWASP category, `CWE-\d+` format, foreign keys) |
| Spreadsheet / CSV injection    | the findings export prefixes any cell starting with `=`, `+`, `-` or `@` so Excel and Sheets never evaluate it as a formula |
| URL validation                 | `util.is_http_url` only accepts `http` / `https` with a host  |
| Open-redirect guard            | login `next` parameter must start with `/` and not `//`       |
| Cookie hardening               | `SESSION_COOKIE_HTTPONLY`, `SAMESITE=Lax`, `REMEMBER_COOKIE_HTTPONLY`, HTTPS-only (`Secure`) in production |
| Security headers               | CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, HSTS over HTTPS |
| Brute-force protection         | `rate_limit.py` lockout on the session and JWT login forms    |
| Information disclosure         | API serializers expose an explicit field allow-list; reports expose the file name, not the absolute path |
| Token lifetime                 | access tokens expire in 60 minutes, refresh tokens in 7 days  |

## Security hardening log (identify → mitigate → retest)

Five weaknesses were found in this application, fixed, and re-tested. All
testing was done against the app running on `127.0.0.1`.

| # | Finding | Before | Mitigation | Retest result |
| - | ------- | ------ | ---------- | ------------- |
| 1 | Default/weak `SECRET_KEY` used to sign session cookies and CSRF tokens | `SECRET_KEY` fell back to the literal `change-this-in-production` | [config.py](config.py) reads the key from the environment and `configuration_problems()` flags any key that is the default or shorter than 32 characters | `FLASK_ENV=production` with the default key now raises `RuntimeError: Refusing to start with insecure configuration`; development logs a `Security warning:` line and keeps running so the demo still works |
| 2 | Werkzeug debugger enabled | `app.run(debug=True)` was hard-coded in [app.py](app.py) | Debug now comes from the config (`DevelopmentConfig.DEBUG=True`, `ProductionConfig.DEBUG=False`) so the interactive debugger (RCE risk) can never be enabled by the production config | `app.config["DEBUG"]` is `True` in development and `False` in production |
| 3 | No security response headers | Responses carried only Flask defaults, so the app could be framed and had no CSP | `apply_security_headers()` in [app.py](app.py) adds `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy` and `Cross-Origin-Opener-Policy`; HSTS is added when cookies are HTTPS-only | `GET /auth/login` returns 200 with `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and a `Content-Security-Policy` header |
| 4 | No login brute-force protection | Unlimited password guesses against `/auth/login` and `/api/auth/login` | [rate_limit.py](rate_limit.py) counts failures per IP + username; both login paths call it. After 5 failures inside 300 s the key is locked for 300 s and returns HTTP 429 | 5 bad attempts → the 5th and any later attempt (even with the correct password) return 429; the JSON API returns 429 with `{"details": {"retry_after": 300}}`; a successful login clears the counter |
| 5 | Session cookie could travel over plain HTTP | `SESSION_COOKIE_SECURE` was unset | `SESSION_COOKIE_SECURE` / `REMEMBER_COOKIE_SECURE` are environment-driven and `ProductionConfig` defaults them to `True`, so cookies are only sent over HTTPS and HSTS is emitted | With `SESSION_COOKIE_SECURE=true` the `Set-Cookie` value includes `Secure` and responses include `Strict-Transport-Security` |

Mitigations that were **already** present and are worth documenting in the same
report: parameterised queries via SQLAlchemy, Jinja2 auto-escaping, Flask-WTF
CSRF tokens, Werkzeug password hashing, and role/record-level authorisation
shared by the UI and the API (see the table above).

Thresholds and the HTTPS-only cookies are configurable through the environment;
see [.env.example](.env.example).

## Tests

The suite runs against a throwaway in-memory SQLite database
(`FLASK_ENV=testing`), so it never touches the MySQL data or the demo database.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

[tests/conftest.py](tests/conftest.py) provides the fixtures: the app factory,
model factories (`make_user`, `make_application`, `make_vulnerability`), the
HTML login helper and the JWT helper. Coverage: authentication, RBAC for all
three roles, parameterised search, pagination, the JSON API, the report security
score and the CSV export.

## Roadmap

- [x] Four CRUD modules, sessions, RBAC, input validation, password hashing
- [x] JSON REST API under `/api` with JWT authentication
- [x] Three roles (`admin`, `user`, `client`) and an admin role-management UI
- [x] `README`, `.env.example`
- [x] MySQL as the default connection, with `seed.py` creating one account per role
- [x] Security hardening pass (strong `SECRET_KEY` from env, `DEBUG` off in
      production, security headers, login rate limiting / lockout)
- [x] OWASP Top 10 (2021) / CWE classification, evidence and remediation on findings
- [x] 0–100 security score with a letter grade, shown on the dashboard, the
      applications list and the report
- [x] `pytest` suite for auth, RBAC, search, the API and the export
- [x] Pagination, empty states and filters in the list views
- [x] CSV export of the findings list
- [x] Security testing report — see [report.md](report.md): scope, method,
      8 findings (identify → reproduce → mitigate → retest), verified controls,
      residual risk and a test-case matrix
- [ ] Git repository initialised and pushed to GitHub

---

**Author:** Sachin — BSc Cybersecurity, Nepal.
