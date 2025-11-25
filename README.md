# WebSecScanner
- Krushal Hirpara

Professional web application security assessment platform with a modern interface and built‑in scanners for XSS, SQL Injection, and CSRF. Designed around authenticated use, CSRF protection, and persistent scan history.

## Highlights

- **Scanners**: XSS (reflected, stored, DOM), SQLi (error/union/boolean/time‑based), CSRF protection checks.
- **Crawler**: Discovers forms and inputs to map the target’s attack surface.
- **Payloads**: Curated XSS and SQLi payload sets in `data/payloads/`.
- **Reports & History**: JSON/HTML outputs and recent scans per user.
- **Auth**: Login, signup, profile; the dashboard (`/`) requires login.
- **Security**: CSRF protection (`Flask‑WTF`), secure cookies, centralized logging, MongoDB persistence.

## Structure

```
app.py                          # Flask app: routes, auth, scanners, reports
config/settings.json            # Scanning configuration (modes, crawl depth, capabilities)
data/payloads/                  # XSS & SQLi payload sets
src/core/                       # Utilities, logger, DatabaseManager
src/scanners/                   # crawler.py, xss_scanner.py, sqli_scanner.py, csrf_scanner.py
src/web/static/style.css        # UI styling
src/web/templates/              # base, login, signup, profile, index, results, history, reports
render.yaml                     # Render deployment configuration (Gunicorn start)
requirements.txt                # Python dependencies
```

## Key Modules

- `src/scanners/crawler.py`: Enumerates links and forms; extracts inputs for testing.
- `src/scanners/xss_scanner.py`: Context‑aware XSS detection using multiple payload techniques.
- `src/scanners/sqli_scanner.py`: SQLi detection across error/union/boolean/time‑based methods.
- `src/scanners/csrf_scanner.py`: CSRF token presence/validation, cookie attributes, origin/referer checks.
- `src/core/database.py`: MongoDB persistence for users and scans.
- `src/core/logger.py`: Unified logging setup.
- `src/core/utils.py`: Shared security helpers.

## Configuration & Environment

- App configuration lives in `config/settings.json` (crawl depth, assessment modes, capability metadata).
- Environment variables (production): `FLASK_SECRET_KEY`, `MONGO_URI`, `FLASK_ENV`.
- Cookies are set `HttpOnly` and `SameSite=Lax`; `SESSION_COOKIE_SECURE` is enabled in production.
- CSRF protection is enabled globally via `Flask‑WTF CSRFProtect`.

## Ethics & Safety

- Test only systems you own or have explicit permission to assess.
- Follow applicable laws and responsible disclosure practices.
- Treat all reports and findings as sensitive data.

## Deployment

- Render configuration (`render.yaml`) uses Gunicorn: `app:app` with workers/threads.
- `PYTHON_VERSION` is pinned; secrets are provided via Render environment variables.

## Links

- Live App: https://websec-scanner-qdmo.onrender.com/
- Repository: https://github.com/KRUSHAL2956/WebSecScanner
