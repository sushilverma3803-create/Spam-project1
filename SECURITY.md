# SpamShield AI Security Model & Security Review

This document outlines the defensive security architecture, vulnerability audit findings, threat model, and operational guidelines for **SpamShield AI**.

---

## 1. Threat Model & Architecture Overview

SpamShield AI is an educational and enterprise threat triage engine designed to inspect multi-channel threat indicators (URLs, SMS/text messages, emails, and voice call transcripts).

```
                      +---------------------------------------+
                      |           Client Browser              |
                      |   (Vite + React Single Page App)      |
                      +-------------------+-------------------+
                                          |
                      HTTPS + Bearer JWT  | Inert text display only
                      (Zero cookies)      | (No auto-opening URLs)
                                          v
                      +---------------------------------------+
                      |         Flask API Gateway             |
                      |  - Security Headers (CSP, HSTS, etc.)  |
                      |  - Sliding-Window Rate Limiting       |
                      |  - Payload Size & Type Validation     |
                      |  - JWT Authentication Middleware      |
                      +-------------------+-------------------+
                                          |
                        +-----------------+-----------------+
                        |                                   |
                        v                                   v
        +-------------------------------+   +-------------------------------+
        |   Passive Threat Detectors    |   |      Relational Storage       |
        |  - URL Structural / Lexical   |   |  - SQLAlchemy ORM             |
        |  - SMS Baits / Shortlinks     |   |  - Automated PII Redaction    |
        |  - Email Lures / Headers      |   |  - Scrypt Password Hashing    |
        |  - Call Coercion Heuristics   |   |  - SQLite / PostgreSQL        |
        |  * ZERO outbound HTTP calls   |   |  * Zero plaintext passwords   |
        +-------------------------------+   +-------------------------------+
```

### Trust Boundaries
1. **Untrusted Input**: User-submitted URLs, text messages, email bodies, sender IDs, and transcripts are strictly treated as untrusted, hostile data.
2. **Execution Boundary**: Submitted text is parsed and categorized using internal lexical, heuristic, and trained machine learning pipelines. **No untrusted input is ever executed, evaluated, rendered as raw HTML, or resolved over live network sockets.**
3. **Storage Boundary**: Raw user input undergoes PII redaction (masking credit cards, phone numbers, SSNs, and emails) prior to database persistence.

---

## 2. Vulnerability Review & Defensive Countermeasures

| Vulnerability Category | Risk Status | Countermeasures & Implementation |
| :--- | :--- | :--- |
| **SQL Injection (SQLi)** | **Immune** | 100% of database interactions leverage the **SQLAlchemy 2.0 ORM** with parameterized queries (`db.session.query`, `filter_by`, `ilike`). No dynamic SQL string concatenation exists in the backend. |
| **Cross-Site Scripting (XSS)** | **Mitigated** | Frontend built in React with automatic JSX contextual string escaping. Zero occurrences of `dangerouslySetInnerHTML`, `innerHTML`, or `eval()`. Strict Content-Security-Policy (CSP) headers block unauthorized script injection. |
| **Cross-Site Request Forgery (CSRF)** | **Mitigated** | Stateless authentication using cryptographic `Authorization: Bearer <token>` HTTP headers. The API does not rely on ambient credentials or ambient session cookies, rendering cross-site forged requests ineffective. |
| **Insecure CORS** | **Enforced** | `flask-cors` restricts cross-origin resource sharing to explicitly whitelisted origins (`CORS_ORIGINS`). Comma-separated entries are trimmed and sanitized against wildcard credential abuse. |
| **Insecure File Upload** | **N/A** | The application does not expose file upload endpoints. Scans accept JSON text payloads exclusively. |
| **Path Traversal & LFI** | **Mitigated** | Model weights are loaded strictly from static, hardcoded relative paths (`ml/models/*.joblib`). User input never dictates filesystem paths or file handles. |
| **Command Injection** | **Immune** | No system shell invocations (`os.system`, `subprocess`, `popen`) exist within the application logic. |
| **Unsafe URL Fetching (SSRF)** | **Mitigated** | **Strict Passive Analysis**: The URL detection module (`URLAnalyzerService`) executes offline lexical and heuristic inspection only. It makes **zero** outbound HTTP/HTTPS, DNS, or socket requests. |
| **Unrestricted Input Size (DoS)** | **Enforced** | Global `MAX_CONTENT_LENGTH` caps payloads at 5 MB. Endpoint-specific bounds enforce: URL <= 2,048 chars, Message <= 50,000 chars, Email body <= 500,000 chars, Call transcript <= 500,000 chars, Password <= 128 chars, Email <= 254 chars. |
| **Sensitive Information Leakage** | **Mitigated** | User model `to_dict()` strictly omits `password_hash`. `pii_redactor.py` masks sensitive credentials, phone numbers, and payment cards before saving audit records. |
| **Plaintext Passwords** | **Eliminated** | Passwords are cryptographically salted and hashed using **Werkzeug scrypt/PBKDF2** algorithms (`generate_password_hash`). Passwords under 6 or over 128 characters are rejected. |
| **Exposed Environment Variables** | **Secured** | Sensitive keys (`SECRET_KEY`, `JWT_SECRET_KEY`, `DATABASE_URL`) are read via `python-dotenv`. `.env` and `.env.production` are strictly ignored by `.gitignore`. |
| **Verbose Production Errors** | **Eliminated** | Global exception handlers catch unhandled errors and return sanitized JSON messages (`{"success": False, "error": "An internal error occurred."}`). Internal tracebacks are logged exclusively to the server logger. |
| **Missing API Validation** | **Hardened** | Every analysis and authentication route validates types, schema structure, non-empty content, and boundary limits, returning descriptive HTTP 400 Bad Request responses. |
| **Missing Rate Limiting** | **Enforced** | Thread-safe sliding-window rate limiters enforce limits per IP: **20 requests/minute** for `/api/auth/*` (brute-force defense) and **60 requests/minute** for `/api/*` scan endpoints. Stale memory records are automatically pruned. |

---

## 3. URL Security & Passive Isolation Policy

### Core Rule: Zero Automatic Execution
> **The application must never automatically execute, navigate to, or interact with submitted suspicious URLs.**

1. **Passive Inspection**:
   - The link detector analyzes structural indicators: IP host usage, Punycode/IDN homoglyph prefixes (`xn--`), suspicious TLD patterns (`.xyz`, `.top`, `.click`), subdomain depth, entropy scores, and social engineering keywords (`login`, `verify`, `banking`).
   - The server does not perform HTTP requests, does not follow redirects over the wire, and does not perform active DNS resolution on submitted targets.
2. **Display Isolation**:
   - The user interface renders submitted URLs purely as non-interactive plain text (`<span>`, `<p>`, `<pre>`).
   - URLs are **never** rendered within clickable `<a href="...">` tags, `window.open()` handlers, or embedded `<iframe>` elements.
3. **Future URL Reputation Integration Architecture**:
   - If third-party reputation feeds (e.g., Google Safe Browsing, VirusTotal, AbuseIPDB) are integrated:
     - All queries must be performed via **backend-to-backend API calls using cryptographic hashes or sanitized domain queries**.
     - The end-user browser must **never** be directed to or communicate with the target URL.
     - Live rendering or sandbox screenshots must only be generated inside an isolated, disposable container environment (e.g., headless sandboxed Chromium inside an ephemeral Docker container) with network egress controls.

---

## 4. HTTP Security Headers

The backend sets defense-in-depth HTTP security headers on all responses via the application factory (`backend/app/__init__.py`):

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: cross-origin
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self' http://localhost:5173 http://127.0.0.1:5173 http://localhost:5000 http://127.0.0.1:5000; frame-ancestors 'none'; form-action 'self';
Strict-Transport-Security: max-age=31536000; includeSubDomains (production only)
```

---

## 5. Dependency Audit Documentation

### Python Environment Audit
- **Flask**: 3.1.3 (Up-to-date, secure WSGI framework)
- **Werkzeug**: 3.1.8 (Provides modern scrypt password hashing)
- **SQLAlchemy**: 2.0.54 (Secure parameterized query engine)
- **PyJWT**: 2.14.0 (RFC 7519 cryptographic token signing)
- **scikit-learn**: 1.9.1 (Isolated offline ML classification)
- **cryptography**: 50.0.1 (Underlying cryptographic primitives)

### Node.js / React Frontend Audit
- **React**: 18.3.1
- **Vite**: 6.4.3
- **Lucide React**: 0.460.0
- **Recharts**: 2.13.3
- **React Router DOM**: 6.28.0

#### Advisory Assessment (`npm audit`):
- `react-router` 6.28.0 reports moderate advisories regarding:
  1. *Open redirect via backslash in `<Link>`/`useNavigate` (CVE-2025-68470 bypass)*:
     - **Status in SpamShield**: Non-impacted. SpamShield routes are strictly static internal routes (`/dashboard`, `/history`, `/scan/*`, `/login`). No user-controlled redirect URLs or backslash-prefixed paths are accepted by navigation handlers.
  2. *Constructor injection via `deserializeErrors()` in SSR hydration*:
     - **Status in SpamShield**: Non-impacted. SpamShield is bundled as a purely client-side Single Page Application (SPA); no Server-Side Rendering (SSR) hydration is utilized.

---

## 6. Known Limitations & Production Recommendations

1. **Distributed Rate Limiting**:
   - *Current*: In-memory sliding window rate limiter per process.
   - *Recommendation*: For multi-process/multi-server deployments (e.g. Gunicorn/uWSGI with multiple workers), configure a shared **Redis** or **Memcached** backend for distributed rate synchronization.
2. **Database Engine**:
   - *Current*: SQLite in `database/spamshield.db` (ideal for local triage, demonstrations, and test suites).
   - *Recommendation*: Migrate `DATABASE_URL` to PostgreSQL with connection pooling (e.g., PgBouncer) for high-concurrency production deployments.
3. **Token Revocation (Denylist)**:
   - *Current*: Stateless JWTs expire after 24 hours. Logout is enforced client-side by clearing stored tokens.
   - *Recommendation*: Implement a fast-lookup Redis token denylist or refresh token rotation for instantaneous revocation upon administrator action.
4. **Proxy Header Trust**:
   - *Current*: `TRUST_PROXIES` is set to `False` by default, preventing spoofed `X-Forwarded-For` headers from bypassing IP rate limiting.
   - *Recommendation*: Enable `TRUST_PROXIES=True` only when deployed behind a validated reverse proxy (such as Nginx, Cloudflare, or AWS ALB) that strips untrusted upstream headers.
