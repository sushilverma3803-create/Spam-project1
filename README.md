# SpamShield AI – Multi-Channel Spam & Threat Detection System

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask 3.0](https://img.shields.io/badge/Backend-Flask%203.0-green.svg)](https://palletsprojects.com/p/flask/)
[![React 18](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-cyan.svg)](https://react.dev/)
[![TailwindCSS](https://img.shields.io/badge/Styling-Tailwind%20CSS-blueviolet.svg)](https://tailwindcss.com/)
[![License: Educational](https://img.shields.io/badge/License-Educational%20Defensive%20Use-emerald.svg)](#educational-scope--privacy-guarantee)

> **SpamShield AI** is an intelligent cybersecurity threat analysis platform that detects and triages user-provided digital artifacts across four critical vectors:
> 1. **URL / Link Detection** (IP-in-URL, lexical entropy, brand typosquatting, high-risk TLDs)
> 2. **SMS / Message Detection** (Smishing keywords, delivery lures, shortlinks, urgency markers)
> 3. **Email Spam Detection** (Business Email Compromise, credential harvesting, urgent headers)
> 4. **Call Scam Detection** (Vishing transcript analysis for IRS/police impersonation, gift card & crypto wire coercion)

---

## 🛡️ Educational Scope & Privacy Guarantee

- **Zero Real-World Interception**: Does **not** access the user's active microphone, calls, inbox, contacts, or operating system telemetry.
- **Passive Link Analysis**: URLs are inspected structurally and lexically without loading or executing external client-side scripts.
- **Transcript-Only Vishing Module**: Analyzes user-pasted text transcripts or uploaded text files with optional caller ID metadata.
- **Automatic PII Redaction**: Phone numbers, emails, and sensitive patterns are automatically masked before saving to the audit database.

---

## 📁 Repository Structure

```text
Spam Project/
├── backend/
│   ├── app/
│   │   ├── config.py             # Environment configurations
│   │   ├── models/               # SQLAlchemy models (Scan, User, ChannelScans)
│   │   ├── routes/               # REST API blueprints (/api, /api/auth, /api/v1)
│   │   ├── services/             # Orchestration, demo data, & metric aggregation
│   │   ├── detectors/            # 4 Detector modules (URL, SMS, Email, Call)
│   │   └── utilities/            # JWT, rate limiter, PII redactor, response formatters
│   ├── requirements.txt          # Python dependencies (Flask, scikit-learn, etc.)
│   └── run.py                    # Flask development server
├── frontend/
│   ├── src/
│   │   ├── components/           # Threat badges, SVG risk gauge, Navbar, Modals
│   │   ├── context/              # AuthContext & ToastContext providers
│   │   ├── pages/                # Home, Dashboard, 4 Scanners, History, About, Auth
│   │   ├── services/             # API client & 10 educational sample datasets
│   │   └── App.jsx               # React Router layout container
│   ├── tailwind.config.js        # SOC dark theme tokens
│   └── vite.config.js            # Vite configuration with Flask reverse proxy
├── ml/
│   ├── preprocessor.py           # Text cleaning, entropy calculation, feature extraction
│   ├── model_trainer.py          # scikit-learn pipeline serialization
│   └── models/                   # Serialized ML model storage
├── database/                     # SQLite database storage (spamshield.db)
├── docs/                         # Specifications, architecture, API, and reports
├── tests/                        # 102 backend pytest test suites
├── .env.example                  # Environment variable template
└── README.md
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Python 3.10+** (tested on 3.10 through 3.14)
- **Node.js 18+** and **npm**

### 2. Backend Setup
```bash
# Install Python dependencies
pip install -r backend/requirements.txt

# Run backend test suite (102 tests)
python -m pytest tests/

# Start Flask Backend (runs on http://127.0.0.1:5000)
python backend/run.py
```

### 3. Frontend Setup
```bash
cd frontend

# Install Node dependencies
npm install

# Run frontend test suite (30 tests across 8 files)
npm test -- --run

# Build production bundle
npm run build

# Start Vite Development Server (runs on http://localhost:5173)
npm run dev
```

Visit **`http://localhost:5173`** in your browser to interact with SpamShield AI.

---

## 🔑 Preconfigured Demo Analyst Credentials

The application initializes SQLite database tables on startup and seeds a preconfigured analyst account:
- **Email / Username**: `analyst@spamshield.ai`
- **Password**: `SpamShield2026!`
- *(Or use the 1-Click "Use Preconfigured Demo Analyst Credentials" button on `/login`)*

---

## 📡 REST API Reference

| Endpoint | Method | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `GET /api/v1/health` | `GET` | No | System healthcheck and operational status |
| `POST /api/auth/login` | `POST` | No | Authenticate user & issue signed JWT Bearer token |
| `POST /api/auth/register` | `POST` | No | Register new security analyst account |
| `GET /api/auth/me` | `GET` | Yes | Retrieve authenticated analyst session profile |
| `GET /api/demo-data` | `GET` | No | Retrieve all 10 realistic educational demo datasets |
| `GET /api/demo-data/<channel>` | `GET` | No | Fetch demo samples for URL, MESSAGE, EMAIL, or CALL |
| `POST /api/scan/url` | `POST` | Optional | Passive structural, lexical, & TLD link inspection |
| `POST /api/scan/message` | `POST` | Optional | SMS / smishing ML TF-IDF and urgency analysis |
| `POST /api/scan/email` | `POST` | Optional | Email subject, body, deceptive anchor & BEC evaluation |
| `POST /api/scan/call-transcript` | `POST` | Optional | Vishing extortion, IRS coercion, & authority analysis |
| `GET /api/stats/summary` | `GET` | Yes | Real-time SQL aggregated dashboard KPI counters |
| `GET /api/stats/charts` | `GET` | Yes | Classification & channel distribution for Recharts |
| `GET /api/scans` | `GET` | Yes | Paginated, searchable, filterable audit history list |
| `DELETE /api/scans/<id>` | `DELETE` | Yes | Remove single audit record |
| `POST /api/scans/clear` | `POST` | Yes | Clear entire audit log |

---

## 📊 Standardized Response Schema

Every scanner returns a standardized contract:
```json
{
  "channel": "CALL_TRANSCRIPT",
  "classification": "HIGH_RISK_SCAM",
  "risk_score": 85,
  "confidence": 0.92,
  "reasons": [
    "Law enforcement arrest threat: 'arrest warrant' identified in call dialogue.",
    "Untraceable retail gift card demand: 'gift card' identified in call dialogue."
  ],
  "indicators": [
    { "type": "COERCION_INDICATOR", "value": "arrest warrant", "severity": "CRITICAL" },
    { "type": "COERCION_INDICATOR", "value": "gift card", "severity": "CRITICAL" }
  ],
  "recommendation": "IMMEDIATE DANGER: This is a high-pressure vishing scam. Do NOT send money, gift cards, or share OTPs. Hang up immediately."
}
```
