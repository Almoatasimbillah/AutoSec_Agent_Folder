# 🛡️ Autonomous Security Research Agent (AutoSec Agent)

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests: 48 Passing](https://img.shields.io/badge/tests-48%20passed%20(100%25)-brightgreen.svg)](tests/)

> An architecture-first, scientific security research and bug bounty auditing platform with deterministic scope enforcement (Action Gate), multi-framework route mining, passive interception proxy, differential parameter anomaly detection, and visual exploit chaining.

---

## 🚀 Key Features & Pillars

### 1. 🕷️ Smart SPA Route & Endpoint Crawler
- Inspects HTML DOM anchors and forms.
- Regex-based mining of modern frontend routes (Angular Router, React Router, Vue, and SPA hash routing).
- Deep inspection of JavaScript bundles (`*.bundle.js`, `vendor.js`, `app.js`) for internal REST API endpoints (`/api/...`, `/rest/...`, `/v1/...`, `/graphql`).
- 100% strictly filtered through the deterministic `ActionGate`.

### 2. 🛰️ Built-in Passive Interception Proxy (`127.0.0.1:8085`)
- Lightweight native asyncio proxy without external binary dependencies.
- Zero active attacks: passively inspects regular browser traffic.
- Automatic detection of sensitive token leaks (JWT, Bearer, API keys, session tokens).
- Flags missing defense headers (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `HSTS`).
- 1-Click forwarding to Request Repeater or Parameter Miner.

### 3. 🧪 Differential Parameter Miner & Anomaly Detector
- Non-destructive canary probing against top 30 bug bounty high-impact parameters.
- Detects status code drift (e.g. `200 -> 500` or `401 -> 200`).
- Classifies reflection context (`SCRIPT_BLOCK`, `JSON_RESPONSE`, `HTML_ATTRIBUTE`, `HTML_BODY`).
- Measures response length variances with anomaly risk scoring.

### 4. 🕸️ Vulnerability Chaining & Visual Attack Graph
- Correlates isolated findings into multi-step compound exploit chains:
  - *Secret Leak → IDOR / BOLA Endpoint → Data Exfiltration*
  - *Permissive CORS → Missing CSRF → Account Takeover*
  - *Missing Clickjacking Headers → State-Changing CSRF → Unauthorized Action*
- Calculates compound **CVSS 3.1** scores and remediation priorities.

### 5. 🎯 Tactical Playbooks & Bug Bounty Writeups
- Pre-loaded with offensive playbooks matching modern tech stacks (Node, Express, Angular, JWT, OAuth, GraphQL).
- Import custom writeups and articles from HackerOne, Bugcrowd, or blogs to generate instant test hypotheses.

### 6. 🔁 Burp Suite-Style Request Repeater & AI Security Co-Pilot
- Interactive manual request modifier with automatic researcher header injection.
- Real-time AI advisory for HTTP response analysis (e.g., 403 Forbidden bypass advice, IDOR validation, CORS triage).

---

## 🏗️ Architecture & Philosophy

```text
┌─────────────────────────────────────────────────────────────┐
│                    Action Gate (Firewall)                   │
│  - Default-Deny Scope Engine (Wildcard, Domain, CIDR)      │
│  - Policy Verification (Rate Limiting, Header Injection)    │
└──────────────────────────────▲──────────────────────────────┘
                               │
┌──────────────────────────────┴──────────────────────────────┐
│                    Orchestration Engine                     │
│  - Scientific Hypothesis Engine (Observe -> Formulate -> Disprove)
│  - Multi-Account Identity Manager (Context A vs B vs Anon)  │
│  - Target Model & Hierarchical Attack Surface Graph         │
│  - Physical SQLite DB & SHA-256 Evidence Vault per Target   │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/YOUR_USERNAME/autonomous-security-agent.git
cd autonomous-security-agent

# Create virtual environment
python -m venv .venv

# Activate on Windows:
.venv\Scripts\activate
# Activate on Linux/macOS:
# source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Test Suite
```bash
pytest -v tests/
# 48 passed (100%)
```

### 3. Launch Mission Control Dashboard
```bash
# On Windows:
start_server.bat

# Or run directly with Python:
python -m src.web.server
```
Open **`http://localhost:8000`** in your browser to access the Mission Control UI.

---

## 🛡️ Responsible Disclosure & Safety Guidelines
- This tool is built exclusively for authorized penetration testing, bug bounty programs, and defensive security research.
- Always obtain written authorization before testing any target.
- The `ActionGate` defaults to **STRICT DEFAULT-DENY** to prevent accidental out-of-scope testing.

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
