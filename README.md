# 🛡️ Sentinel - Passive Recon Scanner

**Sentinel** is a Python-based passive reconnaissance scanner designed for penetration testers and security engineers who want quick visibility into common misconfigurations and weak points—without authentication or intrusive scanning.

It performs lightweight, contextual checks against a target web application and outputs a clean JSON report for triage, escalation, or inclusion in findings.

---

## 🔧 Features

- 🔒 **Missing Security Headers** detection
- 🔐 **TLS Misconfiguration & Cipher Suite Analysis** (via `nmap`)
- 🧱 **Backend Fingerprinting** (headers, cookies, server tech)
- 🧪 **Injection Point Detection** (reflected inputs + context type)
- 🔍 **Sensitive Data Exposure** (API keys, tokens, secrets)
- 📦 **Outdated JS/CSS/Meta Components**
- 🔓 **Auth Enumeration Detection** (differentiated error behavior)
- 🚦 **Rate Limiting Weaknesses**
- 🧠 **Contextual Snippets** and exact endpoints included in report

---

## 🚀 Quick Start

### 🐍 Requirements

Install dependencies:

```bash
pip install -r requirements.txt
