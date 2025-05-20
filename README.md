# Sentinel
Python Script for Automating 8 Most Common Findings Across Web-Application &amp; External Tests
# 🛡️ Sentinel - Passive Recon Scanner

**Sentinel** is a Python-based passive reconnaissance scanner designed to streamline early-stage web application assessments. Built for pentesters, red-teamers, and security engineers, Sentinel provides lightweight, no-auth checks to quickly surface misconfigurations, weak headers, outdated components, and potential injection points.

---

## 🔧 Features

- ✅ Missing Security Headers Detection
- 🔐 TLS Configuration & Cipher Suite Enumeration (nmap integration)
- 🧱 Backend Fingerprinting (Server, X-Powered-By, Cookies)
- 🧪 Reflected Injection Testing with Context Analysis
- 🔍 Sensitive Data Exposure (e.g. API keys, tokens, secrets)
- 🧠 Outdated Front-End Library Detection
- 🔓 Authentication Enumeration Differentiation
- 🚦 Rate Limiting Evaluation (POST to login paths)
- 📄 JSON Report Output with Rich Contextual Data

---

## 🖥️ Usage

```bash
python3 sentinel.py https://target.com
