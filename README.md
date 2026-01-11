# Automated Phishing Triage (SOAR-Lite)

## Overview
This repository contains a **SOAR-lite phishing triage project** built as a
**self-initiated learning exercise** to demonstrate how automation can support
SOC phishing investigations.

The workflow automates **IOC extraction, threat enrichment, risk scoring, and
SOC-style reporting**, while keeping the **analyst in control of verdict decisions**.

⚠️ This is NOT a production SOAR system.  
⚠️ No automated blocking or remediation is performed.

---

## Key Capabilities
- Phishing IOC extraction (URLs, IPs)
- Threat intelligence enrichment (VirusTotal, WHOIS)
- Risk scoring logic (0–100)
- Analyst-driven recommendations
- CSV-based SOC reporting

---

## Tech Stack
- Python 3
- Regex
- VirusTotal API
- WHOIS
- CSV reporting

---

## How to Run

```bash
pip install -r requirements.txt
python phishing_triage.py
