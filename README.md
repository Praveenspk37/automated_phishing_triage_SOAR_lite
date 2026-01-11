# Automated Phishing Triage (SOAR-Lite)

## Overview
This repository contains a **SOAR-lite phishing triage project** built as a
**self-initiated learning exercise** to demonstrate how automation can support
SOC phishing investigations.

The workflow automates **IOC extraction, threat enrichment, risk scoring, classification, and
SOC-style reporting**, while keeping the **analyst in control of verdict decisions**.

⚠️ This is NOT a production SOAR system.  
⚠️ No automated blocking or remediation is performed.

---

## Key Capabilities
- Phishing IOC extraction (URLs, IPs)
- Threat intelligence enrichment (VirusTotal, WHOIS, AbuseIPDB)
- Risk scoring logic (0–100)
- Email classification (True Positive for phishing, False Positive for spam/safe)
- Analyst-driven recommendations
- CSV-based SOC reporting for multiple email samples

---

## Tech Stack
- Python 3
- Regex
- VirusTotal API
- AbuseIPDB API
- WHOIS
- CSV reporting

---

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Praveenspk37/automated_phishing_triage_SOAR_lite.git
   cd automated_phishing_triage_SOAR_lite
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # On Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure API keys in `config.py`:
   - Obtain a VirusTotal API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
   - Obtain an AbuseIPDB API key from [AbuseIPDB](https://www.abuseipdb.com/register)
   - Update `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` in `config.py`

---

## How to Run

Run the triage script:
```bash
python main.py
```

The script processes all `.txt` files in the `samples/` folder, extracts indicators, enriches with APIs, scores risks, classifies emails, and generates a CSV report in `output/triage_report.csv`.

---

## Sample Data

The `samples/` folder contains example email files:
- `phish_*.txt`: True positive phishing emails
- `fp_*.txt`: False positive safe emails
- `spam_*.txt`: False positive spam emails

---

## Output

The `output/triage_report.csv` includes:
- File Name
- Classification (True Positive / False Positive)
- Indicator (URL or "No URLs found")
- Domain Age
- VT Malicious/Suspicious counts
- Risk Score
- Recommendation

For true positives, recommendations are based on risk score. For false positives, it's "False Positive - No Escalation".

---

## Workflow

1. **IOC Extraction**: Regex-based extraction of URLs and IPs from email content.
2. **Enrichment**: Query WHOIS for domain age, VirusTotal for URL reputation, AbuseIPDB for IP abuse scores.
3. **Scoring**: Calculate risk score based on domain age, keywords, VT results, and IP scores.
4. **Classification**: Label emails as True Positive (phishing) or False Positive based on filename.
5. **Reporting**: Generate CSV with all details for SOC review.

---

## Disclaimer

This project is for educational purposes only. Use real API keys responsibly and respect rate limits. Do not use in production without proper security reviews.
