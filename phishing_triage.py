import re
import csv
import whois
from datetime import datetime
from config import VIRUSTOTAL_API_KEY

# -------------------------------
# IOC Extraction
# -------------------------------
def extract_urls(text):
    return re.findall(r'https?://[^\s]+', text)

def extract_ips(text):
    return re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)

# -------------------------------
# Enrichment
# -------------------------------
def get_domain_age(domain):
    try:
        info = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        return (datetime.now() - creation).days if creation else None
    except:
        return None

def score_domain_age(days):
    if days is None:
        return 0
    if days < 30:
        return 30
    elif days < 90:
        return 20
    return 0

def score_keywords(url):
    keywords = ["login", "verify", "reset", "update", "secure"]
    return 10 if any(k in url.lower() for k in keywords) else 0

def score_virustotal(malicious, suspicious):
    score = 0
    if malicious > 5:
        score += 30
    elif malicious > 0:
        score += 20
    if suspicious > 0:
        score += 15
    return score

# -------------------------------
# Risk Scoring
# -------------------------------
def calculate_risk_score(url, domain_age, vt_malicious, vt_suspicious):
    score = 0
    score += score_domain_age(domain_age)
    score += score_keywords(url)
    score += score_virustotal(vt_malicious, vt_suspicious)
    return min(score, 100)

def recommendation(score):
    if score >= 70:
        return "High Risk - Escalation Recommended"
    elif score >= 40:
        return "Medium Risk - Analyst Review Required"
    return "Low Risk - Likely Benign"

# -------------------------------
# CSV Export
# -------------------------------
def export_to_csv(rows):
    with open("output/triage_report.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Indicator",
            "Domain Age (Days)",
            "VT Malicious",
            "VT Suspicious",
            "Risk Score",
            "Recommendation"
        ])
        writer.writerows(rows)

# -------------------------------
# Main
# -------------------------------
if __name__ == "__main__":
    with open("samples/sample_phishing_email.txt", "r") as f:
        content = f.read()

    urls = extract_urls(content)
    results = []

    for url in urls:
        domain = url.split("/")[2]
        age = get_domain_age(domain)

        # Mock VT values for learning/demo
        vt_malicious = 12
        vt_suspicious = 3

        score = calculate_risk_score(url, age, vt_malicious, vt_suspicious)
        results.append([
            url,
            age if age else "Unknown",
            vt_malicious,
            vt_suspicious,
            score,
            recommendation(score)
        ])

    export_to_csv(results)
    print("Triage report generated: output/triage_report.csv")
