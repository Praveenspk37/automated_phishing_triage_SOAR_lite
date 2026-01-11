import re
import csv
import whois
import requests
from datetime import datetime
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY

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
        return 20  # Assume unknown age is suspicious
    if days < 30:
        return 30
    elif days < 90:
        return 20
    return 0

def score_keywords(url):
    keywords = ["login", "verify", "reset", "update", "secure", "support", "password", "account"]
    return 50 if any(k in url.lower() for k in keywords) else 0

def score_virustotal(malicious, suspicious):
    score = 0
    if malicious > 5:
        score += 30
    elif malicious > 0:
        score += 20
    if suspicious > 0:
        score += 15
    return score

def get_virustotal_report(url):
    try:
        # Submit URL for scanning
        submit_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        data = {"url": url}
        response = requests.post(submit_url, headers=headers, data=data)
        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            # Get analysis report
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report_response = requests.get(report_url, headers=headers)
            if report_response.status_code == 200:
                stats = report_response.json()["data"]["attributes"]["stats"]
                return stats["malicious"], stats["suspicious"]
        return 0, 0
    except:
        return 0, 0

def get_abuseipdb_score(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()["data"]
            return data["abuseConfidenceScore"]
        return 0
    except:
        return 0

# -------------------------------
# Risk Scoring
# -------------------------------
def calculate_risk_score(url, domain_age, vt_malicious, vt_suspicious, ip_scores=None):
    score = 0
    score += score_domain_age(domain_age)
    score += score_keywords(url)
    score += score_virustotal(vt_malicious, vt_suspicious)
    if ip_scores:
        score += sum(ip_scores)  # Add IP abuse scores
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
    with open("samples/phish_password_reset.txt", "r") as f:
        content = f.read()

    urls = extract_urls(content)
    ips = extract_ips(content)
    ip_scores = [get_abuseipdb_score(ip) for ip in ips]
    results = []

    for url in urls:
        domain = url.split("/")[2]
        age = get_domain_age(domain)

        vt_malicious, vt_suspicious = get_virustotal_report(url)

        score = calculate_risk_score(url, age, vt_malicious, vt_suspicious, ip_scores)
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
