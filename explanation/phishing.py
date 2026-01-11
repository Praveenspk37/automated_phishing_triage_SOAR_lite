import re  # Imports the 're' module for regular expressions, used for pattern matching in text.
import csv  # Imports the 'csv' module for reading and writing CSV files.
import whois  # Imports the 'whois' module to query domain registration information.
from datetime import datetime  # Imports 'datetime' class from 'datetime' module for date/time operations.
from config import VIRUSTOTAL_API_KEY  # Imports the VirusTotal API key from a config file (though not used in this code).

# -------------------------------
# IOC Extraction
# -------------------------------
def extract_urls(text):  # Defines a function to extract URLs from text.
    return re.findall(r'https?://[^\s]+', text)  # Uses regex to find all HTTP/HTTPS URLs in the text and returns them as a list.

def extract_ips(text):  # Defines a function to extract IP addresses from text.
    return re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)  # Uses regex to find all IPv4 addresses and returns them as a list.

# -------------------------------
# Enrichment
# -------------------------------
def get_domain_age(domain):  # Defines a function to get the age of a domain in days.
    try:  # Starts a try block to handle potential errors.
        info = whois.whois(domain)  # Queries WHOIS for the domain's information.
        creation = info.creation_date  # Extracts the creation date from the WHOIS data.
        if isinstance(creation, list):  # Checks if creation_date is a list (some WHOIS responses return lists).
            creation = creation[0]  # Takes the first date if it's a list.
        return (datetime.now() - creation).days if creation else None  # Calculates days since creation; returns None if no date.
    except:  # Catches any exceptions (e.g., domain not found).
        return None  # Returns None on error.

def score_domain_age(days):  # Defines a function to score domain age for risk assessment.
    if days is None:  # If no age data, score 0.
        return 0
    if days < 30:  # If less than 30 days old, high risk score.
        return 30
    elif days < 90:  # If less than 90 days old, medium risk score.
        return 20
    return 0  # Otherwise, low risk.

def score_keywords(url):  # Defines a function to score URLs based on suspicious keywords.
    keywords = ["login", "verify", "reset", "update", "secure"]  # List of suspicious keywords.
    return 10 if any(k in url.lower() for k in keywords) else 0  # Returns 10 if any keyword is in the URL (case-insensitive), else 0.

def score_virustotal(malicious, suspicious):  # Defines a function to score based on VirusTotal results.
    score = 0  # Initializes score.
    if malicious > 5:  # If more than 5 malicious detections, add 30.
        score += 30
    elif malicious > 0:  # If any malicious detections, add 20.
        score += 20
    if suspicious > 0:  # If any suspicious detections, add 15.
        score += 15
    return score  # Returns the total score.

# -------------------------------
# Risk Scoring
# -------------------------------
def calculate_risk_score(url, domain_age, vt_malicious, vt_suspicious):  # Defines a function to calculate overall risk score.
    score = 0  # Initializes score.
    score += score_domain_age(domain_age)  # Adds domain age score.
    score += score_keywords(url)  # Adds keyword score.
    score += score_virustotal(vt_malicious, vt_suspicious)  # Adds VirusTotal score.
    return min(score, 100)  # Caps the score at 100.

def recommendation(score):  # Defines a function to provide a recommendation based on score.
    if score >= 70:  # If score >= 70, high risk.
        return "High Risk - Escalation Recommended"
    elif score >= 40:  # If score >= 40, medium risk.
        return "Medium Risk - Analyst Review Required"
    return "Low Risk - Likely Benign"  # Otherwise, low risk.

# -------------------------------
# CSV Export
# -------------------------------
def export_to_csv(rows):  # Defines a function to export results to a CSV file.
    with open("output/triage_report.csv", "w", newline="", encoding="utf-8") as f:  # Opens the CSV file for writing.
        writer = csv.writer(f)  # Creates a CSV writer object.
        writer.writerow([  # Writes the header row.
            "Indicator",
            "Domain Age (Days)",
            "VT Malicious",
            "VT Suspicious",
            "Risk Score",
            "Recommendation"
        ])
        writer.writerows(rows)  # Writes all data rows.

# -------------------------------
# Main
# -------------------------------
if __name__ == "__main__":  # Ensures the code runs only if the script is executed directly.
    with open("samples/sample_phishing_email.txt", "r") as f:  # Opens the sample email file for reading.
        content = f.read()  # Reads the entire content of the file.

    urls = extract_urls(content)  # Extracts URLs from the email content.
    results = []  # Initializes an empty list for results.

    for url in urls:  # Loops through each extracted URL.
        domain = url.split("/")[2]  # Extracts the domain from the URL (e.g., 'example.com' from 'https://example.com/path').
        age = get_domain_age(domain)  # Gets the domain age.

        # Mock VT values for learning/demo  # Comment: These are placeholder values for demonstration.
        vt_malicious = 12  # Sets mock malicious count.
        vt_suspicious = 3  # Sets mock suspicious count.

        score = calculate_risk_score(url, age, vt_malicious, vt_suspicious)  # Calculates the risk score.
        results.append([  # Appends a row of data to results.
            url,  # The URL.
            age if age else "Unknown",  # Domain age or "Unknown".
            vt_malicious,  # Malicious count.
            vt_suspicious,  # Suspicious count.
            score,  # Risk score.
            recommendation(score)  # Recommendation.
        ])

    export_to_csv(results)  # Exports the results to CSV.
    print("Triage report generated: output/triage_report.csv")  # Prints a success message.