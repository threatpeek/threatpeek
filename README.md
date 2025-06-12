# 🛡️ ThreatPeek PH

A lightweight cybersecurity threat-scanning API built using **FastAPI**.  
Scan URLs for phishing, malware, and SSL issues, and generate human-friendly threat reports.

## 🚀 Features

- URL Reputation Check (VirusTotal, PhishTank)
- SSL Configuration Scan (SSL Labs)
- IP Threat Intel (AbuseIPDB)
- Domain/IP WHOIS Lookup
- PDF Summary Reports (Coming soon)
- JSON API Output

## 🔧 Tech Stack

- **Backend**: FastAPI (Python)
- **Report Gen**: ReportLab / WeasyPrint (optional)
- **Database**: SQLite (MVP), PostgreSQL (planned)
- **Caching**: Redis (optional)
- **Hosting**: Render, Railway, or VPS (planned)

## 📦 Installation

```bash
# Clone this repo
git clone https://github.com/erickills/ThreatPeekPH.git
cd threatpeek-ph

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
