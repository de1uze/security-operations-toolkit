# Security Operations Toolkit

A Python-based SOC analyst toolkit for threat intelligence, phishing analysis, and log parsing.

Built by **Pratik Shringarpure** — MS Cybersecurity @ Yeshiva University | SC-200 | Security+ | CCSK | ISC2 CC

---

## Tools

### 🔍 1. IOC Checker (`ioc_checker/ioc_checker.py`)
Enriches IPs, domains, and file hashes using VirusTotal and AbuseIPDB.

**Features:**
- Auto-detects IOC type (IP, domain, MD5, SHA1, SHA256)
- Parallel API queries for faster triage
- Color-coded threat intel report

**Usage:**
```bash
python3 ioc_checker.py --ioc 185.220.101.45
python3 ioc_checker.py --ioc malware.example.com
python3 ioc_checker.py --ioc 44d88612fea8a8f36de82e1278abb02f
```

### 📧 2. Phishing Analyzer (`phishing_analyzer/phishing_analyzer.py`)
*Coming soon*

### 📋 3. Log Parser (`log_parser/log_parser.py`)
*Coming soon*

---

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env  # add your API keys
```

## API Keys Required
- [VirusTotal](https://virustotal.com) — free tier
- [AbuseIPDB](https://abuseipdb.com) — free tier
