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

---

### 📧 2. Phishing Analyzer (`phishing_analyzer/phishing_analyzer.py`)
Analyzes raw email headers for phishing and spoofing indicators.

**Features:**
- SPF, DKIM, DMARC validation with live DNS lookups
- From/Reply-To/Return-Path mismatch detection
- Urgency keyword and suspicious mailer detection
- URL extraction with IP-based, shortener, and lookalike domain flagging
- Risk score (0-100) with verdict

**Usage:**
```bash
python3 phishing_analyzer.py --file email.txt
python3 phishing_analyzer.py --file suspicious.eml
```

---

### 📋 3. Log Parser (`log_parser/log_parser.py`)
Parses Windows Event Logs, flags suspicious activity, and maps findings to MITRE ATT&CK.

**Features:**
- Parses Windows Event Log XML exports
- Detects brute force, privilege escalation, lateral movement, persistence, and defense evasion
- Maps 15+ Event IDs to MITRE ATT&CK techniques
- Flags suspicious processes (mimikatz, psexec, mshta, etc.)
- MITRE ATT&CK technique summary table

**Detected Event IDs:**
| Event ID | Description | MITRE Technique |
|----------|-------------|-----------------|
| 4625 | Failed Logon / Brute Force | T1110 |
| 4624 | Successful Logon | T1078 |
| 4688 | Suspicious Process Created | T1059 |
| 4720 | Backdoor Account Created | T1136 |
| 4732 | User Added to Admin Group | T1098 |
| 7045 | Malicious Service Installed | T1543 |
| 1102 | Audit Log Cleared | T1070 |

**Usage:**
```bash
python3 log_parser.py --file events.xml
```

---

## Setup

```bash
git clone https://github.com/de1uze/security-operations-toolkit.git
cd security-operations-toolkit
pip install -r requirements.txt
cp .env.example .env  # add your API keys
```

## API Keys Required
- [VirusTotal](https://virustotal.com) — free tier
- [AbuseIPDB](https://abuseipdb.com) — free tier

## Author
**Pratik Shringarpure**
MS Cybersecurity — Yeshiva University (GPA 3.98)
SC-200 | Security+ | CCSK | ISC2 CC | 365-day LetsDefend SOC streak
