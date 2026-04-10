# phishing_analyzer.py
"""
Phishing Analyzer — Security Operations Toolkit
Author: Pratik Shringarpure
Purpose: Analyze raw email headers for phishing indicators
"""

import re
import sys
import argparse
import dns.resolver
from email import message_from_string
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


# ──────────────────────────────────────────────
# SECTION 1: HEADER PARSING
# ──────────────────────────────────────────────
# Python's built-in email library parses raw headers into a dict-like object.
# We extract the fields SOC analysts care about most.

def parse_headers(raw_email: str) -> dict:
    """
    Parses raw email text into structured fields.
    Uses Python's built-in email.message_from_string.
    """
    msg = message_from_string(raw_email)

    return {
        "from":        msg.get("From", ""),
        "reply_to":    msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "to":          msg.get("To", ""),
        "subject":     msg.get("Subject", ""),
        "message_id":  msg.get("Message-ID", ""),
        "received":    msg.get_all("Received", []),
        "auth_results": msg.get("Authentication-Results", ""),
        "spf":         msg.get("Received-SPF", ""),
        "dkim":        msg.get("DKIM-Signature", ""),
        "x_mailer":    msg.get("X-Mailer", ""),
        "body":        get_body(msg),
    }


def get_body(msg) -> str:
    """Extracts plain text body from email message object."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
                except Exception:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
        except Exception:
            body = msg.get_payload()
    return body


# ──────────────────────────────────────────────
# SECTION 2: SPF / DKIM / DMARC CHECKS
# ──────────────────────────────────────────────
# These are the three email authentication standards.
# SPF  — did the email come from an authorized server?
# DKIM — is the email cryptographically signed by the domain?
# DMARC — what should happen if SPF/DKIM fail?
# We check both what the headers claim AND do live DNS lookups.

def check_spf(headers: dict) -> dict:
    """
    Checks SPF result from Received-SPF header.
    Also does a live DNS lookup for the sender domain's SPF record.
    """
    spf_header = headers.get("spf", "").lower()
    from_domain = extract_domain(headers.get("from", ""))

    # What the receiving server reported
    if "pass" in spf_header:
        header_result = "PASS"
    elif "fail" in spf_header:
        header_result = "FAIL"
    elif "softfail" in spf_header:
        header_result = "SOFTFAIL"
    elif "neutral" in spf_header:
        header_result = "NEUTRAL"
    else:
        header_result = "NONE"

    # Live DNS lookup — does the domain even have an SPF record?
    dns_record = lookup_spf(from_domain)

    return {
        "header_result": header_result,
        "domain":        from_domain,
        "dns_record":    dns_record,
        "suspicious":    header_result in ["FAIL", "SOFTFAIL", "NONE"],
    }


def lookup_spf(domain: str) -> str:
    """Queries DNS TXT records to find SPF record for a domain."""
    if not domain:
        return "N/A"
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.startswith("v=spf1"):
                return txt
        return "No SPF record found"
    except Exception:
        return "DNS lookup failed"


def check_dkim(headers: dict) -> dict:
    """
    Checks if DKIM signature is present in headers.
    Note: Full DKIM cryptographic verification requires the email body
    which is out of scope for header-only analysis.
    """
    dkim_header = headers.get("dkim", "")
    auth_results = headers.get("auth_results", "").lower()

    present = bool(dkim_header)

    # Check authentication results header for dkim verdict
    if "dkim=pass" in auth_results:
        result = "PASS"
    elif "dkim=fail" in auth_results:
        result = "FAIL"
    elif present:
        result = "PRESENT (unverified)"
    else:
        result = "MISSING"

    return {
        "result":     result,
        "present":    present,
        "suspicious": result in ["FAIL", "MISSING"],
    }


def check_dmarc(headers: dict) -> dict:
    """
    Checks DMARC by doing a live DNS lookup on the sender domain.
    DMARC tells receiving servers what to do when SPF/DKIM fail.
    """
    from_domain = extract_domain(headers.get("from", ""))
    auth_results = headers.get("auth_results", "").lower()

    # Check authentication results header
    if "dmarc=pass" in auth_results:
        header_result = "PASS"
    elif "dmarc=fail" in auth_results:
        header_result = "FAIL"
    else:
        header_result = "NONE"

    # Live DNS lookup for DMARC record
    dns_record = lookup_dmarc(from_domain)

    return {
        "header_result": header_result,
        "domain":        from_domain,
        "dns_record":    dns_record,
        "suspicious":    header_result in ["FAIL", "NONE"],
    }


def lookup_dmarc(domain: str) -> str:
    """Queries DNS for DMARC record at _dmarc.domain."""
    if not domain:
        return "N/A"
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                return txt
        return "No DMARC record found"
    except Exception:
        return "DNS lookup failed"


# ──────────────────────────────────────────────
# SECTION 3: SPOOFING INDICATORS
# ──────────────────────────────────────────────
# Phishing emails often have mismatches between header fields.
# A legitimate email from paypal.com won't have a Reply-To at gmail.com.

def check_spoofing(headers: dict) -> list:
    """
    Checks for common spoofing and phishing indicators.
    Returns a list of finding dicts with description and severity.
    """
    findings = []

    from_addr    = headers.get("from", "")
    reply_to     = headers.get("reply_to", "")
    return_path  = headers.get("return_path", "")
    message_id   = headers.get("message_id", "")
    subject      = headers.get("subject", "")

    from_domain      = extract_domain(from_addr)
    reply_to_domain  = extract_domain(reply_to)
    return_path_domain = extract_domain(return_path)

    # Check 1: From domain vs Reply-To domain mismatch
    if reply_to and from_domain and reply_to_domain:
        if from_domain != reply_to_domain:
            findings.append({
                "check":    "From/Reply-To Mismatch",
                "detail":   f"From: {from_domain} | Reply-To: {reply_to_domain}",
                "severity": "HIGH",
            })

    # Check 2: From domain vs Return-Path domain mismatch
    if return_path and from_domain and return_path_domain:
        if from_domain != return_path_domain:
            findings.append({
                "check":    "From/Return-Path Mismatch",
                "detail":   f"From: {from_domain} | Return-Path: {return_path_domain}",
                "severity": "HIGH",
            })

    # Check 3: Message-ID domain mismatch
    if message_id:
        mid_domain = extract_domain(message_id)
        if mid_domain and from_domain and mid_domain != from_domain:
            findings.append({
                "check":    "Message-ID Domain Mismatch",
                "detail":   f"From: {from_domain} | Message-ID: {mid_domain}",
                "severity": "MEDIUM",
            })

    # Check 4: Urgency keywords in subject
    urgency_keywords = [
        "urgent", "immediate", "action required", "verify now",
        "suspended", "locked", "unusual activity", "confirm your",
        "click here", "limited time", "expires", "winner"
    ]
    subject_lower = subject.lower()
    matched = [kw for kw in urgency_keywords if kw in subject_lower]
    if matched:
        findings.append({
            "check":    "Urgency Keywords in Subject",
            "detail":   f"Matched: {', '.join(matched)}",
            "severity": "MEDIUM",
        })

    # Check 5: Suspicious X-Mailer
    x_mailer = headers.get("x_mailer", "").lower()
    suspicious_mailers = ["massmailer", "bulk", "phpmailer", "sendblaster"]
    if any(m in x_mailer for m in suspicious_mailers):
        findings.append({
            "check":    "Suspicious X-Mailer",
            "detail":   f"X-Mailer: {headers.get('x_mailer')}",
            "severity": "MEDIUM",
        })

    return findings


# ──────────────────────────────────────────────
# SECTION 4: URL EXTRACTION
# ──────────────────────────────────────────────
# Phishing emails hide malicious URLs in the body.
# We extract all URLs and flag suspicious patterns.

def extract_and_analyze_urls(body: str) -> list:
    """
    Extracts URLs from email body and flags suspicious patterns.
    """
    url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, body)

    analyzed = []
    for url in urls:
        flags = []

        # Flag IP-based URLs (no domain name — common in phishing)
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            flags.append("IP-based URL")

        # Flag URL shorteners
        shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "rb.gy"]
        if any(s in url for s in shorteners):
            flags.append("URL shortener")

        # Flag lookalike domains (e.g. paypa1.com, arnazon.com)
        lookalikes = ["paypa", "arnazon", "goggle", "micros0ft", "app1e", "faceb00k"]
        if any(l in url.lower() for l in lookalikes):
            flags.append("Lookalike domain")

        # Flag excessive subdomains (legitimate sites rarely use 3+ subdomains)
        domain_part = re.sub(r'https?://', '', url).split('/')[0]
        if domain_part.count('.') >= 3:
            flags.append("Excessive subdomains")

        # Flag non-HTTPS
        if url.startswith("http://"):
            flags.append("Non-HTTPS")

        analyzed.append({
            "url":   url[:80] + "..." if len(url) > 80 else url,
            "flags": flags,
            "suspicious": len(flags) > 0,
        })

    return analyzed


# ──────────────────────────────────────────────
# SECTION 5: HELPER FUNCTIONS
# ──────────────────────────────────────────────

def extract_domain(text: str) -> str:
    """Extracts domain from an email address or URL."""
    if not text:
        return ""
    # Try email address format first
    email_match = re.search(r'@([\w.-]+)', text)
    if email_match:
        return email_match.group(1).lower()
    # Try URL format
    url_match = re.search(r'https?://([\w.-]+)', text)
    if url_match:
        return url_match.group(1).lower()
    return ""


def calculate_risk_score(spf: dict, dkim: dict, dmarc: dict,
                          spoofing: list, urls: list) -> tuple:
    """
    Calculates overall phishing risk score (0-100).
    Returns (score, verdict).
    """
    score = 0

    if spf["suspicious"]:   score += 20
    if dkim["suspicious"]:  score += 20
    if dmarc["suspicious"]: score += 15

    for finding in spoofing:
        if finding["severity"] == "HIGH":   score += 20
        if finding["severity"] == "MEDIUM": score += 10

    suspicious_urls = [u for u in urls if u["suspicious"]]
    score += min(len(suspicious_urls) * 10, 25)

    score = min(score, 100)

    if score >= 70:
        verdict = "HIGH RISK"
    elif score >= 40:
        verdict = "MEDIUM RISK"
    elif score >= 10:
        verdict = "LOW RISK"
    else:
        verdict = "CLEAN"

    return score, verdict


# ──────────────────────────────────────────────
# SECTION 6: REPORT RENDERING
# ──────────────────────────────────────────────

SEVERITY_COLORS = {
    "HIGH":        "bold red",
    "MEDIUM":      "bold yellow",
    "LOW":         "bold green",
    "HIGH RISK":   "bold red",
    "MEDIUM RISK": "bold yellow",
    "LOW RISK":    "bold cyan",
    "CLEAN":       "bold green",
    "PASS":        "bold green",
    "FAIL":        "bold red",
    "SOFTFAIL":    "bold yellow",
    "MISSING":     "bold red",
    "NONE":        "dim",
}

def render_report(headers: dict, spf: dict, dkim: dict, dmarc: dict,
                  spoofing: list, urls: list):

    score, verdict = calculate_risk_score(spf, dkim, dmarc, spoofing, urls)
    color = SEVERITY_COLORS.get(verdict, "white")

    # Header panel
    console.print(Panel(
        f"[bold]From:[/bold]    {headers['from']}\n"
        f"[bold]Subject:[/bold] {headers['subject']}\n"
        f"[bold]Risk Score:[/bold] {score}/100\n"
        f"[bold]Verdict:[/bold] [{color}]{verdict}[/{color}]",
        title="[bold blue]📧 Phishing Analysis Report[/bold blue]",
        border_style="blue",
        expand=False
    ))

    # Auth results table
    auth_table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
    auth_table.add_column("Check")
    auth_table.add_column("Result")
    auth_table.add_column("Detail")

    spf_color  = "bold green" if not spf["suspicious"]  else "bold red"
    dkim_color = "bold green" if not dkim["suspicious"] else "bold red"
    dmarc_color = "bold green" if not dmarc["suspicious"] else "bold red"

    auth_table.add_row("SPF",   f"[{spf_color}]{spf['header_result']}[/{spf_color}]",   spf["dns_record"][:60])
    auth_table.add_row("DKIM",  f"[{dkim_color}]{dkim['result']}[/{dkim_color}]",        "Signature present" if dkim["present"] else "No signature")
    auth_table.add_row("DMARC", f"[{dmarc_color}]{dmarc['header_result']}[/{dmarc_color}]", dmarc["dns_record"][:60])
    console.print(Panel(auth_table, title="[cyan]Email Authentication[/cyan]", border_style="cyan"))

    # Spoofing indicators
    if spoofing:
        spoof_table = Table(box=box.SIMPLE_HEAD, header_style="bold red")
        spoof_table.add_column("Indicator")
        spoof_table.add_column("Severity")
        spoof_table.add_column("Detail")
        for f in spoofing:
            sev_color = SEVERITY_COLORS.get(f["severity"], "white")
            spoof_table.add_row(
                f["check"],
                f"[{sev_color}]{f['severity']}[/{sev_color}]",
                f["detail"]
            )
        console.print(Panel(spoof_table, title="[red]⚠ Spoofing Indicators[/red]", border_style="red"))
    else:
        console.print(Panel("[green]No spoofing indicators detected[/green]",
                           title="Spoofing Indicators", border_style="green"))

    # URL analysis
    if urls:
        url_table = Table(box=box.SIMPLE_HEAD, header_style="bold magenta")
        url_table.add_column("URL")
        url_table.add_column("Flags")
        for u in urls:
            flag_str = ", ".join(u["flags"]) if u["flags"] else "Clean"
            flag_color = "bold red" if u["suspicious"] else "bold green"
            url_table.add_row(u["url"], f"[{flag_color}]{flag_str}[/{flag_color}]")
        console.print(Panel(url_table, title="[magenta]🔗 URL Analysis[/magenta]", border_style="magenta"))

    console.rule()


# ──────────────────────────────────────────────
# SECTION 7: CLI ENTRYPOINT
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Phishing Analyzer — parse email headers for phishing indicators",
        epilog="Examples:\n"
               "  python3 phishing_analyzer.py --file email.txt\n"
               "  python3 phishing_analyzer.py --file suspicious.eml",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--file", required=True, help="Path to raw email file (.txt or .eml)")
    args = parser.parse_args()

    try:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            raw_email = f.read()
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] File not found: {args.file}")
        sys.exit(1)

    console.print(f"\n[dim]Analyzing email headers from[/dim] [bold]{args.file}[/bold]...\n")

    headers = parse_headers(raw_email)
    spf     = check_spf(headers)
    dkim    = check_dkim(headers)
    dmarc   = check_dmarc(headers)
    spoofing = check_spoofing(headers)
    urls    = extract_and_analyze_urls(headers["body"])

    render_report(headers, spf, dkim, dmarc, spoofing, urls)


if __name__ == "__main__":
    main()