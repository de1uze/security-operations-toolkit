# ioc_checker.py
"""
IOC Checker — Security Operations Toolkit
Author: Pratik Shringarpure
Purpose: Enrich IPs, domains, and file hashes using VirusTotal + AbuseIPDB
"""

import re
import sys
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
# from config import (
#     VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY,
#     VT_BASE, ABUSEIPDB_BASE
# )

console = Console()  # Rich's output engine — used instead of print()
import os
from dotenv import load_dotenv
load_dotenv(dotenv_path="/Users/dominoexe/Documents/Projects/security-operations-toolkit/ioc_checker/.env")
print("KEY:", os.getenv("38091f5ec7f00e1f72d17998506ba33bc9e08e59801cce574b953166ef1c6fe7"))


VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

# ──────────────────────────────────────────────
# SECTION 1: IOC TYPE DETECTION
# ──────────────────────────────────────────────
# A SOC analyst instantly knows what kind of IOC they're looking at.
# We replicate that with regex patterns.

def detect_ioc_type(ioc: str) -> str:
    """
    Detects whether the input is an IP address, domain, MD5, SHA1, or SHA256.
    Returns a string label used to route to the right API endpoint.
    """
    ip_pattern     = r"^\d{1,3}(\.\d{1,3}){3}$"
    domain_pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    md5_pattern    = r"^[a-fA-F0-9]{32}$"
    sha1_pattern   = r"^[a-fA-F0-9]{40}$"
    sha256_pattern = r"^[a-fA-F0-9]{64}$"

    if re.match(ip_pattern, ioc):
        return "ip"
    elif re.match(sha256_pattern, ioc):
        return "sha256"
    elif re.match(sha1_pattern, ioc):
        return "sha1"
    elif re.match(md5_pattern, ioc):
        return "md5"
    elif re.match(domain_pattern, ioc):
        return "domain"
    else:
        return "unknown"

    # NOTE: Order matters — check hashes before domain because a 40-char hex
    # string could theoretically match a loose domain regex.


# ──────────────────────────────────────────────
# SECTION 2: VIRUSTOTAL API
# ──────────────────────────────────────────────
# VT has different endpoints per IOC type, but returns the same
# stats structure: how many AV engines flagged this IOC as malicious.

def query_virustotal(ioc: str, ioc_type: str) -> dict:
    """
    Queries the VirusTotal v3 API.
    Returns a normalized dict with verdict, malicious count, and total engines.
    """
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    # Route to the correct VT endpoint based on IOC type
    endpoint_map = {
        "ip":     f"{VT_BASE}/ip_addresses/{ioc}",
        "domain": f"{VT_BASE}/domains/{ioc}",
        "md5":    f"{VT_BASE}/files/{ioc}",
        "sha1":   f"{VT_BASE}/files/{ioc}",
        "sha256": f"{VT_BASE}/files/{ioc}",
    }

    url = endpoint_map.get(ioc_type)
    if not url:
        return {"error": "Unsupported IOC type for VirusTotal"}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # raises HTTPError for 4xx/5xx responses
        data = response.json()

        # VT buries the useful data in data → attributes → last_analysis_stats
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())

        # Derive a simple verdict so we don't have to re-interpret this later
        if malicious >= 5:
            verdict = "MALICIOUS"
        elif malicious >= 1 or suspicious >= 3:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "source":     "VirusTotal",
            "verdict":    verdict,
            "malicious":  malicious,
            "suspicious": suspicious,
            "total":      total,
            "ratio":      f"{malicious}/{total}",
        }

    except requests.exceptions.Timeout:
        return {"source": "VirusTotal", "error": "Request timed out"}
    except requests.exceptions.HTTPError as e:
        return {"source": "VirusTotal", "error": f"HTTP {e.response.status_code}"}
    except (KeyError, ValueError) as e:
        return {"source": "VirusTotal", "error": f"Unexpected response format: {e}"}


# ──────────────────────────────────────────────
# SECTION 3: ABUSEIPDB API
# ──────────────────────────────────────────────
# AbuseIPDB is IP-only — it crowdsources abuse reports.
# Key signal: abuseConfidenceScore (0-100). Above 80 is a strong flag.

def query_abuseipdb(ip: str) -> dict:
    """
    Queries AbuseIPDB for IP reputation.
    Only valid for IP-type IOCs.
    """
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress":    ip,
        "maxAgeInDays": 90,   # look back 90 days of abuse reports
        "verbose":      True  # includes individual report details
    }

    try:
        response = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers=headers,
            params=params,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()["data"]

        score = data.get("abuseConfidenceScore", 0)

        if score >= 80:
            verdict = "MALICIOUS"
        elif score >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "source":        "AbuseIPDB",
            "verdict":       verdict,
            "score":         score,
            "country":       data.get("countryCode", "N/A"),
            "isp":           data.get("isp", "N/A"),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", "Never"),
            "usage_type":    data.get("usageType", "N/A"),
        }

    except requests.exceptions.Timeout:
        return {"source": "AbuseIPDB", "error": "Request timed out"}
    except requests.exceptions.HTTPError as e:
        return {"source": "AbuseIPDB", "error": f"HTTP {e.response.status_code}"}
    except (KeyError, ValueError) as e:
        return {"source": "AbuseIPDB", "error": f"Unexpected response format: {e}"}


# ──────────────────────────────────────────────
# SECTION 4: PARALLEL QUERY ORCHESTRATION
# ──────────────────────────────────────────────
# Instead of querying VT then AbuseIPDB sequentially (slow),
# we fire both requests at the same time using threads.

def enrich_ioc(ioc: str, ioc_type: str) -> dict:
    """
    Dispatches API queries in parallel and aggregates results.
    Uses ThreadPoolExecutor — ideal for I/O-bound tasks like HTTP calls.
    """
    results = {}

    # Build a task list — only include AbuseIPDB if the IOC is an IP
    tasks = {"virustotal": (query_virustotal, [ioc, ioc_type])}
    if ioc_type == "ip":
        tasks["abuseipdb"] = (query_abuseipdb, [ioc])

    # max_workers=2 — one thread per API call
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(fn, *args): name
            for name, (fn, args) in tasks.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = {"error": str(e)}

    return results


# ──────────────────────────────────────────────
# SECTION 5: REPORT RENDERING
# ──────────────────────────────────────────────
# Rich lets us build scannable, color-coded output.
# In a real SOC, you're triaging quickly — formatting matters.

VERDICT_COLORS = {
    "MALICIOUS":  "bold red",
    "SUSPICIOUS": "bold yellow",
    "CLEAN":      "bold green",
    "UNKNOWN":    "dim",
}

def render_report(ioc: str, ioc_type: str, results: dict):
    """Renders the enriched threat intel report to the terminal."""

    # Derive overall verdict from all sources (worst case wins)
    verdicts = [
        r.get("verdict", "UNKNOWN")
        for r in results.values()
        if "error" not in r
    ]
    if "MALICIOUS" in verdicts:
        overall = "MALICIOUS"
    elif "SUSPICIOUS" in verdicts:
        overall = "SUSPICIOUS"
    elif "CLEAN" in verdicts:
        overall = "CLEAN"
    else:
        overall = "UNKNOWN"

    color = VERDICT_COLORS[overall]

    # Header panel
    console.print(Panel(
        f"[bold]IOC:[/bold] {ioc}\n"
        f"[bold]Type:[/bold] {ioc_type.upper()}\n"
        f"[bold]Overall Verdict:[/bold] [{color}]{overall}[/{color}]",
        title="[bold blue]🔍 IOC Enrichment Report[/bold blue]",
        border_style="blue",
        expand=False
    ))

    # VirusTotal section
    vt = results.get("virustotal", {})
    if "error" in vt:
        console.print(f"[red]VirusTotal Error:[/red] {vt['error']}")
    else:
        vt_table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
        vt_table.add_column("Metric")
        vt_table.add_column("Value")
        vt_color = VERDICT_COLORS.get(vt["verdict"], "white")
        vt_table.add_row("Verdict",    f"[{vt_color}]{vt['verdict']}[/{vt_color}]")
        vt_table.add_row("Detection",  vt["ratio"])
        vt_table.add_row("Malicious",  str(vt["malicious"]))
        vt_table.add_row("Suspicious", str(vt["suspicious"]))
        vt_table.add_row("Total Engines", str(vt["total"]))
        console.print(Panel(vt_table, title="[cyan]VirusTotal[/cyan]", border_style="cyan"))

    # AbuseIPDB section (IP only)
    ab = results.get("abuseipdb", {})
    if ab:
        if "error" in ab:
            console.print(f"[red]AbuseIPDB Error:[/red] {ab['error']}")
        else:
            ab_table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold magenta")
            ab_table.add_column("Metric")
            ab_table.add_column("Value")
            ab_color = VERDICT_COLORS.get(ab["verdict"], "white")
            ab_table.add_row("Verdict",       f"[{ab_color}]{ab['verdict']}[/{ab_color}]")
            ab_table.add_row("Abuse Score",   f"{ab['score']}/100")
            ab_table.add_row("Country",       ab["country"])
            ab_table.add_row("ISP",           ab["isp"])
            ab_table.add_row("Usage Type",    ab["usage_type"])
            ab_table.add_row("Total Reports", str(ab["total_reports"]))
            ab_table.add_row("Last Reported", ab["last_reported"])
            console.print(Panel(ab_table, title="[magenta]AbuseIPDB[/magenta]", border_style="magenta"))

    console.rule()


# ──────────────────────────────────────────────
# SECTION 6: CLI ENTRYPOINT
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="IOC Checker — query VirusTotal + AbuseIPDB for threat intel",
        epilog="Examples:\n"
               "  python ioc_checker.py --ioc 8.8.8.8\n"
               "  python ioc_checker.py --ioc malware.example.com\n"
               "  python ioc_checker.py --ioc 44d88612fea8a8f36de82e1278abb02f",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--ioc", required=True, help="IP address, domain, or file hash to check")
    args = parser.parse_args()

    ioc = args.ioc.strip().lower()
    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "unknown":
        console.print("[red]Error:[/red] Could not detect IOC type. Provide a valid IP, domain, MD5, SHA1, or SHA256.")
        sys.exit(1)

    console.print(f"\n[dim]Querying threat intel for[/dim] [bold]{ioc}[/bold] [dim](type: {ioc_type})...[/dim]\n")

    results = enrich_ioc(ioc, ioc_type)
    render_report(ioc, ioc_type, results)


if __name__ == "__main__":
    main()