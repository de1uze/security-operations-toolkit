# log_parser.py
"""
Log Parser — Security Operations Toolkit
Author: Pratik Shringarpure
Purpose: Parse Windows Event Logs, flag suspicious activity, map to MITRE ATT&CK
"""

import re
import sys
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


# ──────────────────────────────────────────────
# SECTION 1: MITRE ATT&CK MAPPING
# ──────────────────────────────────────────────
# This is the heart of the tool — mapping raw Windows Event IDs
# to real adversary techniques. This is exactly what a SOC analyst
# does manually; we're automating it.

MITRE_MAP = {
    4624: {
        "name":        "Successful Logon",
        "technique":   "T1078",
        "tactic":      "Defense Evasion / Persistence",
        "description": "Valid account logon — monitor for unusual hours or sources",
        "severity":    "LOW",
    },
    4625: {
        "name":        "Failed Logon",
        "technique":   "T1110",
        "tactic":      "Credential Access",
        "description": "Failed authentication — multiple failures indicate brute force",
        "severity":    "MEDIUM",
    },
    4648: {
        "name":        "Explicit Credential Logon",
        "technique":   "T1134",
        "tactic":      "Defense Evasion / Privilege Escalation",
        "description": "Logon using explicit credentials — may indicate lateral movement",
        "severity":    "HIGH",
    },
    4688: {
        "name":        "Process Created",
        "technique":   "T1059",
        "tactic":      "Execution",
        "description": "New process creation — flag suspicious executables",
        "severity":    "MEDIUM",
    },
    4698: {
        "name":        "Scheduled Task Created",
        "technique":   "T1053",
        "tactic":      "Persistence / Privilege Escalation",
        "description": "Scheduled task created — common persistence mechanism",
        "severity":    "HIGH",
    },
    4702: {
        "name":        "Scheduled Task Updated",
        "technique":   "T1053",
        "tactic":      "Persistence",
        "description": "Scheduled task modified — may indicate persistence attempt",
        "severity":    "HIGH",
    },
    4720: {
        "name":        "User Account Created",
        "technique":   "T1136",
        "tactic":      "Persistence",
        "description": "New user account — may indicate backdoor account creation",
        "severity":    "HIGH",
    },
    4726: {
        "name":        "User Account Deleted",
        "technique":   "T1531",
        "tactic":      "Impact",
        "description": "Account deleted — may indicate covering tracks",
        "severity":    "MEDIUM",
    },
    4732: {
        "name":        "User Added to Admin Group",
        "technique":   "T1098",
        "tactic":      "Persistence / Privilege Escalation",
        "description": "Privilege escalation via group membership change",
        "severity":    "CRITICAL",
    },
    4756: {
        "name":        "Member Added to Security Group",
        "technique":   "T1098",
        "tactic":      "Persistence",
        "description": "Security group modification — monitor for unauthorized changes",
        "severity":    "HIGH",
    },
    4768: {
        "name":        "Kerberos TGT Requested",
        "technique":   "T1558",
        "tactic":      "Credential Access",
        "description": "Kerberos ticket request — watch for Kerberoasting patterns",
        "severity":    "MEDIUM",
    },
    4771: {
        "name":        "Kerberos Pre-Auth Failed",
        "technique":   "T1110",
        "tactic":      "Credential Access",
        "description": "Failed Kerberos auth — may indicate password spraying",
        "severity":    "HIGH",
    },
    7045: {
        "name":        "New Service Installed",
        "technique":   "T1543",
        "tactic":      "Persistence / Privilege Escalation",
        "description": "New service created — common malware persistence method",
        "severity":    "CRITICAL",
    },
    4104: {
        "name":        "PowerShell Script Block",
        "technique":   "T1059.001",
        "tactic":      "Execution",
        "description": "PowerShell execution logged — review for malicious commands",
        "severity":    "HIGH",
    },
    1102: {
        "name":        "Audit Log Cleared",
        "technique":   "T1070",
        "tactic":      "Defense Evasion",
        "description": "Security log cleared — strong indicator of attacker covering tracks",
        "severity":    "CRITICAL",
    },
}

# Suspicious process names to flag in Event ID 4688
SUSPICIOUS_PROCESSES = [
    "mimikatz", "meterpreter", "empire", "cobalt",
    "psexec", "wce.exe", "fgdump", "pwdump",
    "netcat", "nc.exe", "ncat",
    "certutil", "bitsadmin", "mshta", "wscript", "cscript",
    "regsvr32", "rundll32", "msiexec",
    "powershell", "cmd.exe", "wmic",
]


# ──────────────────────────────────────────────
# SECTION 2: XML PARSING
# ──────────────────────────────────────────────
# Windows exports event logs as XML. Each <Event> contains
# a <System> block with metadata and an <EventData> block with details.

def parse_event_log(file_path: str) -> list:
    """
    Parses a Windows Event Log XML file.
    Returns a list of normalized event dicts.
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        console.print(f"[red]XML Parse Error:[/red] {e}")
        sys.exit(1)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] File not found: {file_path}")
        sys.exit(1)

    events = []

    # Handle both wrapped (<Events>) and bare (<Event>) root elements
    if root.tag.endswith("Event"):
        event_elements = [root]
    else:
        event_elements = root.findall(".//{*}Event")

    for event in event_elements:
        parsed = parse_single_event(event)
        if parsed:
            events.append(parsed)

    return events


def parse_single_event(event) -> dict:
    """
    Extracts fields from a single <Event> XML element.
    Uses {*} wildcard to handle XML namespaces gracefully.
    """
    try:
        # System block contains metadata
        system = event.find("{*}System")
        if system is None:
            return None

        event_id_el = system.find("{*}EventID")
        time_el     = system.find("{*}TimeCreated")
        computer_el = system.find("{*}Computer")
        channel_el  = system.find("{*}Channel")

        event_id = int(event_id_el.text) if event_id_el is not None else 0
        timestamp = time_el.get("SystemTime", "") if time_el is not None else ""
        computer  = computer_el.text if computer_el is not None else "Unknown"
        channel   = channel_el.text if channel_el is not None else "Unknown"

        # EventData block contains the actual event details
        event_data = {}
        data_block = event.find("{*}EventData")
        if data_block is not None:
            for data in data_block.findall("{*}Data"):
                name  = data.get("Name", "")
                value = data.text or ""
                if name:
                    event_data[name] = value

        return {
            "event_id":   event_id,
            "timestamp":  format_timestamp(timestamp),
            "computer":   computer,
            "channel":    channel,
            "data":       event_data,
        }

    except Exception as e:
        return None


def format_timestamp(ts: str) -> str:
    """Converts ISO timestamp to readable format."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ts


# ──────────────────────────────────────────────
# SECTION 3: THREAT DETECTION
# ──────────────────────────────────────────────

def analyze_events(events: list) -> list:
    """
    Runs detection logic on parsed events.
    Returns a list of findings with MITRE mappings.
    """
    findings = []
    failed_logons = {}  # track brute force attempts per user

    for event in events:
        eid  = event["event_id"]
        data = event["data"]

        # Skip events not in our detection map
        if eid not in MITRE_MAP:
            continue

        mitre    = MITRE_MAP[eid]
        finding  = {
            "event_id":   eid,
            "timestamp":  event["timestamp"],
            "computer":   event["computer"],
            "name":       mitre["name"],
            "technique":  mitre["technique"],
            "tactic":     mitre["tactic"],
            "severity":   mitre["severity"],
            "description": mitre["description"],
            "details":    [],
            "extra_flags": [],
        }

        # Pull common fields
        user        = data.get("SubjectUserName") or data.get("TargetUserName", "N/A")
        logon_type  = data.get("LogonType", "")
        process     = data.get("NewProcessName") or data.get("ProcessName", "")
        ip_address  = data.get("IpAddress") or data.get("WorkstationName", "")
        task_name   = data.get("TaskName", "")
        service_name = data.get("ServiceName", "")

        if user:        finding["details"].append(f"User: {user}")
        if ip_address:  finding["details"].append(f"Source: {ip_address}")
        if process:     finding["details"].append(f"Process: {process}")
        if task_name:   finding["details"].append(f"Task: {task_name}")
        if service_name: finding["details"].append(f"Service: {service_name}")

        # Extra detection logic per event type

        # Brute force detection — track consecutive failed logons
        if eid == 4625:
            key = user
            failed_logons[key] = failed_logons.get(key, 0) + 1
            if failed_logons[key] >= 3:
                finding["extra_flags"].append(
                    f"⚠ BRUTE FORCE: {failed_logons[key]} failed attempts for '{user}'"
                )
                finding["severity"] = "CRITICAL"

        # Suspicious logon type (3=Network, 10=RemoteInteractive)
        if eid == 4624 and logon_type in ["3", "10"]:
            finding["extra_flags"].append(
                f"Remote logon detected (Type {logon_type})"
            )

        # Suspicious process names
        if eid == 4688 and process:
            proc_lower = process.lower()
            for sus in SUSPICIOUS_PROCESSES:
                if sus in proc_lower:
                    finding["extra_flags"].append(f"⚠ SUSPICIOUS PROCESS: {process}")
                    finding["severity"] = "CRITICAL"
                    break

        # Log clearing is always critical
        if eid == 1102:
            finding["extra_flags"].append("⚠ AUDIT LOG CLEARED — Attacker may be covering tracks")
            finding["severity"] = "CRITICAL"

        findings.append(finding)

    return findings


# ──────────────────────────────────────────────
# SECTION 4: REPORT RENDERING
# ──────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold cyan",
    "LOW":      "bold green",
}

def render_report(findings: list, total_events: int):
    """Renders the threat analysis report."""

    # Summary counts
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    # Summary panel
    console.print(Panel(
        f"[bold]Total Events Parsed:[/bold] {total_events}\n"
        f"[bold]Suspicious Events:[/bold] {len(findings)}\n"
        f"[bold red]Critical:[/bold red] {counts['CRITICAL']}  "
        f"[bold yellow]High:[/bold yellow] {counts['HIGH']}  "
        f"[bold cyan]Medium:[/bold cyan] {counts['MEDIUM']}  "
        f"[bold green]Low:[/bold green] {counts['LOW']}",
        title="[bold blue]🛡 Windows Event Log Analysis[/bold blue]",
        border_style="blue",
        expand=False
    ))

    if not findings:
        console.print("[green]No suspicious activity detected.[/green]")
        return

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    # Findings table
    table = Table(box=box.SIMPLE_HEAD, header_style="bold blue", show_lines=True)
    table.add_column("Severity",  width=10)
    table.add_column("Time",      width=22)
    table.add_column("Event ID",  width=9)
    table.add_column("Name",      width=24)
    table.add_column("MITRE",     width=12)
    table.add_column("Tactic",    width=28)
    table.add_column("Details",   width=35)

    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "white")
        details_str = "\n".join(f["details"])
        if f["extra_flags"]:
            details_str += "\n" + "\n".join(f["extra_flags"])

        table.add_row(
            f"[{color}]{f['severity']}[/{color}]",
            f["timestamp"],
            str(f["event_id"]),
            f["name"],
            f["technique"],
            f["tactic"],
            details_str,
        )

    console.print(table)
    console.rule()

    # MITRE ATT&CK summary
    techniques = {}
    for f in findings:
        t = f["technique"]
        if t not in techniques:
            techniques[t] = {"tactic": f["tactic"], "count": 0, "name": f["name"]}
        techniques[t]["count"] += 1

    mitre_table = Table(box=box.SIMPLE_HEAD, header_style="bold magenta")
    mitre_table.add_column("Technique ID")
    mitre_table.add_column("Name")
    mitre_table.add_column("Tactic")
    mitre_table.add_column("Occurrences")

    for tid, info in sorted(techniques.items()):
        mitre_table.add_row(
            tid,
            info["name"],
            info["tactic"],
            str(info["count"])
        )

    console.print(Panel(
        mitre_table,
        title="[magenta]🎯 MITRE ATT&CK Technique Summary[/magenta]",
        border_style="magenta"
    ))
    console.rule()


# ──────────────────────────────────────────────
# SECTION 5: CLI ENTRYPOINT
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Log Parser — analyze Windows Event Logs and map to MITRE ATT&CK",
        epilog="Examples:\n"
               "  python3 log_parser.py --file events.xml\n"
               "  python3 log_parser.py --file security.evtx.xml",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--file", required=True, help="Path to Windows Event Log XML file")
    args = parser.parse_args()

    console.print(f"\n[dim]Parsing event log:[/dim] [bold]{args.file}[/bold]...\n")

    events   = parse_event_log(args.file)
    findings = analyze_events(events)

    render_report(findings, len(events))


if __name__ == "__main__":
    main()