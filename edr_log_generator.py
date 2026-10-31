#!/usr/bin/env python3
"""
SimEDR - Synthetic EDR Telemetry Log Generator
Generates ECS (Elastic Common Schema) compliant endpoint and network security telemetry
with realistic benign noise and injected attack vectors (MITRE ATT&CK).
"""

import argparse
import json
import random
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta

USERS = [
    "pmehta", "jdsouza", "sgupta", "kiyer", "mkhan", "nverma", 
    "vreddy", "dnair", "svc_backup", "svc_sql", "administrator"
]

HOSTS = [
    {"name": "WS-FIN-010", "ip": ["10.10.1.10"], "os": "Windows 11 Enterprise 23H2"},
    {"name": "WS-FIN-011", "ip": ["10.10.1.11"], "os": "Windows 11 Enterprise 23H2"},
    {"name": "WS-FIN-012", "ip": ["10.10.1.12"], "os": "Windows 11 Enterprise 23H2"},
    {"name": "WS-HR-011",  "ip": ["10.10.2.11"], "os": "Windows 11 Enterprise 23H2"},
    {"name": "WS-HR-012",  "ip": ["10.10.2.12"], "os": "Windows 11 Enterprise 23H2"},
    {"name": "WS-ENG-013", "ip": ["10.10.3.13"], "os": "Windows 11 Enterprise 23H2"},
    {"name": "WS-ENG-015", "ip": ["10.10.3.15"], "os": "Windows 11 Enterprise 23H2"},
    {"name": "WS-SALES-011", "ip": ["10.10.4.11"], "os": "Windows 11 Enterprise 23H2"},
    {"name": "SRV-DC-01",  "ip": ["10.10.0.10"], "os": "Windows Server 2022"},
    {"name": "SRV-FILE-01","ip": ["10.10.0.20"], "os": "Windows Server 2022"},
    {"name": "SRV-DB-01",  "ip": ["10.10.0.40"], "os": "Ubuntu 22.04 LTS"},
]

EXTERNAL_DOMAINS = [
    ("www.google.com", "52.22.183.85"),
    ("slack.com", "104.130.188.27"),
    ("teams.microsoft.com", "20.96.233.134"),
    ("login.microsoftonline.com", "142.222.166.126"),
    ("s3.amazonaws.com", "13.122.58.78"),
    ("github.com", "140.82.121.4"),
]

SUSPICIOUS_C2_IP = "198.51.100.23"

def generate_benign_event(event_time):
    host_info = random.choice(HOSTS)
    user = random.choice(USERS)
    cat_type = random.choice(["network_connection", "dns_query", "process_created", "user_logon", "file_modified", "registry_set"])
    event_id = str(uuid.uuid4())
    ts = event_time.isoformat()

    base = {
        "@timestamp": ts,
        "event": {
            "id": event_id,
            "kind": "event",
            "severity": 0,
            "module": "edr",
        },
        "agent": {"id": f"{random.randint(1000000000000000, 9999999999999999):x}", "type": "edr", "name": "SimEDR", "version": "1.0"},
        "observer": {"vendor": "Mitigata", "product": "SimEDR", "version": "1.0"},
        "host": {"name": host_info["name"], "hostname": host_info["name"], "ip": host_info["ip"], "os": {"type": "windows" if "Windows" in host_info["os"] else "linux", "full": host_info["os"]}},
        "user": {"name": user, "domain": "CORP"},
    }

    if cat_type == "network_connection":
        domain, ext_ip = random.choice(EXTERNAL_DOMAINS)
        base["event"].update({"category": ["network"], "type": ["connection"], "action": "network_connection", "dataset": "edr.network"})
        base["process"] = {"pid": random.randint(1000, 65000), "name": random.choice(["chrome.exe", "msedge.exe", "teams.exe", "svchost.exe"])}
        base["source"] = {"ip": host_info["ip"][0], "port": random.randint(49152, 65535)}
        base["destination"] = {"ip": ext_ip, "port": random.choice([80, 443]), "domain": domain}
        base["network"] = {"transport": "tcp", "direction": "outbound", "protocol": "https", "bytes": random.randint(1200, 500000)}

    elif cat_type == "dns_query":
        domain, ext_ip = random.choice(EXTERNAL_DOMAINS)
        base["event"].update({"category": ["network"], "type": ["protocol"], "action": "dns_query", "dataset": "edr.network"})
        base["dns"] = {"question": {"name": domain, "type": "A"}, "response_code": "NOERROR", "resolved_ip": [ext_ip]}
        base["process"] = {"pid": random.randint(1000, 65000), "name": "svchost.exe"}

    elif cat_type == "process_created":
        proc = random.choice(["chrome.exe", "notepad.exe", "excel.exe", "winword.exe", "explorer.exe", "MsMpEng.exe"])
        base["event"].update({"category": ["process"], "type": ["start"], "action": "process_created", "dataset": "edr.process"})
        base["process"] = {
            "pid": random.randint(1000, 65000),
            "name": proc,
            "executable": f"C:\\Program Files\\{proc}",
            "command_line": f'"{proc}" /standard',
            "parent": {"pid": random.randint(500, 5000), "name": "explorer.exe"},
            "entity_id": str(uuid.uuid4())
        }

    elif cat_type == "user_logon":
        base["event"].update({"category": ["authentication"], "type": ["start"], "action": "user_logon", "dataset": "edr.authentication", "outcome": "success"})
        base["winlog"] = {"event_id": 4624, "logon": {"type": random.choice(["Interactive", "Network"])}}
        base["source"] = {"ip": random.choice(HOSTS)["ip"][0]}

    elif cat_type == "file_modified":
        base["event"].update({"category": ["file"], "type": ["change"], "action": "file_modified", "dataset": "edr.file"})
        base["file"] = {"path": f"C:\\Users\\{user}\\Documents\\report_{random.randint(1,5)}.docx", "name": "report.docx", "size": random.randint(10000, 5000000)}
        base["process"] = {"pid": random.randint(1000, 65000), "name": "winword.exe"}

    else:
        base["event"].update({"category": ["registry"], "type": ["change"], "action": "registry_value_set", "dataset": "edr.registry"})
        base["registry"] = {"path": "HKCU\\Software\\Microsoft\\Office\\16.0\\Common", "data": {"strings": [str(random.randint(1000, 99999))]}}
        base["process"] = {"pid": random.randint(1000, 65000), "name": "excel.exe"}

    return base

def generate_threat_event(event_time, threat_type):
    ts = event_time.isoformat()
    event_id = str(uuid.uuid4())

    base = {
        "@timestamp": ts,
        "event": {
            "id": event_id,
            "kind": "alert",
            "severity": 5,
            "module": "edr",
            "outcome": "failure",
        },
        "agent": {"id": f"{random.randint(1000000000000000, 9999999999999999):x}", "type": "edr", "name": "SimEDR", "version": "1.0"},
        "observer": {"vendor": "Mitigata", "product": "SimEDR", "version": "1.0"},
        "labels": {"synthetic": "true", "simulated_detection": "true"}
    }

    if threat_type == "c2_beaconing":
        base["event"].update({
            "category": ["network"],
            "type": ["connection"],
            "action": "network_connection",
            "dataset": "edr.network",
            "outcome": "success"
        })
        base["host"] = {"name": "WS-FIN-010", "hostname": "WS-FIN-010", "ip": ["10.10.1.10"], "os": {"type": "windows", "full": "Windows 11 Enterprise 23H2"}}
        base["user"] = {"name": "vreddy", "domain": "CORP"}
        base["process"] = {"pid": 2984, "name": "powershell.exe", "command_line": f"powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp"}
        base["source"] = {"ip": "10.10.1.10", "port": random.randint(49152, 65535)}
        base["destination"] = {"ip": SUSPICIOUS_C2_IP, "port": 443, "domain": "cdn-update-sync.net"}
        base["network"] = {"transport": "tcp", "direction": "outbound", "protocol": "https", "bytes": random.randint(2400, 15000)}
        base["threat"] = {
            "framework": "MITRE ATT&CK",
            "technique": {"id": ["T1071.001"], "name": ["Web Protocols: C2 Beaconing"]},
            "tactic": {"name": ["Command and Control"]}
        }
        base["rule"] = {"id": "c2-beacon-1071", "name": f"Outbound HTTPS C2 Beaconing to Suspect External Host ({SUSPICIOUS_C2_IP})", "severity": "critical"}

    elif threat_type == "brute_force":
        base["event"].update({
            "category": ["authentication"],
            "type": ["start"],
            "action": "user_logon",
            "dataset": "edr.authentication",
            "outcome": "failure"
        })
        base["host"] = {"name": "SRV-DC-01", "hostname": "SRV-DC-01", "ip": ["10.10.0.10"], "os": {"type": "windows", "full": "Windows Server 2022"}}
        base["user"] = {"name": random.choice(["svc_backup", "svc_sql", "administrator"]), "domain": "CORP"}
        base["winlog"] = {"event_id": 4625, "logon": {"type": "Network"}}
        base["source"] = {"ip": "10.10.1.10"}
        base["labels_extra"] = {"failed_count_5min": random.randint(25, 140)}
        base["threat"] = {
            "framework": "MITRE ATT&CK",
            "technique": {"id": ["T1110"], "name": ["Brute Force: Password Guessing"]},
            "tactic": {"name": ["Credential Access"]}
        }
        base["rule"] = {"id": "ccb7b967", "name": "High rate of failed logons from single source", "severity": "medium"}

    elif threat_type == "powershell_exec":
        base["event"].update({
            "category": ["process"],
            "type": ["start"],
            "action": "process_created",
            "dataset": "edr.process",
            "outcome": "success"
        })
        base["host"] = {"name": "WS-FIN-010", "hostname": "WS-FIN-010", "ip": ["10.10.1.10"], "os": {"type": "windows", "full": "Windows 11 Enterprise 23H2"}}
        base["user"] = {"name": "vreddy", "domain": "CORP"}
        base["process"] = {
            "pid": random.randint(1000, 65000),
            "name": "powershell.exe",
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command Invoke-Mimikatz",
            "parent": {"pid": 2984, "name": "cmd.exe"},
            "entity_id": str(uuid.uuid4())
        }
        base["threat"] = {
            "framework": "MITRE ATT&CK",
            "technique": {"id": ["T1059.001"], "name": ["Command and Scripting Interpreter: PowerShell"]},
            "tactic": {"name": ["Execution"]}
        }
        base["rule"] = {"id": "ps-exec-1059", "name": "Suspicious Obfuscated PowerShell Invocation", "severity": "high"}

    else:
        # kerberoasting
        base["event"].update({
            "category": ["authentication"],
            "type": ["protocol"],
            "action": "kerberos_request",
            "dataset": "edr.authentication",
            "outcome": "success"
        })
        base["host"] = {"name": "SRV-DC-01", "hostname": "SRV-DC-01", "ip": ["10.10.0.10"], "os": {"type": "windows", "full": "Windows Server 2022"}}
        base["user"] = {"name": "svc_sql", "domain": "CORP"}
        base["source"] = {"ip": "10.10.1.10", "port": 135}
        base["destination"] = {"ip": "10.10.0.10", "port": 88}
        base["threat"] = {
            "framework": "MITRE ATT&CK",
            "technique": {"id": ["T1558.003"], "name": ["Steal or Forge Kerberos Tickets: Kerberoasting"]},
            "tactic": {"name": ["Credential Access"]}
        }
        base["rule"] = {"id": "krb-roast-1558", "name": "Unusual High-Entropy Kerberos SPN Ticket Request Burst", "severity": "critical"}

    return base

def main():
    parser = argparse.ArgumentParser(description="SimEDR Log Generator")
    parser.add_argument("--count", type=int, default=10000, help="Number of logs to generate")
    parser.add_argument("--output", type=str, choices=["file", "stdout"], default="file", help="Output target")
    parser.add_argument("--file", type=str, default="edr_events.json", help="Output file path when output is file")
    parser.add_argument("--rate", type=float, default=0, help="Rate limit in eps (0 = maximum speed)")

    args = parser.parse_args()

    total_events = args.count
    threat_ratio = 0.053  # ~530 alerts out of 10000 events
    threat_types = ["c2_beaconing", "brute_force", "powershell_exec", "kerberoasting"]

    start_time = datetime.now(timezone.utc) - timedelta(minutes=15)
    f = open(args.file, "w", encoding="utf-8") if args.output == "file" else None

    try:
        for i in range(total_events):
            event_time = start_time + timedelta(milliseconds=i * 90)
            is_threat = (random.random() < threat_ratio)
            
            if is_threat:
                event = generate_threat_event(event_time, random.choice(threat_types))
            else:
                event = generate_benign_event(event_time)

            line = json.dumps(event, separators=(',', ':'))
            
            if f:
                f.write(line + "\n")
            else:
                print(line)

            if args.rate > 0:
                time.sleep(1.0 / args.rate)

    finally:
        if f:
            f.close()
            print(f"[SimEDR] Successfully generated {total_events} events into {args.file}")

if __name__ == "__main__":
    main()
