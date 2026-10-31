"""Memory-safe, fast streaming ingestion (single path, no Rust path).

One stream -> parse each line -> stamp Sigma/MITRE -> batch-insert (20000).
Never holds the whole file or all rows: state is one 4 MB chunk, one decoded
line buffer, one 20000-row batch, and small counters. On an 8 GB PC that
batch is ~20 MB of rows, plus DuckDB's capped memory (see database.py:
half of system RAM, max 4 GB), so total peak stays well under 8 GB even
for a 6 GB log. Progress is based on bytes actually read from the stream,
not on UploadFile.size (unreliable for chunked uploads); it is updated
after every batch flush.

Speed, in order of impact (measured on the 10k sample repeated to 200k):
1. A fast ECS/JSONL path: direct dict lookups instead of the generic
   dotted-path search, and orjson instead of stdlib json when available.
2. No `line.lower()` on every row: explicit rule/threat rows (the common
   alert case) return before any keyword scan, and the lower-cased copy
   is only built when the keyword path is actually reached.
3. Larger batches (20000 vs 5000): far fewer PyArrow table builds and
   DuckDB INSERT statements per million rows.
4. DuckDB memory/threads are set from the machine (database.py), so a
   multi-core 8 GB PC is actually used instead of a fixed 2 GB / 4 threads.

Formats: nested ECS JSONL (source.ip, destination.ip, host.name, user.name,
event.action/kind, rule.name, threat.technique.id, network.bytes,
destination.port, dns.question.name, process.name), flat JSON, syslog/plain
text, CEF-ish key=value, CSV (header skipped / mapped). gzip is detected by
magic bytes (not just the extension) and decompressed incrementally.
A pathological single line is capped at 256 KiB before parsing.
"""
import codecs
import csv
import gzip
import io
import json
import re
import time
import zlib
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

try:
    import orjson as _orjson
except ImportError:  # orjson is in requirements.txt; stdlib json is the fallback
    _orjson = None

from backend.database import bulk_insert_rows, total_rows, apply_brute_force_rule

CHUNK_SIZE = 4 * 1024 * 1024      # 4 MB stream chunks: fewer read/decode calls
BATCH_SIZE = 20000                # ~20 MB of rows max; still small vs 8 GB RAM
MAX_LINE_CHARS = 262144
RAW_TRUNCATE = 1000


def _loads(line: str):
    """orjson (C, ~3-5x stdlib json for these events) with stdlib fallback."""
    if _orjson is not None:
        return _orjson.loads(line)
    return json.loads(line)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TS_RE = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")
KV_RE = re.compile(r"(\w+)=([^\s]+)")
# Apache / Nginx combined access log:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /x HTTP/1.0" 200 2326
APACHE_RE = re.compile(
    r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) ([^"]*?) [^"]*" (\d{3}) (\d+|-)')
APACHE_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"
# FortiGate key=value, quoted values may contain spaces, e.g.
# msg="User logged in from 10.0.0.1"  -- the old (\w+)=([^\s]+) parser
# split such values at the space and kept the quotes.
FGT_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
FGT_SUBTYPE_EVENT = {
    "dns": "DNS_QUERY", "traffic": "TRAFFIC", "webfilter": "WEB_FILTER",
    "ips": "IPS", "antivirus": "ANTIVIRUS", "app-ctrl": "APP_CTRL",
    "emailfilter": "EMAIL_FILTER", "dlp": "DLP", "voip": "VOIP",
}
FGT_DENY_ACTIONS = {"deny", "block", "blocked", "drop", "dropped", "reset"}


def detect_format(lines) -> str:
    """Auto-detect a .log file's format from its first lines.

    Returns one of: jsonl, apache, csv, cef, syslog, plain.
    This is what lets one ingestion path handle firex-10G.log (or any
    other real .log dataset) without the user hand-configuring a parser:
    the format is read from the data, then mapped to the Mitigata schema
    (timestamp, source_ip, destination_ip, user, host, event_type,
    status, port, bytes, sigma/mitre). Send the first ~20 lines of a new
    file to confirm the mapping before a full 6 GB run."""
    counts = {"jsonl": 0, "apache": 0, "csv": 0, "cef": 0, "syslog": 0, "plain": 0,
              "fortigate": 0}
    for line in lines:
        s = line.strip() if isinstance(line, str) else ""
        if not s:
            continue
        if s.startswith("{"):
            counts["jsonl"] += 1
        elif "srcip=" in s and "dstip=" in s:
            counts["fortigate"] += 1
        elif APACHE_RE.match(s):
            counts["apache"] += 1
        elif s.startswith("CEF:"):
            counts["cef"] += 1
        elif "," in s and IP_RE.search(s):
            counts["csv"] += 1
        elif TS_RE.search(s) or IP_RE.search(s):
            counts["syslog"] += 1
        else:
            counts["plain"] += 1
    if not any(counts.values()):
        return "plain"
    return max(counts, key=counts.get)

active_ingestion_jobs: Dict[str, Dict[str, Any]] = {}


def cleanup_old_jobs(max_history: int = 30) -> None:
    while len(active_ingestion_jobs) > max_history:
        active_ingestion_jobs.pop(next(iter(active_ingestion_jobs)), None)


# ---------------------------------------------------------------- Sigma rules
# Kept from the old pipeline.py (6 rules). Explicit threat/rule fields in an
# event take precedence over keyword matching (see stamp()).
SIGMA_RULES = [
    {"id": "SIGMA-001", "name": "Kerberoasting SPN Ticket Request Burst",
     "mitre_id": "T1558.003", "tactic": "Credential Access", "severity": "CRITICAL",
     "weight": 0.92, "keywords": ["kerberos", "spn", "tgs", "ticket", "encryption type 0x17"],
     "ports": [88, 135, 389]},
    {"id": "SIGMA-002", "name": "Privileged Remote Service Lateral Movement",
     "mitre_id": "T1021.001", "tactic": "Lateral Movement", "severity": "HIGH",
     "weight": 0.85, "keywords": ["ssh", "rdp", "winrm", "remote desktop", "pam_unix", "session opened"],
     "ports": [22, 3389, 5985, 5986]},
    {"id": "SIGMA-003", "name": "High-Frequency Authentication Brute Force",
     "mitre_id": "T1110.001", "tactic": "Credential Access", "severity": "HIGH",
     "weight": 0.78, "keywords": ["failed password", "authentication failure", "invalid credentials", "login deny"],
     "ports": [22, 443, 3389, 80]},
    {"id": "SIGMA-004", "name": "Network Discovery & LDAP Reconnaissance",
     "mitre_id": "T1046", "tactic": "Discovery", "severity": "MEDIUM",
     "weight": 0.65, "keywords": ["ldap", "port scan", "syn sweep", "directory sweep", "nmap"],
     "ports": [389, 636, 135, 445]},
    {"id": "SIGMA-005", "name": "Unauthorized Egress & Exfiltration Over Alternative Port",
     "mitre_id": "T1048.003", "tactic": "Exfiltration", "severity": "CRITICAL",
     "weight": 0.95, "keywords": ["customer vault", "egress block", "large payload", "dns tunneling", "data dump"],
     "ports": [5432, 27017, 3306, 443, 53]},
    {"id": "SIGMA-006", "name": "Public-Facing Application Exploitation / SSRF Header Smuggling",
     "mitre_id": "T1190", "tactic": "Initial Access", "severity": "CRITICAL",
     "weight": 0.90, "keywords": ["imds", "header smuggling", "reverse proxy", "169.254.169.254", "sqli", "rce"],
     "ports": [80, 443, 8080]},
    # Explicit EDR rules from the sample set (in addition to the 6 above).
    {"id": "SIGMA-007", "name": "Outbound HTTPS C2 Beaconing",
     "mitre_id": "T1071.001", "tactic": "Command and Control", "severity": "CRITICAL",
     "weight": 0.95, "keywords": ["c2 beacon"], "ports": [443]},
    {"id": "SIGMA-008", "name": "Suspicious Obfuscated PowerShell Invocation",
     "mitre_id": "T1059.001", "tactic": "Execution", "severity": "HIGH",
     "weight": 0.88, "keywords": ["invoke-mimikatz", "powershell.exe -enc"], "ports": []},
]
RULE_ID_MAP = {
    "c2-beacon-1071": "SIGMA-007", "ps-exec-1059": "SIGMA-008",
    "krb-roast-1558": "SIGMA-001", "ccb7b967": "SIGMA-003",
}
def _kw_hit(raw_lower: str, kw: str) -> bool:
    """Word-boundary match for short keywords (so 'rce' does NOT match
    'source', 'spn' does not match part of another word, etc.); plain
    substring match for multi-word phrases. Kept for the generic path;
    the hot keyword path in stamp() uses the precompiled combined regex
    below instead of one re.search() per keyword per row."""
    if " " in kw or len(kw) > 4:
        return kw in raw_lower
    return _WORD_RES[kw].search(raw_lower) is not None


# Precompiled word-boundary regexes for short keywords (len <= 4, no space).
# The old code called re.search() with a fresh pattern string for every
# keyword on every row; profiling a 200k-row file showed that alone cost
# ~44s of ~61s total. One combined regex + precompiled patterns fixes it.
_SHORT_KWS = sorted({kw for r in SIGMA_RULES for kw in r["keywords"]
                     if " " not in kw and len(kw) <= 4})
_WORD_RES = {kw: re.compile(r"\b" + re.escape(kw) + r"\b") for kw in _SHORT_KWS}
_WORD_RE = re.compile(r"\b(?:" + "|".join(re.escape(kw) for kw in _SHORT_KWS) + r")\b")
_KW_TO_RULES = {}
for _r in SIGMA_RULES:
    for _kw in _r["keywords"]:
        if " " not in _kw and len(_kw) <= 4:
            _KW_TO_RULES.setdefault(_kw, []).append(_r)
_LONG_KWS = [(kw, r) for r in SIGMA_RULES for kw in r["keywords"]
             if " " in kw or len(kw) > 4]

# Explicit rule.name -> (sigma id, mitre, tactic, severity) for the sample EDR set.
EXPLICIT_RULES = {
    "c2-beacon": ("SIGMA-006", "T1071.001", "Command and Control", "CRITICAL"),
    "failed logon": ("SIGMA-003", "T1110", "Credential Access", "HIGH"),
    "powershell": ("SIGMA-006", "T1059.001", "Execution", "HIGH"),
    "kerberos": ("SIGMA-001", "T1558.003", "Credential Access", "CRITICAL"),
}


def _first(d: Any, *keys: str):
    """Nested lookup: keys may be dotted paths; a list value yields item 0."""
    for k in keys:
        cur = d
        ok = True
        for part in k.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur is not None:
            if isinstance(cur, list):
                return cur[0] if cur else None
            return cur
    return None


def _parse_ts(val: Any):
    if val is None:
        return None
    try:
        if isinstance(val, (int, float)):
            return datetime.fromtimestamp(val, tz=timezone.utc).replace(tzinfo=None)
        s = str(val).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=None)
    except Exception:
        return None


def stamp(raw_lower: Optional[str], port: int, event_type: str, status: str,
          explicit_mitre: Optional[str], explicit_tactic: Optional[str],
          rule_name: str, rule_id: str = "", raw: str = "") -> Tuple[Optional[str], Optional[str], Optional[str], str, bool]:
    """Return (sigma_rule_id, mitre_id, tactic, severity, is_threat).

    raw_lower may be None: it is only built (from raw) when the keyword
    path is actually reached, so explicit rule/threat rows never pay for
    a lower-cased copy of the whole line."""
    if rule_id and rule_id in RULE_ID_MAP:
        for rule in SIGMA_RULES:
            if rule["id"] == RULE_ID_MAP[rule_id]:
                return rule["id"], rule["mitre_id"], rule["tactic"], rule["severity"], True
    rn = (rule_name or "").lower()
    for needle, mapped in EXPLICIT_RULES.items():
        if needle in rn:
            return mapped[0], mapped[1], mapped[2], mapped[3], True
    if explicit_mitre:
        # A vendor rule/threat block already identified this event; trust it.
        sev = "CRITICAL" if str(explicit_mitre).startswith(("T1071", "T1558")) else "HIGH"
        return None, str(explicit_mitre), explicit_tactic or "Credential Access", sev, True
    if raw_lower is None:
        raw_lower = raw.lower()
    best = None

    def _consider(rule):
        nonlocal best
        if best is None or rule["weight"] > best["weight"]:
            best = rule

    # One combined regex search finds every short keyword in the line at
    # once, instead of one re.search() per keyword per row.
    for m in _WORD_RE.finditer(raw_lower):
        for rule in _KW_TO_RULES.get(m.group(0), ()):
            _consider(rule)
    # Long / multi-word keywords: plain substring search, which is C-fast.
    for kw, rule in _LONG_KWS:
        if kw in raw_lower:
            _consider(rule)
    # Port + tactic hint (no keyword needed).
    if port:
        et_up = (event_type or "").upper()
        for rule in SIGMA_RULES:
            if port in rule["ports"] and rule["tactic"].upper() in et_up:
                _consider(rule)
    if best:
        return best["id"], best["mitre_id"], best["tactic"], best["severity"], True
    if status == "DENY":
        return None, None, None, "LOW", False
    return None, None, None, "LOW", False


def _nested_str(d: Any) -> Optional[str]:
    """First item of a list, else the value itself, as a string."""
    if isinstance(d, list):
        return str(d[0]) if d else None
    return str(d) if d is not None else None


def _parse_json_fast(d: dict, raw: str) -> Optional[tuple]:
    """Fast path for the common ECS/JSONL shape. Same output contract and
    same stamp() decisions as parse_line(); only the field extraction is
    direct dict access instead of the generic dotted-path search, and no
    lower-cased copy of the line is built unless stamp() needs keywords.
    Returns None if the dict does not look like an ECS event, in which
    case parse_line() falls back to the generic path."""
    if not isinstance(d, dict):
        return None
    ev = d.get("event")
    if isinstance(ev, str):
        # event as a plain string, e.g. {"event": "login"}
        event_type_str = ev
        ev = {}
    else:
        event_type_str = None
        if not isinstance(ev, dict) and ev is not None:
            return None
        ev = ev or {}
    src_d = d.get("source") if isinstance(d.get("source"), dict) else {}
    dst_d = d.get("destination") if isinstance(d.get("destination"), dict) else {}
    host_d = d.get("host") if isinstance(d.get("host"), dict) else {}
    user_d = d.get("user") if isinstance(d.get("user"), dict) else {}
    threat_d = d.get("threat") if isinstance(d.get("threat"), dict) else {}
    rule_d = d.get("rule") if isinstance(d.get("rule"), dict) else {}
    net_d = d.get("network") if isinstance(d.get("network"), dict) else {}

    ts = _parse_ts(d.get("@timestamp") or d.get("timestamp") or d.get("time")
                   or d.get("datetime") or d.get("ts") or ev.get("created"))
    src = _nested_str(src_d.get("ip") or d.get("source_ip") or d.get("src_ip")
                      or d.get("src") or d.get("client_ip"))
    if src is None:
        src = _nested_str(host_d.get("ip"))
    dst = _nested_str(dst_d.get("ip") or d.get("destination_ip") or d.get("dest_ip")
                      or d.get("dst") or d.get("server_ip"))
    if dst is None:
        dst = _nested_str(dst_d.get("domain") or (d.get("dns") or {}).get("resolved_ip")
                          if isinstance(d.get("dns"), dict) else None)
    user = _nested_str(user_d.get("name") or d.get("user_identity") or d.get("user")
                       or d.get("username") or d.get("actor"))
    host = _nested_str(host_d.get("name") or host_d.get("hostname") or d.get("host_name")
                       or d.get("host") or d.get("hostname"))
    event_type = str(event_type_str or ev.get("action") or d.get("event_type")
                     or d.get("action") or d.get("method") or d.get("protocol")
                     or "EVENT").upper()
    outcome = str(ev.get("outcome") or d.get("outcome") or d.get("status")
                  or d.get("result") or "").lower()
    if outcome in ("failure", "failed", "deny", "denied", "reject", "blocked", "drop"):
        status = "DENY"
    elif outcome in ("success", "accepted", "allow"):
        status = "ACCEPT"
    else:
        winlog = d.get("winlog") if isinstance(d.get("winlog"), dict) else {}
        status = "DENY" if winlog.get("event_id") in (4625, "4625") else "ACCEPT"
    try:
        port = int(dst_d.get("port") or d.get("destination_port")
                   or d.get("dest_port") or d.get("port") or 0)
    except Exception:
        port = 0
    try:
        nbytes = int(net_d.get("bytes") or d.get("bytes") or d.get("network_bytes") or 0)
    except Exception:
        nbytes = 0
    rule_name = str(rule_d.get("name") or d.get("rule_name") or "")
    rule_id = str(rule_d.get("id") or d.get("rule_id") or "")
    technique = threat_d.get("technique") if isinstance(threat_d.get("technique"), dict) else {}
    explicit_mitre = _nested_str(technique.get("id") or threat_d.get("technique_id"))
    tactic = threat_d.get("tactic") if isinstance(threat_d.get("tactic"), dict) else {}
    explicit_tactic = _nested_str(tactic.get("name"))
    sigma, mitre, tactic_out, sev, threat = stamp(
        None, port, event_type, status, explicit_mitre, explicit_tactic,
        rule_name, rule_id, raw=raw)
    dns_d = d.get("dns") if isinstance(d.get("dns"), dict) else {}
    q_d = dns_d.get("question") if isinstance(dns_d.get("question"), dict) else {}
    domain = _nested_str(q_d.get("name") or dst_d.get("domain"))
    return (ts, src, dst, user, host, event_type, status, port, nbytes,
            sigma, mitre, tactic_out, sev, threat, raw, domain, None)


def _parse_fortigate(s: str, raw: str) -> Optional[tuple]:
    """Exact mapping for FortiGate UTM logs (the firex-10G.log sample).

    Input (one line, key=value, quoted values may contain spaces):
      date=2026-10-23 time=08:48:26 eventtime=1792745306000000000
      tz="+0530" devname="FGT60FTK00000000" ... subtype="dns" ...
      srcip=10.10.40.156 srcport=37918 ... dstip=11.113.232.73 dstport=53
      ... proto=17 action="pass" service="DNS" ... hostname="nytimes.com"

    Output (17-tuple, same order as the schema, domain/device appended):
      timestamp   = date + time (local time as written; eventtime is only
                    a fallback, and is epoch nanoseconds, not milliseconds)
      source_ip   = srcip
      destination_ip = dstip
      user_identity = user / srcuser / dstuser, if present (none in the
                    sample, so None -- never invented from an interface)
      host_name   = None for FortiGate: hostname= is the *queried DNS
                    domain*, not the source host, and devname= is the
                    firewall device, not an endpoint. Both are kept
                    separately (domain / device_name) instead of being
                    mislabelled as the host.
      event_type  = subtype mapped (dns -> DNS_QUERY, traffic -> TRAFFIC,
                    ...) or service upper-cased if subtype is unknown
      status      = pass/accept/allow -> ACCEPT; deny/block/drop/reset -> DENY
      port        = dstport (the service port; srcport is kept in raw)
      bytes       = sentbyte + rcvdbyte when present (traffic logs),
                    else network.bytes, else 0 (DNS sample has no byte field)
      sigma/mitre/tactic/severity/is_threat = stamp() on the full line,
                    so a DNS-tunnelling / C2 keyword in msg= still fires
      raw_message = full original line (truncated to 1000 chars)
      domain      = hostname= (nytimes.com, aljazeera.com in the sample)
                    or dst domain / dns.question.name for other formats
      device_name = devname= (FGT60FTK00000000 in the sample)
    """
    kv = {}
    for m in FGT_KV_RE.finditer(s):
        v = m.group(2)
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            v = v[1:-1]
        kv[m.group(1)] = v
    if "srcip" not in kv or "dstip" not in kv:
        return None
    ts = None
    if kv.get("date") and kv.get("time"):
        try:
            ts = datetime.strptime(f"{kv['date']} {kv['time']}", "%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = None
    if ts is None and kv.get("eventtime"):
        try:
            # FortiGate eventtime is epoch *nanoseconds*.
            ts = datetime.fromtimestamp(int(kv["eventtime"]) / 1_000_000_000,
                                        tz=timezone.utc).replace(tzinfo=None)
        except Exception:
            ts = None
    subtype = (kv.get("subtype") or "").lower()
    service = (kv.get("service") or "").upper()
    event_type = FGT_SUBTYPE_EVENT.get(subtype) or service or subtype.upper() or "TRAFFIC"
    action = (kv.get("action") or "").lower()
    status = "DENY" if action in FGT_DENY_ACTIONS else "ACCEPT"
    try:
        port = int(kv.get("dstport") or 0)
    except Exception:
        port = 0
    try:
        nbytes = int(kv.get("sentbyte") or 0) + int(kv.get("rcvdbyte") or 0)
    except Exception:
        nbytes = 0
    user = kv.get("user") or kv.get("srcuser") or kv.get("dstuser") or None
    domain = kv.get("hostname") or kv.get("domain") or None
    device = kv.get("devname") or kv.get("devid") or None
    sigma, mitre, tactic, sev, threat = stamp(
        None, port, event_type, status, None, None, "", raw=raw)
    return (ts, kv["srcip"], kv["dstip"], user, None,
            event_type, status, port, nbytes,
            sigma, mitre, tactic, sev, threat, raw, domain, device)


def parse_line(line: str) -> Optional[tuple]:
    """One log line -> 15-tuple matching database.py column order, or None
    for a blank line. A non-empty line that cannot be parsed at all still
    becomes a row (raw text, no IPs) so row counts never silently drop data."""
    if line is None:
        return None
    s = line.strip()
    if not s:
        return None
    if len(s) > MAX_LINE_CHARS:
        s = s[:MAX_LINE_CHARS]
    raw = s[:RAW_TRUNCATE]

    ts = None; src = dst = user = host = None
    event_type = "TRAFFIC"; status = "ACCEPT"; port = 0; nbytes = 0
    rule_name = ""; explicit_mitre = None; explicit_tactic = None

    if s.startswith("{"):
        try:
            d = _loads(s)
            if isinstance(d, dict):
                fast = _parse_json_fast(d, raw)
                if fast is not None:
                    return fast
                # Unusual JSON shape: fall through to the generic path below
                # (which re-parses with the dotted-path search).
                d2 = d
                ts = _parse_ts(_first(d2, "@timestamp", "timestamp", "time", "datetime", "ts", "event.created"))
                src = _first(d2, "source.ip", "source_ip", "src_ip", "src", "client_ip", "sourceIp")
                dst = _first(d2, "destination.ip", "destination_ip", "dest_ip", "dst", "server_ip", "destIp", "dns.resolved_ip", "resolved_ip")
                host_ip = _first(d2, "host.ip")
                if src is None:
                    src = host_ip
                if dst is None:
                    dst = _first(d2, "destination.domain")
                user = _first(d2, "user.name", "user_identity", "user", "username", "actor", "userIdentity")
                host = _first(d2, "host.name", "host_name", "host", "hostname", "node", "hostName")
                event_type = str(_first(d2, "event.action", "event_type", "event", "action", "method", "protocol", "eventType") or "EVENT").upper()
                outcome = str(_first(d2, "event.outcome", "outcome", "status", "result") or "").lower()
                if outcome in ("failure", "failed", "deny", "denied", "reject", "blocked", "drop"):
                    status = "DENY"
                elif outcome in ("success", "accepted", "allow"):
                    status = "ACCEPT"
                elif _first(d2, "winlog.event_id") in (4625, "4625"):
                    status = "DENY"
                port = _first(d2, "destination.port", "destination_port", "dest_port", "port")
                try:
                    port = int(port) if port is not None else 0
                except Exception:
                    port = 0
                nb = _first(d2, "network.bytes", "bytes", "network_bytes")
                try:
                    nbytes = int(nb) if nb is not None else 0
                except Exception:
                    nbytes = 0
                rule_name = str(_first(d2, "rule.name", "rule_name") or "")
                rule_id = str(_first(d2, "rule.id", "rule_id") or "")
                explicit_mitre = _first(d2, "threat.technique.id", "threat.technique_id")
                explicit_tactic = _first(d2, "threat.tactic.name")
                sigma, mitre, tactic, sev, threat = stamp(
                    None, port, event_type, status, explicit_mitre, explicit_tactic, rule_name, rule_id, raw=raw)
                return (ts, str(src) if src else None, str(dst) if dst else None,
                        str(user) if user else None, str(host) if host else None,
                        event_type, status, port, nbytes,
                        sigma, mitre, tactic, sev, threat, raw)
        except Exception:
            pass  # fall through to heuristic parsing below

    # FortiGate UTM log (firex-10G.log): exact key=value mapping.
    # Checked before the generic plain-text path, which lost the
    # timestamp, port, domain and device on these lines.
    if "srcip=" in s and "dstip=" in s:
        fgt = _parse_fortigate(s, raw)
        if fgt is not None:
            return fgt

    # Apache / Nginx access log: proper mapping, not the generic plain-text
    # guess (which lost the status code, byte count and user).
    m_ap = APACHE_RE.match(s)
    if m_ap:
        src_ap, user_ap, ts_ap, method_ap, path_ap, status_ap, bytes_ap = m_ap.groups()
        try:
            ts = datetime.strptime(ts_ap, APACHE_TS_FMT).replace(tzinfo=None)
        except Exception:
            ts = None
        code = int(status_ap)
        status = "DENY" if code >= 400 else "ACCEPT"
        try:
            nbytes = int(bytes_ap) if bytes_ap != "-" else 0
        except Exception:
            nbytes = 0
        event_type = "HTTP_REQUEST"
        sigma, mitre, tactic, sev, threat = stamp(
            None, 80, event_type, status, None, None, "", raw=raw)
        return (ts, src_ap, None, None if user_ap == "-" else user_ap, None,
                event_type, status, 80, nbytes,
                sigma, mitre, tactic, sev, threat, raw)

    # CSV: header row is skipped by the caller (see ingest state); a data row
    # with commas and no braces is tried positionally.
    if "," in s and not s.startswith("{"):
        parts = next(csv.reader(io.StringIO(s)), [])
        if len(parts) >= 3 and IP_RE.search(parts[1] or ""):
            ts = _parse_ts(parts[0])
            src, dst = parts[1], parts[2]
            user = parts[3] if len(parts) > 3 else None
            host = parts[4] if len(parts) > 4 else None
            event_type = (parts[5] if len(parts) > 5 else "TRAFFIC").upper()
            status = (parts[6] if len(parts) > 6 else "ACCEPT").upper()
            sigma, mitre, tactic, sev, threat = stamp(s.lower(), 0, event_type, status, None, None, "")
            return (ts, src, dst, user, host, event_type, status, 0, 0,
                    sigma, mitre, tactic, sev, threat, raw)

    # CEF-ish key=value, syslog, plain text
    kvs = dict(KV_RE.findall(s))
    src = kvs.get("src") or kvs.get("source_ip")
    dst = kvs.get("dst") or kvs.get("destination_ip")
    ips = IP_RE.findall(s)
    if src is None and ips:
        src = ips[0]
    if dst is None and len(ips) > 1:
        dst = ips[1]
    m = TS_RE.search(s)
    if m:
        ts = _parse_ts(m.group(0))
        if ts is None:
            try:
                ts = datetime.strptime(f"{datetime.now().year} {m.group(0)}", "%Y %b %d %H:%M:%S")
            except Exception:
                ts = None
    low = s.lower()
    if any(k in low for k in ("ssh", "login", "auth", "sudo")):
        event_type = "AUTHENTICATION"
    elif "dns" in low or "query" in low:
        event_type = "DNS_QUERY"
    elif "kerberos" in low or "tgs" in low or "ticket" in low or "spn" in low:
        event_type = "KERBEROS_REQUEST"
    elif "http" in low:
        event_type = "HTTP_REQUEST"
    elif "firewall" in low or "drop" in low or "accept" in low:
        event_type = "FIREWALL_RULE"
    if any(k in low for k in ("fail", "deny", "reject", "drop", "error", "block")):
        status = "DENY"
    if "port" in kvs:
        try:
            port = int(kvs["port"])
        except Exception:
            port = 0
    sigma, mitre, tactic, sev, threat = stamp(low, port, event_type, status, None, None, "")
    return (ts, src, dst, None, None, event_type, status, port, 0,
            sigma, mitre, tactic, sev, threat, raw)


class _StreamIngester:
    """Feeds raw bytes (optionally gzip) -> decoded lines -> DB batches."""

    def __init__(self, job_id: Optional[str], filename: str, total_hint: int,
                 raw_threats_only: bool = False):
        self.job_id = job_id
        self.filename = filename
        self.total_hint = total_hint
        # For a multi-hundred-MB+ file, storing a truncated raw copy of
        # every benign row roughly doubles the DuckDB file and the insert
        # work. Threat rows keep their raw text (needed for investigation);
        # benign rows drop it. The dashboard does not use raw_message
        # (its notes are rebuilt from sigma/mitre/tactic), so nothing the
        # UI shows is lost. Override with MITIGATA_STORE_RAW=all.
        self.raw_threats_only = raw_threats_only
        self.start = time.perf_counter()
        self.bytes_read = 0
        self.rows = 0
        self.alerts = 0
        self.batch: List[tuple] = []
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.text_buf = ""
        self.decompressor = None  # zlib object, set on gzip magic
        self.checked_magic = False
        self.header_skipped = False
        self.is_csv = filename.lower().endswith((".csv", ".tsv"))

    def _flush(self) -> None:
        if not self.batch:
            return
        self.rows += bulk_insert_rows(self.batch)
        self.batch.clear()
        self._update_job()

    def _update_job(self) -> None:
        if not self.job_id:
            return
        total = self.total_hint
        pct = round(min(99.0, (self.bytes_read / total) * 100.0), 1) if total else 0.0
        active_ingestion_jobs[self.job_id] = {
            "status": "processing", "filename": self.filename,
            "bytes_processed": self.bytes_read, "total_bytes": total,
            "percent": pct, "remaining_bytes": max(0, total - self.bytes_read) if total else 0,
            "rows_ingested": self.rows,
            "elapsed_seconds": round(time.perf_counter() - self.start, 2),
        }

    def _handle_line(self, line: str) -> None:
        if self.is_csv and not self.header_skipped:
            self.header_skipped = True
            low = line.lower()
            if "timestamp" in low or "source" in low or "src" in low:
                return
        rec = parse_line(line)
        if rec is not None:
            if len(rec) == 15:
                rec = rec + (None, None)  # domain, device_name
            if self.raw_threats_only and not rec[13]:
                rec = rec[:14] + (None,) + rec[15:]
            self.batch.append(rec)
            if rec[13]:  # is_threat is tuple index 13; 14 is raw_message
                self.alerts += 1
            if len(self.batch) >= BATCH_SIZE:
                self._flush()

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.bytes_read += len(chunk)
        if not self.checked_magic:
            self.checked_magic = True
            if chunk[:2] == b"\x1f\x8b":
                self.decompressor = zlib.decompressobj(31)
        data = self.decompressor.decompress(chunk) if self.decompressor else chunk
        text = self.decoder.decode(data)
        self.text_buf += text
        lines = self.text_buf.split("\n")
        self.text_buf = lines.pop()
        for line in lines:
            self._handle_line(line.rstrip("\r"))

    def finish(self) -> Tuple[int, int]:
        if self.decompressor:
            tail = self.decoder.decode(self.decompressor.flush())
            self.text_buf += tail
        else:
            self.text_buf += self.decoder.decode(b"", final=True)
        if self.text_buf.strip():
            self._handle_line(self.text_buf.rstrip("\r"))
        self._flush()
        # Post-load brute-force rule (UPDATE only; cannot double-count rows).
        apply_brute_force_rule()
        self.alerts = _alerts_now()
        return self.rows, self.alerts


def _alerts_now() -> int:
    from backend.database import alerts_count
    return alerts_count()


def _finish_job(ing: _StreamIngester, duration: float) -> None:
    if ing.job_id:
        active_ingestion_jobs[ing.job_id] = {
            "status": "completed", "filename": ing.filename,
            "bytes_processed": ing.bytes_read, "total_bytes": ing.total_hint,
            "percent": 100.0, "remaining_bytes": 0,
            "rows_ingested": ing.rows,
            "elapsed_seconds": round(duration, 2),
        }


async def ingest_upload(file, job_id: Optional[str] = None) -> Tuple[int, int, int, float]:
    """Single streaming path for multipart uploads. Returns
    (ingested_rows, alerts, bytes_read, duration_seconds)."""
    start = time.perf_counter()
    filename = getattr(file, "filename", None) or "upload.log"
    total_hint = int(getattr(file, "size", 0) or 0)
    if job_id:
        cleanup_old_jobs()
        active_ingestion_jobs[job_id] = {
            "status": "processing", "filename": filename, "bytes_processed": 0,
            "total_bytes": total_hint, "percent": 0.0,
            "remaining_bytes": total_hint, "rows_ingested": 0, "elapsed_seconds": 0.0,
        }
    ing = _StreamIngester(job_id, filename, total_hint,
                          raw_threats_only=_raw_threats_only_for(total_hint))
    try:
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break
            ing.feed(chunk)
        rows, alerts = ing.finish()
    except Exception:
        if job_id:
            active_ingestion_jobs[job_id] = {
                "status": "failed", "filename": filename,
                "bytes_processed": ing.bytes_read, "total_bytes": total_hint,
                "percent": 0.0, "remaining_bytes": 0, "rows_ingested": ing.rows,
                "elapsed_seconds": round(time.perf_counter() - start, 2),
            }
        raise
    duration = time.perf_counter() - start
    _finish_job(ing, duration)
    return rows, alerts, ing.bytes_read, duration


def _raw_threats_only_for(size_bytes: int) -> bool:
    """True for large files unless the user explicitly asked for all raw
    text. Env: MITIGATA_STORE_RAW=all (keep everything) or threats_only."""
    import os as _os
    mode = _os.environ.get("MITIGATA_STORE_RAW", "").lower()
    if mode == "all":
        return False
    if mode == "threats_only":
        return True
    return size_bytes > 500_000_000


def ingest_path(path: str, job_id: Optional[str] = None) -> Tuple[int, int, int, float]:
    """Same path for local files (e.g. edr_events.json sample load)."""
    import os
    start = time.perf_counter()
    total_hint = os.path.getsize(path)
    ing = _StreamIngester(job_id, os.path.basename(path), total_hint,
                          raw_threats_only=_raw_threats_only_for(total_hint))
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            ing.feed(chunk)
    rows, alerts = ing.finish()
    duration = time.perf_counter() - start
    _finish_job(ing, duration)
    return rows, alerts, ing.bytes_read, duration


# ------------------------------------------------------------ parallel path
# For a 6 GB file on an 8 GB PC, one Python process is CPU-bound by
# parsing. Splitting the file into byte ranges and parsing each range in
# its own process (max 4 workers, each ~400-500 MB) uses all cores, and
# each worker writes a Parquet shard instead of touching DuckDB. The main
# process then loads the shards with DuckDB's C++ Parquet reader, which
# is far faster than per-batch Python inserts. Total peak: workers
# (~2 GB) + DuckDB (capped 4 GB) + OS, still under 8 GB.
# Gzip files cannot be byte-split, so they fall back to ingest_path().
def _rows_to_arrow(rows: List[tuple]):
    import pyarrow as pa
    cols = ["timestamp", "source_ip", "destination_ip", "user_identity",
            "host_name", "event_type", "status", "port", "bytes",
            "sigma_rule_id", "mitre_id", "tactic", "severity",
            "is_threat", "raw_message", "domain", "device_name"]
    types = [pa.timestamp("us")] + [pa.string()] * 6 + [pa.int32(), pa.int64()] \
        + [pa.string()] * 4 + [pa.bool_(), pa.string(), pa.string(), pa.string()]
    rows = [r if len(r) == 17 else (r + (None, None)) for r in rows]
    arrays = []
    for i, typ in enumerate(types):
        vals = [r[i] for r in rows]
        if typ == pa.timestamp("us"):
            vals = [v if isinstance(v, datetime) else None for v in vals]
        arrays.append(pa.array(vals, type=typ))
    return pa.Table.from_arrays(arrays, names=cols)


def _worker_segment(args) -> Tuple[int, int, str]:
    """Top-level (picklable) worker: parse one byte range to one shard."""
    path, start, end, shard_path, raw_threats_only, is_last = args
    import pyarrow.parquet as pq
    rows = 0
    alerts = 0
    batch: List[tuple] = []
    writer = None
    try:
        with open(path, "rb") as fh:
            if start > 0:
                # Only discard a partial line. If the split point already
                # falls exactly on a line boundary (previous byte is \n),
                # the next line is a full line and must NOT be discarded
                # (the old code lost exactly 1 row per such boundary).
                fh.seek(start - 1)
                prev = fh.read(1)
                if prev != b"\n":
                    fh.readline()  # discard partial line at the split point
                # else: fh is already positioned at the start of a line
            while True:
                line_start = fh.tell()
                if not is_last and line_start >= end:
                    break
                raw_line = fh.readline()
                if not raw_line:
                    break
                try:
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                except Exception:
                    continue
                if not line.strip():
                    continue
                rec = parse_line(line)
                if rec is None:
                    continue
                if len(rec) == 15:
                    rec = rec + (None, None)  # domain, device_name
                if raw_threats_only and not rec[13]:
                    rec = rec[:14] + (None,) + rec[15:]
                batch.append(rec)
                if rec[13]:
                    alerts += 1
                if len(batch) >= BATCH_SIZE:
                    tbl = _rows_to_arrow(batch)
                    if writer is None:
                        writer = pq.ParquetWriter(shard_path, tbl.schema)
                    writer.write_table(tbl)
                    rows += len(batch)
                    batch.clear()
        if batch:
            tbl = _rows_to_arrow(batch)
            if writer is None:
                writer = pq.ParquetWriter(shard_path, tbl.schema)
            writer.write_table(tbl)
            rows += len(batch)
            batch.clear()
    finally:
        if writer is not None:
            writer.close()
    return rows, alerts, shard_path


def ingest_path_parallel(path: str, job_id: Optional[str] = None,
                         workers: Optional[int] = None) -> Tuple[int, int, int, float]:
    """Parallel ingestion for a local file. Falls back to ingest_path()
    for small files (<100 MB), gzip files, or when workers <= 1."""
    import multiprocessing as mp
    import os
    import tempfile
    from backend.database import alerts_count, apply_brute_force_rule, get_db_connection
    start = time.perf_counter()
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        is_gzip = fh.read(2) == b"\x1f\x8b"
    if workers is None:
        try:
            workers = int(os.environ.get("MITIGATA_WORKERS", "0")) or None
        except Exception:
            workers = None
    if workers is None:
        workers = min(4, os.cpu_count() or 4)
    if size < 100_000_000 or is_gzip or workers <= 1:
        return ingest_path(path, job_id=job_id)
    raw_threats_only = _raw_threats_only_for(size)
    chunk = size // workers
    ranges = [(i * chunk, (i + 1) * chunk if i < workers - 1 else size)
              for i in range(workers)]
    parent = os.path.dirname(os.path.abspath(path))
    with tempfile.TemporaryDirectory(prefix=".mitigata_shards_", dir=parent) as tmpdir:
        args = [(path, s, e, os.path.join(tmpdir, f"shard_{i}.parquet"),
                 raw_threats_only, i == workers - 1)
                for i, (s, e) in enumerate(ranges)]
        try:
            ctx = mp.get_context("fork")
        except Exception:
            ctx = mp.get_context("spawn")
        with ctx.Pool(processes=workers) as pool:
            results = pool.map(_worker_segment, args)
        total_rows = 0
        conn = get_db_connection()
        from backend.database import _db_lock
        with _db_lock:
            for rows, _alerts, shard in results:
                total_rows += rows
                if rows and os.path.exists(shard):
                    conn.execute("INSERT INTO raw_logs SELECT * FROM read_parquet(?)", [shard])
    apply_brute_force_rule()
    alerts = alerts_count()
    duration = time.perf_counter() - start
    if job_id:
        active_ingestion_jobs[job_id] = {
            "status": "completed", "filename": os.path.basename(path),
            "bytes_processed": size, "total_bytes": size, "percent": 100.0,
            "remaining_bytes": 0, "rows_ingested": total_rows,
            "elapsed_seconds": round(duration, 2),
        }
    return total_rows, alerts, size, duration
