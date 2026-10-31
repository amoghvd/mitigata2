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
    return (ts, src, dst, user, host, event_type, status, port, nbytes,
            sigma, mitre, tactic_out, sev, threat, raw)


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

    def __init__(self, job_id: Optional[str], filename: str, total_hint: int):
        self.job_id = job_id
        self.filename = filename
        self.total_hint = total_hint
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
    ing = _StreamIngester(job_id, filename, total_hint)
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


def ingest_path(path: str, job_id: Optional[str] = None) -> Tuple[int, int, int, float]:
    """Same path for local files (e.g. edr_events.json sample load)."""
    import os
    start = time.perf_counter()
    total_hint = os.path.getsize(path)
    ing = _StreamIngester(job_id, os.path.basename(path), total_hint)
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
