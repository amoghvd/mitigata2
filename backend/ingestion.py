"""Memory-safe streaming ingestion (single path, no Rust path, no fall-through).

One stream -> parse each line -> stamp Sigma/MITRE -> batch-insert (5000).
Never holds the whole file or all rows: state is one 1 MB chunk, one decoded
line buffer, one 5000-row batch, and small counters. Progress is based on
bytes actually read from the stream, not on UploadFile.size (unreliable for
chunked uploads); it is updated after every batch flush.

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

from backend.database import bulk_insert_rows, total_rows, apply_brute_force_rule

CHUNK_SIZE = 1024 * 1024          # 1 MB stream chunks
BATCH_SIZE = 5000
MAX_LINE_CHARS = 262144
RAW_TRUNCATE = 1000

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
    substring match for multi-word phrases."""
    if " " in kw or len(kw) > 4:
        return kw in raw_lower
    return re.search(r"\b" + re.escape(kw) + r"\b", raw_lower) is not None

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


def stamp(raw_lower: str, port: int, event_type: str, status: str,
          explicit_mitre: Optional[str], explicit_tactic: Optional[str],
          rule_name: str, rule_id: str = "") -> Tuple[Optional[str], Optional[str], Optional[str], str, bool]:
    """Return (sigma_rule_id, mitre_id, tactic, severity, is_threat)."""
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
    best = None
    for rule in SIGMA_RULES:
        hit = any(_kw_hit(raw_lower, kw) for kw in rule["keywords"])
        if hit or (port in rule["ports"] and rule["tactic"].upper() in (event_type or "").upper()):
            if best is None or rule["weight"] > best["weight"]:
                best = rule
    if best:
        return best["id"], best["mitre_id"], best["tactic"], best["severity"], True
    if status == "DENY":
        return None, None, None, "LOW", False
    return None, None, None, "LOW", False


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
            d = json.loads(s)
            if isinstance(d, dict):
                ts = _parse_ts(_first(d, "@timestamp", "timestamp", "time", "datetime", "ts", "event.created"))
                src = _first(d, "source.ip", "source_ip", "src_ip", "src", "client_ip", "sourceIp")
                dst = _first(d, "destination.ip", "destination_ip", "dest_ip", "dst", "server_ip", "destIp", "dns.resolved_ip", "resolved_ip")
                host_ip = _first(d, "host.ip")
                if src is None:
                    src = host_ip
                if dst is None:
                    dst = _first(d, "destination.domain")
                user = _first(d, "user.name", "user_identity", "user", "username", "actor", "userIdentity")
                host = _first(d, "host.name", "host_name", "host", "hostname", "node", "hostName")
                event_type = str(_first(d, "event.action", "event_type", "event", "action", "method", "protocol", "eventType") or "EVENT").upper()
                outcome = str(_first(d, "event.outcome", "outcome", "status", "result") or "").lower()
                if outcome in ("failure", "failed", "deny", "denied", "reject", "blocked", "drop"):
                    status = "DENY"
                elif outcome in ("success", "accepted", "allow"):
                    status = "ACCEPT"
                elif _first(d, "winlog.event_id") in (4625, "4625"):
                    status = "DENY"
                port = _first(d, "destination.port", "destination_port", "dest_port", "port")
                try:
                    port = int(port) if port is not None else 0
                except Exception:
                    port = 0
                nb = _first(d, "network.bytes", "bytes", "network_bytes")
                try:
                    nbytes = int(nb) if nb is not None else 0
                except Exception:
                    nbytes = 0
                rule_name = str(_first(d, "rule.name", "rule_name") or "")
                rule_id = str(_first(d, "rule.id", "rule_id") or "")
                explicit_mitre = _first(d, "threat.technique.id", "threat.technique_id")
                explicit_tactic = _first(d, "threat.tactic.name")
                # Notes-rich fields are kept out of the row (raw is truncated);
                # the frontend note is rebuilt from sigma/mitre/tactic in DB.
                sigma, mitre, tactic, sev, threat = stamp(
                    s.lower(), port, event_type, status, explicit_mitre, explicit_tactic, rule_name, rule_id)
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
