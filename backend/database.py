"""DuckDB storage for Mitigata.

Single shared connection guarded by a lock (DuckDB's Python connection is not
safe for concurrent use). No secondary indexes are created during load:
for a multi-GB file, index maintenance on every batch dominates ingest time.
Aggregates below are full scans / GROUP BYs over the raw table, which is
exactly what DuckDB's columnar engine is good at. If an index is ever wanted,
create it *after* a load finishes, never during one.

Database path: $MITIGATA_DB, else mitigata_logs.duckdb next to the repo root
(the parent of this backend/ directory).
"""
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import duckdb

DATABASE_FILE = os.environ.get(
    "MITIGATA_DB",
    str(Path(__file__).resolve().parent.parent / "mitigata_logs.duckdb"),
)
_db_lock = threading.Lock()
_conn: Optional[duckdb.DuckDBPyConnection] = None

SCHEMA_COLUMNS = (
    "timestamp, source_ip, destination_ip, user_identity, host_name, "
    "event_type, status, port, bytes, sigma_rule_id, mitre_id, tactic, "
    "severity, is_threat, raw_message, domain, device_name"
)
INSERT_SQL = f"INSERT INTO raw_logs ({SCHEMA_COLUMNS}) VALUES ({','.join(['?'] * 17)})"


def _duckdb_memory_limit() -> str:
    """Half of system RAM, capped at 4 GB, floored at 2 GB.

    Linux: /proc/meminfo. Windows: ctypes GlobalMemoryStatusEx.
    Anything else: 2 GB (the old fixed value)."""
    total = 0
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) * 1024
                    break
    except Exception:
        pass
    if not total:
        try:
            import ctypes

            class _MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            ms = _MS()
            ms.dwLength = ctypes.sizeof(ms)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms)):
                total = int(ms.ullTotalPhys)
        except Exception:
            pass
    if not total:
        return "2GB"
    gb = max(2, min(4, total // (2 * 1024 ** 3)))
    return f"{gb}GB"


def get_db_connection() -> duckdb.DuckDBPyConnection:
    global _conn
    if _conn is None:
        with _db_lock:
            if _conn is None:
                _conn = duckdb.connect(database=DATABASE_FILE, read_only=False)
                # Use the machine, but stay safe on an 8 GB PC: half of
                # system RAM, capped at 4 GB, so DuckDB + the Python batch
                # (~20 MB) + the OS still fit comfortably under 8 GB.
                # The old fixed 2 GB / 4 threads under-used a modern PC.
                _conn.execute(f"PRAGMA threads={max(1, os.cpu_count() or 4)}")
                _conn.execute(f"PRAGMA memory_limit='{_duckdb_memory_limit()}'")
                _conn.execute("PRAGMA preserve_insertion_order=false")
                init_schema(_conn)
    return _conn


def init_schema(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS raw_logs (
            timestamp TIMESTAMP,
            source_ip VARCHAR,
            destination_ip VARCHAR,
            user_identity VARCHAR,
            host_name VARCHAR,
            event_type VARCHAR,
            status VARCHAR,
            port INTEGER,
            bytes BIGINT,
            sigma_rule_id VARCHAR,
            mitre_id VARCHAR,
            tactic VARCHAR,
            severity VARCHAR,
            is_threat BOOLEAN,
            raw_message VARCHAR,
            domain VARCHAR,
            device_name VARCHAR
        )
        """
    )
    # Migration for databases created before domain/device_name existed:
    # DuckDB supports ADD COLUMN IF NOT EXISTS.
    for col, typ in (("domain", "VARCHAR"), ("device_name", "VARCHAR")):
        try:
            conn.execute(f"ALTER TABLE raw_logs ADD COLUMN IF NOT EXISTS {col} {typ}")
        except Exception:
            pass


def _rows_to_dicts(cursor) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cursor.description]
    out = []
    for row in cursor.fetchall():
        rec = {}
        for name, val in zip(cols, row):
            rec[name] = val.isoformat() if isinstance(val, datetime) else val
        out.append(rec)
    return out


_ARROW_TYPES = None


def bulk_insert_rows(rows: List[tuple]) -> int:
    """Fast batch insert. Primary path is PyArrow (vectorized, ~100x faster
    than executemany for wide string rows); executemany is the fallback if
    pyarrow is not installed. Executemany on DuckDB 2.0 measured ~500 rows/s
    for these rows, which would make a 6 GB load take hours -- do not use it
    as the primary path."""
    if not rows:
        return 0
    rows = [r if len(r) == 17 else (r + (None, None)) for r in rows]
    conn = get_db_connection()
    with _db_lock:
        try:
            import pyarrow as pa
            cols = ["timestamp", "source_ip", "destination_ip", "user_identity",
                    "host_name", "event_type", "status", "port", "bytes",
                    "sigma_rule_id", "mitre_id", "tactic", "severity",
                    "is_threat", "raw_message", "domain", "device_name"]
            types = [pa.timestamp("us")] + [pa.string()] * 6 + [pa.int32(), pa.int64()] \
                + [pa.string()] * 4 + [pa.bool_(), pa.string(), pa.string(), pa.string()]
            arrays = []
            for i, typ in enumerate(types):
                vals = [r[i] for r in rows]
                if typ == pa.timestamp("us"):
                    vals = [v if isinstance(v, datetime) else None for v in vals]
                arrays.append(pa.array(vals, type=typ))
            tbl = pa.Table.from_arrays(arrays, names=cols)
            conn.register("_mitigata_batch", tbl)
            try:
                conn.execute("INSERT INTO raw_logs SELECT * FROM _mitigata_batch")
            finally:
                conn.unregister("_mitigata_batch")
        except ImportError:
            conn.executemany(INSERT_SQL, rows)
    return len(rows)


def clear_logs() -> None:
    conn = get_db_connection()
    with _db_lock:
        conn.execute("DELETE FROM raw_logs")


def _count(sql: str, params=()) -> int:
    conn = get_db_connection()
    with _db_lock:
        return int(conn.execute(sql, params).fetchone()[0])


def total_rows() -> int:
    return _count("SELECT COUNT(*) FROM raw_logs")


def alerts_count() -> int:
    return _count("SELECT COUNT(*) FROM raw_logs WHERE is_threat")


def get_health_stats() -> Dict[str, Any]:
    total = total_rows()
    alerts = alerts_count()
    size = os.path.getsize(DATABASE_FILE) if os.path.exists(DATABASE_FILE) else 0
    rss_mb = 0.0
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    rss_mb = round(int(line.split()[1]) / 1024, 2)
                    break
    except Exception:
        pass
    return {
        "status": "healthy",
        "duckdb_version": duckdb.__version__,
        "database_file": DATABASE_FILE,
        "database_size_bytes": size,
        "database_size_mb": round(size / (1024 * 1024), 2),
        "total_raw_logs": total,
        "alerts_count": alerts,
        "process_memory_mb": rss_mb,
    }


def get_sample_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Latest rows, mapped to the frontend DuckDBLogRow shape."""
    conn = get_db_connection()
    with _db_lock:
        cur = conn.execute(
            """
            SELECT timestamp, source_ip, destination_ip, event_type, status,
                   port, bytes, sigma_rule_id, mitre_id, tactic, severity,
                   is_threat, host_name, user_identity, domain, device_name
            FROM raw_logs ORDER BY timestamp DESC NULLS LAST LIMIT ?
            """,
            [int(limit)],
        )
        rows = _rows_to_dicts(cur)
    out = []
    for i, r in enumerate(rows):
        threat = bool(r.get("is_threat"))
        sev = (r.get("severity") or "").upper()
        flag = "ANOMALOUS" if threat and sev == "CRITICAL" else ("SUSPICIOUS" if threat else "NORMAL")
        note = r.get("sigma_rule_id") or ""
        if r.get("mitre_id"):
            note = f"{note} {r['mitre_id']}".strip()
        if r.get("tactic"):
            note = f"{note} ({r['tactic']})".strip()
        if r.get("domain"):
            note = f"{note} {r['domain']}".strip()
        out.append({
            "id": f"LOG-{i + 1:03d}",
            "timestamp": r.get("timestamp") or "",
            "sourceIp": r.get("source_ip") or "",
            "destIp": r.get("destination_ip") or "",
            "protocol": r.get("event_type") or "TCP",
            "port": int(r.get("port") or 0),
            "bytes": int(r.get("bytes") or 0),
            "action": "REJECT" if (r.get("status") or "").upper() == "DENY" else "ACCEPT",
            "flag": flag,
            "notes": note or (r.get("event_type") or ""),
        })
    return out


def aggregate_counts() -> Dict[str, Any]:
    conn = get_db_connection()
    with _db_lock:
        total = int(conn.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0])
        alerts = int(conn.execute("SELECT COUNT(*) FROM raw_logs WHERE is_threat").fetchone()[0])
        tactics = _rows_to_dicts(conn.execute(
            "SELECT tactic, COUNT(*) AS cnt FROM raw_logs WHERE is_threat GROUP BY tactic ORDER BY cnt DESC"))
        severities = _rows_to_dicts(conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM raw_logs WHERE is_threat GROUP BY severity ORDER BY cnt DESC"))
        mitres = _rows_to_dicts(conn.execute(
            "SELECT mitre_id, COUNT(*) AS cnt FROM raw_logs WHERE is_threat AND mitre_id IS NOT NULL GROUP BY mitre_id ORDER BY cnt DESC LIMIT 10"))
        hosts = _rows_to_dicts(conn.execute(
            "SELECT host_name, COUNT(*) AS cnt FROM raw_logs WHERE is_threat GROUP BY host_name ORDER BY cnt DESC LIMIT 10"))
        distinct = conn.execute(
            "SELECT COUNT(DISTINCT source_ip), COUNT(DISTINCT destination_ip), COUNT(DISTINCT tactic) FROM raw_logs WHERE is_threat").fetchone()
        by_target = _rows_to_dicts(conn.execute(
            """
            SELECT destination_ip, host_name, tactic, mitre_id, severity, COUNT(*) AS cnt
            FROM raw_logs WHERE is_threat AND destination_ip IS NOT NULL
            GROUP BY destination_ip, host_name, tactic, mitre_id, severity
            ORDER BY cnt DESC LIMIT 50
            """))
    return {
        "total_rows": total, "alerts_count": alerts,
        "tactics": tactics, "severities": severities, "mitres": mitres,
        "top_threat_hosts": hosts,
        "distinct_threat_sources": int(distinct[0] or 0),
        "distinct_threat_targets": int(distinct[1] or 0),
        "distinct_tactics": int(distinct[2] or 0),
        "by_target": by_target,
    }


def top_edges(limit_pairs: int = 60) -> List[Dict[str, Any]]:
    """Merged (source,dest) edges from ALL rows: count + threat count + top protocol.

    The inner query groups by protocol first; Python then merges protocols per
    pair, keeping the most frequent protocol. This is one full scan, not a
    500-row sample.
    """
    conn = get_db_connection()
    with _db_lock:
        rows = _rows_to_dicts(conn.execute(
            """
            SELECT source_ip, destination_ip, event_type, host_name,
                   COUNT(*) AS cnt,
                   SUM(CASE WHEN is_threat THEN 1 ELSE 0 END) AS threat_cnt,
                   MAX(CASE WHEN is_threat THEN severity ELSE NULL END) AS max_sev,
                   MAX(tactic) AS tactic, MAX(mitre_id) AS mitre_id
            FROM raw_logs
            WHERE source_ip IS NOT NULL AND destination_ip IS NOT NULL
              AND source_ip <> '' AND destination_ip <> ''
            GROUP BY source_ip, destination_ip, event_type, host_name
            ORDER BY cnt DESC LIMIT 2000
            """))
    merged: Dict[tuple, Dict[str, Any]] = {}
    for r in rows:
        key = (r["source_ip"], r["destination_ip"])
        m = merged.get(key)
        if m is None:
            merged[key] = {
                "source_ip": r["source_ip"], "destination_ip": r["destination_ip"],
                "host_name": r.get("host_name") or "", "protocol": r.get("event_type") or "TCP",
                "count": int(r["cnt"]), "threat_count": int(r["threat_cnt"] or 0),
                "max_severity": r.get("max_sev"), "tactic": r.get("tactic"), "mitre_id": r.get("mitre_id"),
                "_proto_count": int(r["cnt"]),
            }
        else:
            m["count"] += int(r["cnt"]); m["threat_count"] += int(r["threat_cnt"] or 0)
            if int(r["cnt"]) > m["_proto_count"]:
                m["protocol"] = r.get("event_type") or "TCP"; m["_proto_count"] = int(r["cnt"])
            if r.get("tactic"): m["tactic"] = r["tactic"]
            if r.get("mitre_id"): m["mitre_id"] = r["mitre_id"]
    edges = sorted(merged.values(), key=lambda e: (e["threat_count"], e["count"]), reverse=True)[:limit_pairs]
    for e in edges:
        e.pop("_proto_count", None)
    return edges


def apply_brute_force_rule(min_failures: int = 10) -> int:
    """Post-load frequency rule: only *failed-logon* rows from a source with
    many failed logons get SIGMA-003 / T1110. Restricting to DENY logon rows
    matters: a brute-force source is also a normal workstation, and stamping
    its benign network/registry traffic as threats would inflate alerts and
    mislabel normal traffic. This is an UPDATE, not a second ingestion, so
    it cannot double-count rows. Returns rows updated."""
    conn = get_db_connection()
    with _db_lock:
        cur = conn.execute(
            """
            UPDATE raw_logs SET sigma_rule_id='SIGMA-003', mitre_id='T1110',
                tactic='Credential Access', severity='HIGH', is_threat=true
            WHERE (sigma_rule_id IS NULL OR sigma_rule_id='')
              AND status='DENY'
              AND (event_type LIKE '%LOGON%' OR event_type='AUTHENTICATION')
              AND source_ip IN (
                SELECT source_ip FROM raw_logs
                WHERE status='DENY'
                  AND (event_type LIKE '%LOGON%' OR event_type='AUTHENTICATION')
                GROUP BY source_ip HAVING COUNT(*) >= ?
              )
            """,
            [min_failures],
        )
        return int(cur.rowcount or 0)


def ip_host_map() -> Dict[str, str]:
    """Most frequent host_name per source_ip (event host is usually the
    source host), used for graph node labels."""
    conn = get_db_connection()
    with _db_lock:
        rows = _rows_to_dicts(conn.execute(
            """
            SELECT source_ip, host_name, COUNT(*) AS cnt FROM raw_logs
            WHERE source_ip IS NOT NULL AND host_name IS NOT NULL AND host_name <> ''
            GROUP BY source_ip, host_name ORDER BY cnt DESC
            """))
    out: Dict[str, str] = {}
    for r in rows:
        out.setdefault(r["source_ip"], r["host_name"])
    return out
