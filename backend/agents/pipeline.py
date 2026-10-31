"""Agent 1 (Sigma/MITRE stamping, done at ingest time in ingestion.py) and
Agent 2 (NetworkX graph from DuckDB aggregates over ALL rows).

GraphNode / GraphEdge shapes match src/types/index.ts exactly:
  node: {id,label,role,ip,status,x,y,riskScore,quantumProbability,killChainStage}
  edge: {id,source,target,traversalProbability,protocol,isBreached,quantumPhase,killChainStep}
Node ids are the IP strings themselves, so edge source/target resolve
directly in the dashboard canvas. Fallback nodes (external C2 + DC) are used
only when the database is empty, never as a substitute for real data.
"""
import math
from typing import Any, Dict, List

import networkx as nx

from backend.database import top_edges
from backend.ingestion import SIGMA_RULES

KILL_CHAIN_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
    "Normal Operation",
]

FALLBACK_NODES = [
    {"id": "198.51.100.23", "label": "198.51.100.23", "role": "ingress",
     "ip": "198.51.100.23", "status": "compromised", "x": 100, "y": 190,
     "riskScore": 94.5, "quantumProbability": 0.884,
     "killChainStage": "Command and Control"},
    {"id": "10.10.0.10", "label": "SRV-DC-01", "role": "domain-controller",
     "ip": "10.10.0.10", "status": "targeted", "x": 320, "y": 190,
     "riskScore": 96.0, "quantumProbability": 0.884,
     "killChainStage": "Credential Access"},
]


def _role(ip: str, host_name: str, protocol: str) -> str:
    name = (host_name or "").upper()
    if "DC" in name or "DOMAIN" in name:
        return "domain-controller"
    if "DB" in name or "FILE" in name:
        return "database"
    if name.startswith("WS") or "WORKSTATION" in name:
        return "workstation"
    if protocol in ("KERBEROS_REQUEST",) or "AUTH" in protocol:
        return "auth"
    if not ip.startswith("10."):
        return "ingress"
    return "bastion"


def build_graph_from_aggregates(edges_data: List[Dict[str, Any]],
                               quantum_probs: Dict[str, float] = None,
                               host_map: Dict[str, str] = None):
    """Build a NetworkX DiGraph from merged edge aggregates, then export it
    in the frontend shape. Edge weight/count is the merged alert+flow count
    for that (source, destination) pair across the whole table."""
    quantum_probs = quantum_probs or {}
    host_map = host_map or {}
    G = nx.DiGraph()
    node_stats: Dict[str, Dict[str, Any]] = {}
    for e in edges_data:
        src, dst = e["source_ip"], e["destination_ip"]
        for ip, host in ((src, host_map.get(src, "")),
                          (dst, host_map.get(dst, "") or e.get("host_name") or "")):
            st = node_stats.setdefault(ip, {"count": 0, "threat": 0, "tactics": {}, "host": host, "proto": ""})
            st["count"] += int(e["count"])
            st["threat"] += int(e["threat_count"])
            if e.get("tactic"):
                st["tactics"][e["tactic"]] = st["tactics"].get(e["tactic"], 0) + int(e["count"])
            if host:
                st["host"] = host
        G.add_edge(src, dst, count=int(e["count"]), threat_count=int(e["threat_count"]),
                   protocol=e.get("protocol") or "TCP", tactic=e.get("tactic"),
                   mitre_id=e.get("mitre_id"))
    if not edges_data:
        return {"nodes": FALLBACK_NODES, "edges": [], "graph": G, "node_stats": node_stats}
    max_count = max(int(e["count"]) for e in edges_data) or 1
    max_threat = max(int(e["threat_count"]) for e in edges_data) or 1
    # Layout: highest-threat nodes first, grid so the canvas stays readable.
    ordered = sorted(node_stats.items(),
                     key=lambda kv: (kv[1]["threat"], kv[1]["count"]), reverse=True)
    nodes = []
    for idx, (ip, st) in enumerate(ordered[:40]):
        top_tactic = max(st["tactics"], key=st["tactics"].get) if st["tactics"] else "Normal Operation"
        threat_ratio = st["threat"] / max(st["count"], 1)
        risk = round(min(100.0, 20 + 80 * threat_ratio + 10 * min(1.0, st["threat"] / max(max_threat, 1))), 1)
        status = "compromised" if st["threat"] and threat_ratio >= 0.5 else ("targeted" if st["threat"] else "secure")
        # host_name is the *event* host, not a per-IP hostname: only trust
        # it for internal IPs. An external IP labelled with an internal
        # workstation name would be wrong.
        label = st["host"] if (st["host"] and ip.startswith("10.")) else ip
        nodes.append({
            "id": ip, "label": label,
            "role": _role(ip, st["host"] if ip.startswith("10.") else "", ""),
            "ip": ip, "status": status,
            "x": 100 + (idx % 5) * 200, "y": 120 + (idx // 5) * 180,
            "riskScore": risk,
            "quantumProbability": round(float(quantum_probs.get(ip, threat_ratio)), 4),
            "killChainStage": top_tactic,
        })
    edges = []
    for e in edges_data:
        if e["source_ip"] not in node_stats or e["destination_ip"] not in node_stats:
            continue
        step = KILL_CHAIN_ORDER.index(e["tactic"]) + 1 if e.get("tactic") in KILL_CHAIN_ORDER else 0
        edges.append({
            "id": f"e-{e['source_ip']}-{e['destination_ip']}".replace(".", "-"),
            "source": e["source_ip"], "target": e["destination_ip"],
            "traversalProbability": round(0.05 + 0.9 * (int(e["count"]) / max_count), 4),
            "protocol": e.get("protocol") or "TCP",
            "isBreached": int(e["threat_count"]) > 0,
            "quantumPhase": "QAOA",
            "killChainStep": step,
        })
    return {"nodes": nodes, "edges": edges, "graph": G, "node_stats": node_stats}


def build_attack_graph(limit_pairs: int = 60):
    """Agent 2 entry point: graph from DuckDB aggregates (all rows)."""
    return build_graph_from_aggregates(top_edges(limit_pairs))
