"""Attack-path ranking (Agent 2 output, made explicit).

The dashboard used to show only a graph and one quantum next-hop, so a
user could see nodes and edges but never a ranked list of *paths*,
their confidence, or which path an attacker is most likely to take.
This module turns the merged (source, destination) edge aggregates
from DuckDB into that list.

Confidence, stated plainly so a demo audience can check it:
  edge_probability = (threat_count + 0.5) / (count + 1)
    -- Laplace smoothing: a pair seen 10 times with 10 threats scores
       0.95, a pair seen 100 times with 0 threats scores 0.005, and a
       pair seen once with 1 threat scores 0.75, never a fake 1.0.
  path_confidence = geometric mean of its edge probabilities
    -- a path is only as believable as its weakest hop, but one weak
       hop does not zero the whole path the way a plain product would.
Paths are ranked by confidence first, then by total threat flow, then
by shorter length. The top-ranked path is flagged is_most_likely.
Only paths with at least one threat edge are listed; a purely benign
flow (e.g. internal -> DNS resolver) is not an attack path.
"""
import math
from typing import Any, Dict, List


def compute_attack_paths(edges_data: List[Dict[str, Any]],
                         max_paths: int = 10, max_hops: int = 4) -> Dict[str, Any]:
    adj: Dict[str, List[Dict[str, Any]]] = {}
    for e in edges_data:
        src, dst = e.get("source_ip"), e.get("destination_ip")
        if not src or not dst or src == dst:
            continue
        count = int(e.get("count") or 0)
        threat = int(e.get("threat_count") or 0)
        prob = (threat + 0.5) / (count + 1) if count else 0.0
        adj.setdefault(src, []).append({
            "source": src, "target": dst, "protocol": e.get("protocol") or "TCP",
            "count": count, "threat_count": threat,
            "tactic": e.get("tactic"), "mitre_id": e.get("mitre_id"),
            "edge_probability": round(prob, 4),
        })
    # Highest-threat edges first: the search follows the attack, not noise.
    for src in adj:
        adj[src].sort(key=lambda x: (-x["threat_count"], -x["count"]))

    sources = sorted(
        (s for s, es in adj.items() if any(x["threat_count"] for x in es)),
        key=lambda s: -sum(x["threat_count"] for x in adj[s]))

    found: Dict[tuple, Dict[str, Any]] = {}

    def dfs(current: str, node_path: List[str], edge_path: List[Dict[str, Any]]):
        if len(edge_path) >= 1 and any(x["threat_count"] for x in edge_path):
            key = tuple(node_path)
            probs = [x["edge_probability"] for x in edge_path]
            conf = math.exp(sum(math.log(max(p, 1e-6)) for p in probs) / len(probs))
            cand = {
                "nodes": list(node_path),
                "edges": list(edge_path),
                "hops": len(edge_path),
                "confidence": round(conf, 4),
                "total_flow": sum(x["count"] for x in edge_path),
                "total_threats": sum(x["threat_count"] for x in edge_path),
                "tactics": [x["tactic"] for x in edge_path if x.get("tactic")],
                "mitre_ids": [x["mitre_id"] for x in edge_path if x.get("mitre_id")],
            }
            old = found.get(key)
            if old is None or cand["confidence"] > old["confidence"]:
                found[key] = cand
        if len(edge_path) >= max_hops:
            return
        # Branching cap: top 3 outgoing edges per hop keeps the search
        # fast on a 200-pair graph instead of exploding combinatorially.
        for nxt in adj.get(current, [])[:3]:
            if nxt["target"] in node_path:
                continue
            dfs(nxt["target"], node_path + [nxt["target"]], edge_path + [nxt])

    for src in sources:
        dfs(src, [src], [])

    paths = sorted(found.values(),
                   key=lambda p: (-p["confidence"], -p["total_threats"], p["hops"]))[:max_paths]
    for i, p in enumerate(paths):
        p["rank"] = i + 1
        p["is_most_likely"] = (i == 0)
    return {
        "paths": paths,
        "best_path": paths[0] if paths else None,
        "total_paths_found": len(paths),
        "confidence_formula": ("edge_probability = (threat_count + 0.5) / (count + 1); "
                               "path_confidence = geometric mean of edge probabilities"),
    }
