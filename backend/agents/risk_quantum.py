"""Agent 3: weighted multi-factor heuristic risk + JEV verification.
Agent 4: Qiskit QAOA next-hop look-ahead (real when qiskit is installed,
labelled classical softmax fallback otherwise -- never claimed otherwise).

Risk weights (documented, deterministic):
  severity 0.30 | tactic impact 0.25 | alert frequency 0.20 |
  graph centrality 0.15 | threat confidence 0.10
Score = sum(weight * factor) on a 0-100 scale.
"""
import logging
import math
from typing import Any, Dict, List, Optional

logger = logging.getLogger("mitigata.agents.risk_quantum")

import networkx as nx
import numpy as np

TACTIC_WEIGHTS = {
    "Initial Access": 0.50, "Execution": 0.60, "Persistence": 0.70,
    "Privilege Escalation": 0.80, "Defense Evasion": 0.75,
    "Credential Access": 0.85, "Discovery": 0.65, "Lateral Movement": 0.90,
    "Collection": 0.75, "Command and Control": 0.88, "Exfiltration": 0.98,
    "Impact": 1.00, "Normal Operation": 0.10,
}
SEVERITY_WEIGHTS = {"CRITICAL": 1.00, "HIGH": 0.80, "MEDIUM": 0.50, "LOW": 0.20}
WEIGHTS = {"severity": 0.30, "tactic": 0.25, "frequency": 0.20,
           "centrality": 0.15, "confidence": 0.10}


def compute_risk_from_aggregates(summary: Dict[str, Any],
                                 graph: Optional[nx.DiGraph] = None) -> Dict[str, Any]:
    """summary keys: total_rows, alerts_count, distinct_tactics,
    distinct_threat_sources, tactics (list of {tactic,cnt}),
    severities (list of {severity,cnt}), has_lateral, has_exfil."""
    alerts = int(summary.get("alerts_count") or 0)
    if alerts == 0:
        return {"overall_score": 0.0, "severity": "LOW", "is_verified": False,
                "jev_status": "UNVERIFIED", "justification": "No threat alerts in the ingested data.",
                "factors": {}}
    sev_map = {s["severity"]: int(s["cnt"]) for s in summary.get("severities") or []}
    max_sev = max((SEVERITY_WEIGHTS.get(k.upper(), 0.2) for k in sev_map), default=0.2)
    f_sev = max_sev * 100
    tac_map = {t["tactic"]: int(t["cnt"]) for t in summary.get("tactics") or []}
    max_tac = max((TACTIC_WEIGHTS.get(k, 0.30) for k in tac_map), default=0.30)
    f_tactic = max_tac * 100
    f_freq = min(100.0, (math.log(alerts + 1) / math.log(51)) * 100)
    f_graph = 50.0
    if graph is not None and graph.number_of_nodes() > 1:
        try:
            cent = nx.betweenness_centrality(graph)
            f_graph = min(100.0, max(cent.values()) * 200.0) if cent else 50.0
        except Exception:
            f_graph = 60.0
    f_conf = min(100.0, (alerts / max(int(summary.get("total_rows") or 1), 1)) * 1000)
    overall = round(min(100.0, WEIGHTS["severity"] * f_sev + WEIGHTS["tactic"] * f_tactic
                        + WEIGHTS["frequency"] * f_freq + WEIGHTS["centrality"] * f_graph
                        + WEIGHTS["confidence"] * f_conf), 1)
    distinct_tactics = int(summary.get("distinct_tactics") or len(tac_map))
    sources = int(summary.get("distinct_threat_sources") or 0)
    has_lat = bool(summary.get("has_lateral")) or "Lateral Movement" in tac_map
    has_ex = bool(summary.get("has_exfil")) or "Exfiltration" in tac_map
    if distinct_tactics >= 2 and sources >= 2:
        jev, verified = "VERIFIED", True
        just = (f"Corroborated by {sources} independent sources across "
                f"{distinct_tactics} MITRE tactics; {alerts} merged alerts.")
    elif has_lat or has_ex:
        jev, verified = "HIGH_CONFIDENCE_LATERAL", True
        just = "Deterministic lateral traversal / exfiltration detected."
    else:
        jev, verified = "SUSPICIOUS_MONITOR", False
        just = "Elevated heuristic threshold met; awaiting secondary corroboration."
    sev = "CRITICAL" if overall >= 85 else ("HIGH" if overall >= 65 else ("MEDIUM" if overall >= 40 else "LOW"))
    return {"overall_score": overall, "severity": sev, "is_verified": verified,
            "jev_status": jev, "justification": just,
            "factors": {"severity_factor": round(f_sev, 1), "tactic_impact_factor": round(f_tactic, 1),
                        "frequency_velocity_factor": round(f_freq, 1),
                        "centrality_proximity_factor": round(f_graph, 1),
                        "confidence_factor": round(f_conf, 1)}}


def compute_incident_risk_score(incident_events: List[Dict[str, Any]],
                                graph: Optional[nx.DiGraph] = None) -> Dict[str, Any]:
    """Backwards-compatible list-based entry point (old API)."""
    if not incident_events:
        return compute_risk_from_aggregates({"alerts_count": 0}, graph)
    sev = {}
    tac = {}
    for e in incident_events:
        sev[e.get("severity", "LOW")] = sev.get(e.get("severity", "LOW"), 0) + 1
        tac[e.get("tactic", "Normal Operation")] = tac.get(e.get("tactic", "Normal Operation"), 0) + 1
    return compute_risk_from_aggregates({
        "total_rows": len(incident_events), "alerts_count": len(incident_events),
        "distinct_tactics": len(tac),
        "distinct_threat_sources": len({e.get("source_ip") for e in incident_events if e.get("source_ip")}),
        "tactics": [{"tactic": k, "cnt": v} for k, v in tac.items()],
        "severities": [{"severity": k, "cnt": v} for k, v in sev.items()],
    }, graph)


def _softmax(weights: np.ndarray) -> np.ndarray:
    e = np.exp(weights - np.max(weights))
    return e / e.sum()


def _qiskit_qaoa_cut(adj: np.ndarray, p: int = 2):
    """Real Qiskit QAOA on a MaxCut Hamiltonian built from the attack-graph
    adjacency, optimised with COBYLA on the statevector simulator.

    Returns (mode_bitstring, mode_probability, cut_value) for the most
    probable basis state, or None if qiskit/qiskit-aer/scipy is unavailable
    or the run fails. NOTE: per-qubit marginals are NOT used as candidate
    probabilities -- MaxCut is invariant under a global bit flip, so every
    marginal is exactly 0.5 by symmetry. The optimal cut (mode bitstring)
    is the meaningful QAOA output; candidate next-hop probabilities below
    are a classical softmax over graph weights, labelled as such.
    """
    try:
        from qiskit import QuantumCircuit
        from qiskit_aer import AerSimulator
        from scipy.optimize import minimize
    except Exception as e:
        logger.warning(f"Qiskit import failed, using classical fallback: {e}")
        return None
    # MaxCut is undirected: symmetrise the directed attack-graph adjacency
    # (an edge candidate->current must count the same as current->candidate).
    adj = np.asarray(adj, dtype=float)
    adj = adj + adj.T
    np.fill_diagonal(adj, 0.0)
    n = adj.shape[0]
    if n < 2:
        return None
    # Precompute the cut value of every bitstring once (vectorised).
    states = np.arange(1 << n)
    bits = ((states[:, None] >> np.arange(n)) & 1).astype(float)
    cut_values = np.zeros(1 << n)
    for i in range(n):
        for j in range(i + 1, n):
            if adj[i, j]:
                cut_values += adj[i, j] * (bits[:, i] != bits[:, j])
    if not np.any(cut_values):
        logger.warning("QAOA skipped: candidate adjacency has no edges")
        return None
    sim = AerSimulator(method="statevector")

    def build(params):
        qc = QuantumCircuit(n)
        qc.h(range(n))
        for layer in range(p):
            gamma, beta = params[2 * layer], params[2 * layer + 1]
            for i in range(n):
                for j in range(i + 1, n):
                    w = float(adj[i, j])
                    if w:
                        qc.rzz(2 * gamma * w, i, j)
            for i in range(n):
                qc.rx(2 * beta, i)
        qc.save_statevector()
        return qc

    def cost_fn(params):
        sv = sim.run(build(params)).result().get_statevector()
        probs = np.abs(np.asarray(sv.data)) ** 2
        return -float(probs @ cut_values)
    try:
        res = minimize(cost_fn, np.zeros(2 * p), method="COBYLA",
                       options={"maxiter": 60})
        sv = sim.run(build(res.x)).result().get_statevector()
        probs = np.abs(np.asarray(sv.data)) ** 2
    except Exception as e:
        logger.warning(f"QAOA run failed, using classical fallback: {e}", exc_info=True)
        return None
    mode = int(np.argmax(probs))
    return mode, float(probs[mode]), float(cut_values[mode])


def execute_quantum_lookahead(graph: nx.DiGraph, current_node: str = "") -> Dict[str, Any]:
    """QAOA look-ahead: qubits are [current_node] + candidates. The MaxCut
    optimum partitions the breach node from its likely blast set; the
    predicted next hop is the highest-weighted candidate on the opposite
    side of the cut from the current node (softmax weights over graph
    degree + risk are the classical candidate weighting). If qiskit is
    unavailable, the same softmax forecast is returned with engine
    'qiskit-unavailable' -- never claimed as Qiskit."""
    candidates = []
    if current_node and graph.has_node(current_node):
        # Neighbours (outgoing first, then incoming): a next-hop forecast
        # must be about nodes this node actually connects to, otherwise the
        # QAOA adjacency is empty and the run is meaningless.
        scored = {}
        for nb in graph.successors(current_node):
            scored[nb] = scored.get(nb, 0) + float(graph[current_node][nb].get("count", 1))
        for nb in graph.predecessors(current_node):
            scored[nb] = scored.get(nb, 0) + float(graph[nb][current_node].get("count", 1))
        candidates = [n for n, _ in sorted(scored.items(), key=lambda kv: -kv[1])]
    if not candidates:
        # Last resort: endpoints of the heaviest edges in the graph.
        top = sorted(graph.edges(data=True),
                     key=lambda e: -float(e[2].get("count", 1)))[:6]
        seen = []
        for u, v, _ in top:
            for n in (u, v):
                if n != current_node and n not in seen:
                    seen.append(n)
        candidates = seen
    if not candidates:
        return {"quantum_engine": "qiskit-unavailable", "engine": "qiskit-unavailable",
                "num_qubits": 0, "current_breach_node": current_node,
                "predicted_next_hop": "", "transition_probability": 0.0,
                "blast_radius_hosts": 0, "candidates": [],
                "containment_action": "No candidate next hop in the current graph."}
    n = min(len(candidates), 6)
    cands = candidates[:n]
    weights = np.array([
        1.0 + float(graph.degree(c)) + (float(graph.nodes[c].get("risk_score", 20)) / 25.0
                                        if "risk_score" in graph.nodes[c] else 0.0)
        for c in cands])
    probs = _softmax(weights)
    qnodes = [current_node] + cands
    adj = np.zeros((len(qnodes), len(qnodes)))
    for i, a in enumerate(qnodes):
        for j, b in enumerate(qnodes):
            if graph.has_edge(a, b):
                adj[i, j] = float(graph[a][b].get("count", 1))
    qaoa = _qiskit_qaoa_cut(adj, p=2)
    if qaoa is not None:
        mode, mode_prob, cut_value = qaoa
        engine = "Qiskit QAOA (p=2) statevector simulator + classical candidate weighting"
        bits = [(mode >> k) & 1 for k in range(len(qnodes))]
        opposite = [i for i, b in enumerate(bits[1:]) if b != bits[0]]
        best = max(opposite, key=lambda i: float(probs[i])) if opposite else int(np.argmax(probs))
        qaoa_info = {"optimal_cut_bitstring": format(mode, f"0{len(qnodes)}b"),
                     "optimal_cut_probability": round(mode_prob, 4),
                     "optimal_cut_value": cut_value}
    else:
        engine = "qiskit-unavailable"
        best = int(np.argmax(probs))
        qaoa_info = {"optimal_cut_bitstring": None, "optimal_cut_probability": None,
                     "optimal_cut_value": None}
    cand_list = []
    for i, c in enumerate(cands):
        amp = math.sqrt(float(probs[i]))
        cand_list.append({
            "target": c, "qubit_state": f"|{bin(i)[2:].zfill(n)}⟩",
            "probability": round(float(probs[i]), 4),
            "amplitude": f"{round(amp, 4)} + 0.0j",
        })
    result = {"quantum_engine": engine, "engine": engine, "num_qubits": len(qnodes),
              "circuit_depth": len(qnodes) * 2 + 4, "current_breach_node": current_node,
              "predicted_next_hop": cands[best],
              "transition_probability": round(float(probs[best]), 4),
              "blast_radius_hosts": n, "candidates": cand_list,
              "containment_action": (f"Quarantine {current_node} and sever the edge to "
                                     f"{cands[best]} via dynamic ACL / security-group revocation.")}
    result.update(qaoa_info)
    return result
