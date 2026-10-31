"""Mitigata FastAPI backend (Agents 1-5).

Run:  uvicorn backend.main:app --host 0.0.0.0 --port 8000   (from repo root)
Frontend dev: `vite` (vite.config.ts proxies /api -> localhost:8000).
Production: build the frontend once (`npm run build`); if dist/ exists it is
served statically after the API routes below.

Payload shapes match what DashboardPage.tsx already consumes -- no UI change
was made. Sample load streams edr_events.json through the SAME ingestion
path as uploads; there is no separate in-memory path.
"""
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.database import (
    aggregate_counts, alerts_count, clear_logs, get_health_stats,
    get_sample_logs, init_schema, get_db_connection, ip_host_map, top_edges, total_rows,
)
from backend.ingestion import (active_ingestion_jobs, detect_format,
                               ingest_path, ingest_path_parallel, ingest_upload,
                               parse_line)
from backend.agents.pipeline import build_graph_from_aggregates
from backend.agents.risk_quantum import compute_risk_from_aggregates, execute_quantum_lookahead
from backend.agents.reporting import (
    GENERATED_REPORTS_CACHE, generate_multilingual_narrative, generate_pdf_report,
)
from backend.schemas import ReportRequest

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("mitigata.backend")
ROOT = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_schema(get_db_connection())
    yield


app = FastAPI(title="Mitigata Autonomous Cyber Defense Platform", version="2.1.0",
              lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])


# ------------------------------------------------------------ dashboard payload
def _severity_word(score_100: float) -> str:
    return "critical" if score_100 >= 85 else ("high" if score_100 >= 65
            else ("elevated" if score_100 >= 40 else "medium"))


def dashboard_payload() -> Dict[str, Any]:
    """Full dashboard payload built from DuckDB aggregates over ALL rows."""
    agg = aggregate_counts()
    edges_data = top_edges(60)
    # Quantum first (its per-node probabilities feed the graph nodes).
    graph0 = build_graph_from_aggregates(edges_data, host_map=ip_host_map())
    breach = ""
    if graph0["nodes"]:
        breach = graph0["nodes"][0]["ip"]
    quantum = execute_quantum_lookahead(graph0["graph"], current_node=breach) if breach else {
        "quantum_engine": "qiskit-unavailable", "predicted_next_hop": "",
        "transition_probability": 0.0, "candidates": []}
    qprobs = {c["target"]: c["probability"] for c in quantum.get("candidates", [])}
    graph = build_graph_from_aggregates(edges_data, quantum_probs=qprobs, host_map=ip_host_map())
    tactics = agg["tactics"]
    risk = compute_risk_from_aggregates({
        "total_rows": agg["total_rows"], "alerts_count": agg["alerts_count"],
        "distinct_tactics": agg["distinct_tactics"],
        "distinct_threat_sources": agg["distinct_threat_sources"],
        "tactics": tactics, "severities": agg["severities"],
        "has_lateral": any(t["tactic"] == "Lateral Movement" for t in tactics),
        "has_exfil": any(t["tactic"] == "Exfiltration" for t in tactics),
    }, graph["graph"])
    # Incidents: one per top threatened target (grouped target rows, top tactic).
    by_target: Dict[str, Dict[str, Any]] = {}
    for r in agg["by_target"]:
        key = (r["destination_ip"], r["tactic"])
        if key not in by_target or int(r["cnt"]) > int(by_target[key]["cnt"]):
            by_target[key] = r
    top_targets = sorted(by_target.values(), key=lambda r: int(r["cnt"]), reverse=True)[:5]
    top_mitre = (agg["mitres"][0]["mitre_id"] if agg["mitres"] else "")
    incidents = []
    for i, r in enumerate(top_targets):
        sev_word = _severity_word(risk["overall_score"])
        incidents.append({
            "id": f"INC-{abs(hash(r['destination_ip'])) % 9000 + 1000}",
            "title": f"{r['tactic'] or 'Threat'} activity targeting {r['destination_ip']}",
            "severity": sev_word, "score": round(risk["overall_score"] / 10, 1),
            "stage": r["tactic"] or "Unknown", "targetAsset": r["destination_ip"],
            "ipAddress": r["destination_ip"], "detectedAt": "now",
            "sourceEngine": "DuckDB", "status": "active",
            "description": (f"{int(r['cnt'])} merged alerts for {r['destination_ip']} "
                            f"({r['tactic']}, {r['mitre_id'] or 'no MITRE id'}). "
                            f"Risk {risk['overall_score']}/100, JEV {risk['jev_status']}: {risk['justification']}"),
            "sarvamSummaryByLang": {
                "en": f"{agg['total_rows']} rows ingested, {agg['alerts_count']} alerts. "
                      f"Top tactic: {tactics[0]['tactic'] if tactics else 'none'}.",
                "hi": f"{agg['total_rows']} लॉग्स में से {agg['alerts_count']} चेतावनियाँ मिलीं।",
                "te": f"{agg['total_rows']} లాగ్‌లలో {agg['alerts_count']} హెచ్చరికలు నమోదయ్యాయి।",
                "ml": f"{agg['total_rows']} ലോഗുകളിൽ {agg['alerts_count']} മുന്നറിയിപ്പുകൾ കണ്ടെത്തി.",
            },
            "quantumNextHop": {
                "predictedNode": quantum.get("predicted_next_hop", ""),
                "probability": quantum.get("transition_probability", 0.0),
                "mitreTechnique": top_mitre,
                "quarantineAction": quantum.get("containment_action", ""),
            },
        })
    return {
        "total_rows": agg["total_rows"], "alerts_count": agg["alerts_count"],
        "sample_logs": get_sample_logs(50),
        "incidents": incidents, "nodes": graph["nodes"], "edges": graph["edges"],
        "risk": risk, "quantum": quantum,
        "sarvam_summary": (f"Mitigata ingested {agg['total_rows']} events with "
                           f"{agg['alerts_count']} alerts. " +
                           (f"Top tactic: {tactics[0]['tactic']} ({tactics[0]['cnt']} alerts). " if tactics else "") +
                           f"Risk {risk['overall_score']}/100 ({risk['jev_status']}). "
                           f"Quantum next hop: {quantum.get('predicted_next_hop', '')} "
                           f"({quantum.get('transition_probability', 0)})."),
    }


# ------------------------------------------------------------ health / logs
@app.get("/api/health")
async def health():
    return get_health_stats()


@app.get("/api/logs/sample")
async def logs_sample(limit: int = Query(50, ge=1, le=500)):
    rows = get_sample_logs(limit)
    return {"total_in_db": total_rows(), "returned_count": len(rows), "sample_logs": rows}


@app.delete("/api/logs")
async def logs_delete():
    clear_logs()
    return {"status": "success", "message": "All log records deleted from DuckDB."}


@app.get("/api/ingest/progress")
async def ingest_progress(job_id: str = Query(...)):
    if job_id in active_ingestion_jobs:
        return active_ingestion_jobs[job_id]
    return {"status": "pending", "bytes_processed": 0, "total_bytes": 0, "percent": 0.0,
            "remaining_bytes": 0, "rows_ingested": 0, "elapsed_seconds": 0.0}


# ------------------------------------------------------------ ingest / sample
@app.post("/api/ingest")
async def ingest(file: UploadFile = File(...), job_id: Optional[str] = Query(None)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file must have a valid filename.")
    try:
        rows, _alerts, _bytes, duration = await ingest_upload(file, job_id=job_id)
    except Exception as e:
        logger.error(f"Ingest failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ingestion error: {e}")
    finally:
        await file.close()
    payload = dashboard_payload()
    payload.update({
        "ingested_rows": rows, "duration_seconds": round(duration, 3),
        "throughput_rows_per_second": round(rows / duration, 2) if duration > 0 else float(rows),
    })
    return payload


@app.get("/api/ingest/detect")
async def ingest_detect(path: str = Query(...)):
    """Read the first 200 lines of a file inside the repo root and report
    its detected format + first parsed rows. No data is loaded."""
    target = (ROOT / path).resolve()
    if ROOT not in target.parents and target != ROOT:
        raise HTTPException(status_code=400, detail="Path must be inside the repo root.")
    if not target.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {path}")
    with open(target, "rb") as fh:
        head = [fh.readline().decode("utf-8", errors="replace") for _ in range(200)]
    fmt = detect_format(head)
    parsed = []
    for line in head:
        if line.strip():
            rec = parse_line(line.rstrip("\n"))
            if rec is not None:
                parsed.append({"timestamp": str(rec[0]), "source_ip": rec[1],
                               "destination_ip": rec[2], "user": rec[3],
                               "host": rec[4], "event_type": rec[5],
                               "status": rec[6], "port": rec[7], "bytes": rec[8],
                               "sigma": rec[9], "mitre": rec[10], "tactic": rec[11],
                               "severity": rec[12], "is_threat": rec[13],
                               "domain": rec[15] if len(rec) > 15 else None,
                               "device_name": rec[16] if len(rec) > 16 else None})
            if len(parsed) >= 5:
                break
    return {"path": path, "size_bytes": target.stat().st_size,
            "detected_format": fmt, "sample_rows": parsed}


@app.post("/api/ingest/local")
async def ingest_local(path: str = Query(...), workers: Optional[int] = Query(None)):
    """Ingest a file already on the server/PC (e.g. firex-10G.log in the
    repo root) with the parallel path. This avoids uploading 6 GB through
    the browser. The path must stay inside the repo root."""
    target = (ROOT / path).resolve()
    if ROOT not in target.parents and target != ROOT:
        raise HTTPException(status_code=400, detail="Path must be inside the repo root.")
    if not target.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {path}")
    try:
        rows, _alerts, _bytes, duration = ingest_path_parallel(str(target), workers=workers)
    except Exception as e:
        logger.error(f"Local ingest failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ingestion error: {e}")
    payload = dashboard_payload()
    payload.update({
        "ingested_rows": rows, "duration_seconds": round(duration, 3),
        "throughput_rows_per_second": round(rows / duration, 2) if duration > 0 else float(rows),
    })
    return payload


@app.post("/api/sample/load")
async def sample_load():
    """Clear, then stream edr_events.json through the upload ingestion path."""
    sample = ROOT / "edr_events.json"
    if not sample.exists():
        raise HTTPException(status_code=404, detail="edr_events.json not found in repo root.")
    clear_logs()
    start = time.perf_counter()
    rows, _alerts, _bytes, duration = ingest_path(str(sample))
    payload = dashboard_payload()
    payload.update({
        "ingested_rows": rows, "duration_seconds": round(duration, 3),
        "throughput_rows_per_second": round(rows / duration, 2) if duration > 0 else float(rows),
    })
    return payload


# ------------------------------------------------------------ agents 1-4
@app.post("/api/analyze")
async def analyze():
    agg = aggregate_counts()
    edges_data = top_edges(60)
    graph = build_graph_from_aggregates(edges_data)
    breach = graph["nodes"][0]["ip"] if graph["nodes"] else ""
    quantum = execute_quantum_lookahead(graph["graph"], current_node=breach) if breach else {}
    risk = compute_risk_from_aggregates({
        "total_rows": agg["total_rows"], "alerts_count": agg["alerts_count"],
        "distinct_tactics": agg["distinct_tactics"],
        "distinct_threat_sources": agg["distinct_threat_sources"],
        "tactics": agg["tactics"], "severities": agg["severities"],
        "has_lateral": any(t["tactic"] == "Lateral Movement" for t in agg["tactics"]),
        "has_exfil": any(t["tactic"] == "Exfiltration" for t in agg["tactics"]),
    }, graph["graph"])
    return {"status": "success", "total_analyzed_logs": agg["total_rows"],
            "threat_events_count": agg["alerts_count"],
            "topology": {"nodes": graph["nodes"], "edges": graph["edges"],
                         "total_nodes": len(graph["nodes"]), "total_edges": len(graph["edges"])},
            "risk_assessment": risk, "quantum_forecast": quantum}


@app.get("/api/graph/topology")
async def graph_topology():
    graph = build_graph_from_aggregates(top_edges(60))
    return {"nodes": graph["nodes"], "edges": graph["edges"],
            "total_nodes": len(graph["nodes"]), "total_edges": len(graph["edges"])}


class RiskRequest(BaseModel):
    events: Optional[List[Dict[str, Any]]] = None


@app.post("/api/risk-scores")
async def risk_scores(body: Optional[RiskRequest] = None):
    if body and body.events:
        from backend.agents.risk_quantum import compute_incident_risk_score
        return compute_incident_risk_score(body.events)
    agg = aggregate_counts()
    graph = build_graph_from_aggregates(top_edges(60))
    return compute_risk_from_aggregates({
        "total_rows": agg["total_rows"], "alerts_count": agg["alerts_count"],
        "distinct_tactics": agg["distinct_tactics"],
        "distinct_threat_sources": agg["distinct_threat_sources"],
        "tactics": agg["tactics"], "severities": agg["severities"],
        "has_lateral": any(t["tactic"] == "Lateral Movement" for t in agg["tactics"]),
        "has_exfil": any(t["tactic"] == "Exfiltration" for t in agg["tactics"]),
    }, graph["graph"])


@app.post("/api/quantum-predict")
async def quantum_predict(body: Optional[Dict[str, Any]] = None):
    graph = build_graph_from_aggregates(top_edges(60))
    current = (body or {}).get("current_node") or (graph["nodes"][0]["ip"] if graph["nodes"] else "")
    return execute_quantum_lookahead(graph["graph"], current_node=current)


# ------------------------------------------------------------ agent 5: reports
@app.post("/api/reports/generate")
async def reports_generate(body: ReportRequest):
    agg = aggregate_counts()
    ctx = {"title": body.title, "severity": body.severity, "score": body.score,
           "target_asset": body.target_asset, "predicted_next_hop": body.predicted_next_hop,
           "probability": body.probability, "total_rows": agg["total_rows"],
           "alerts_count": agg["alerts_count"],
           "mitre_tactics": body.mitre_tactics or [t["tactic"] for t in agg["tactics"][:3]]}
    lang = body.language if body.language in ("en", "hi", "te", "ml") else "en"
    narrative = generate_multilingual_narrative(ctx, language=lang)
    report_id, _pdf = generate_pdf_report(ctx, narrative["narrative"], language=lang)
    return {"status": "success", "report_id": report_id, "incident_id": body.incident_id,
            "language": lang, "ai_provider": narrative["provider"],
            "narrative": narrative["narrative"],
            "download_url": f"/api/reports/download/{report_id}"}


@app.get("/api/reports/download/{report_id}")
async def reports_download(report_id: str):
    cached = GENERATED_REPORTS_CACHE.get(report_id)
    if not cached:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return Response(content=cached["pdf_bytes"], media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=Mitigata_Report_{report_id}.pdf"})


# ------------------------------------------------------------ static frontend (if built)
_dist = ROOT / "dist"
if _dist.is_dir() and (_dist / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(_dist), html=True), name="frontend")
