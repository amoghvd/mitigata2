"""Agent 5: Sarvam AI narrative -> Ollama fallback -> grounded template.

The Sarvam key is read ONLY from the SARVAM_API_KEY environment variable at
call time (never a default, never a file, never a log). If it is absent, or
Sarvam times out / rate-limits, we try local Ollama (OLLAMA_API_URL,
OLLAMA_MODEL, default llama3), then a deterministic template that uses only
numbers supplied in incident_context -- never hardcoded totals.
PDF: reportlab if installed, else a minimal valid PDF writer.
GENERATED_REPORTS_CACHE is bounded (oldest entries evicted).
"""
import json
import os
import uuid
import urllib.error
import urllib.request
from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, Tuple

SUPPORTED_LANGUAGES = {"en": "English", "hi": "Hindi", "te": "Telugu", "ml": "Malayalam"}
MAX_REPORTS = 50
GENERATED_REPORTS_CACHE: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()


def _sarvam_url() -> str:
    return os.environ.get("SARVAM_API_URL", "https://api.sarvam.ai/v1/chat/completions")


def _post_json(url: str, payload: Dict[str, Any], headers: Dict[str, str], timeout: float):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def generate_multilingual_narrative(incident_context: Dict[str, Any],
                                    language: str = "en") -> Dict[str, Any]:
    # Belt and braces: the .env file is loaded at app startup, but a
    # direct call to this function (reports endpoint, tests) should also
    # see a key that was only put in backend/.env, not exported.
    try:
        from backend.dotenv import load_env_files
        load_env_files()
    except Exception:
        pass
    title = incident_context.get("title", "High-Priority Threat Incident")
    severity = incident_context.get("severity", "CRITICAL")
    score = incident_context.get("score", 0)
    tactics = ", ".join(incident_context.get("mitre_tactics") or ["Credential Access"])
    target = incident_context.get("target_asset", "Internal infrastructure")
    predicted = incident_context.get("predicted_next_hop", "Unknown")
    prob = incident_context.get("probability", 0)
    total = incident_context.get("total_rows")
    alerts = incident_context.get("alerts_count")
    lang_name = SUPPORTED_LANGUAGES.get(language, "English")
    prompt = (
        f"You are Mitigata Security Intelligence AI. Write a clear executive incident brief in {lang_name}.\n"
        f"Incident: {title}\nSeverity: {severity} (Risk Score: {score}/10)\n"
        f"MITRE ATT&CK Tactics: {tactics}\nTarget asset: {target}\n"
        f"Quantum next-hop forecast: {predicted} (probability {prob})\n"
        + (f"Telemetry: {total} rows ingested, {alerts} alerts.\n" if total is not None else "") +
        "Cover: 1) key statistics, 2) main malicious activities, 3) containment actions."
    )
    key = os.environ.get("SARVAM_API_KEY", "").strip()
    if key:
        try:
            res = _post_json(_sarvam_url(), {
                "model": "sarvam-m", "messages": [
                    {"role": "system", "content": "You are Mitigata Security Intelligence AI."},
                    {"role": "user", "content": prompt}],
                "temperature": 0.2, "max_tokens": 512},
                {"Content-Type": "application/json", "api-subscription-key": key}, timeout=20.0)
            text = res["choices"][0]["message"]["content"].strip()
            if text:
                return {"narrative": text, "provider": "Sarvam AI", "language": language,
                        "timestamp": datetime.utcnow().isoformat()}
        except Exception:
            pass  # fall through to Ollama, then template
    try:
        res = _post_json(os.environ.get("OLLAMA_API_URL", "http://localhost:11434/api/generate"),
                         {"model": os.environ.get("OLLAMA_MODEL", "llama3"),
                          "prompt": prompt, "stream": False},
                         {"Content-Type": "application/json"}, timeout=5.0)
        text = (res.get("response") or "").strip()
        if text:
            return {"narrative": text, "provider": "Local Ollama (fallback)", "language": language,
                    "timestamp": datetime.utcnow().isoformat()}
    except Exception:
        pass
    stats = (f"Telemetry: {total} rows ingested with {alerts} alerts. " if total is not None else "")
    templates = {
        "en": (f"EXECUTIVE INCIDENT BRIEF\n\n{stats}Incident '{title}' ({severity}, risk {score}/10) "
               f"targets {target} via {tactics}. Quantum look-ahead forecasts '{predicted}' "
               f"as the next hop (probability {prob}). Recommended actions: isolate the target asset, "
               "revoke exposed credentials, and block the predicted next-hop edge."),
        "hi": (f"सुरक्षा ब्रीफ: '{title}' ({severity}, जोखिम {score}/10) लक्ष्य {target} है, रणनीति {tactics}। "
               f"अगला संभावित लक्ष्य '{predicted}' (संभावना {prob}) है। तत्काल नेटवर्क आइसोलेशन और क्रेडेंशियल रिवोकेशन की सलाह दी जाती है।"),
        "te": (f"భద్రతా నివేదిక: '{title}' ({severity}, రిస్క్ {score}/10) లక్ష్యం {target}, వ్యూహం {tactics}। "
               f"తదుపరి లక్ష్యం '{predicted}' (సంభావ్యత {prob}). వెంటనే నెట్‌వర్క్ ఐసోలేషన్ మరియు క్రెడెన్షియల్ రద్దు చేయండి."),
        "ml": (f"സുരക്ഷാ റിപ്പോർട്ട്: '{title}' ({severity}, റിസ്ക് {score}/10) ലക്ഷ്യം {target}, തന്ത്രം {tactics}। "
               f"അടുത്ത ലക്ഷ്യം '{predicted}' (സാധ്യത {prob}). ഉടൻ നെറ്റ്‌വർക്ക് ഐസൊലേഷനും ക്രെഡൻഷ്യൽ റദ്ദാക്കലും നടത്തുക."),
    }
    return {"narrative": templates.get(language, templates["en"]),
            "provider": "Deterministic template (no AI provider available)",
            "language": language, "timestamp": datetime.utcnow().isoformat()}


def _minimal_pdf(report_id: str, title: str, narrative: str) -> bytes:
    lines = [f"MITIGATA EXECUTIVE INCIDENT REPORT", f"Report ID: {report_id}", f"Incident: {title}", ""]
    lines += narrative.split("\n")
    # Simpler, valid construction: one content stream with absolute moves.
    stream = "BT /F1 12 Tf\n"
    yy = 740
    for ln in lines:
        safe = ln.replace("\\", "").replace("(", "[").replace(")", "]")[:110]
        stream += f"40 {yy} Td ({safe}) Tj\n"
        yy -= 16
        if yy < 40:
            break
    stream += "ET\n"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >> stream\n" + stream.encode("latin-1", "replace") + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj ".encode() + obj + b" endobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer << /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def generate_pdf_report(incident_context: Dict[str, Any], narrative: str,
                        language: str = "en") -> Tuple[str, bytes]:
    report_id = f"REP-{uuid.uuid4().hex[:8].upper()}"
    title = incident_context.get("title", "Cyber Incident Investigation Report")
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        import io
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=letter)
        w, h = letter
        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, h - 50, "MITIGATA EXECUTIVE INCIDENT REPORT")
        c.setFont("Helvetica", 10)
        c.drawString(40, h - 70, f"Report ID: {report_id} | {datetime.utcnow().isoformat()} UTC")
        c.drawString(40, h - 88, f"Incident: {title}")
        y = h - 120
        c.setFont("Helvetica", 9)
        for ln in narrative.split("\n"):
            if y < 50:
                c.showPage(); y = h - 50; c.setFont("Helvetica", 9)
            c.drawString(40, y, ln[:105]); y -= 14
        c.save()
        pdf = buf.getvalue()
    except Exception:
        pdf = _minimal_pdf(report_id, title, narrative)
    GENERATED_REPORTS_CACHE[report_id] = {
        "report_id": report_id, "title": title, "language": language,
        "created_at": datetime.utcnow().isoformat(), "pdf_bytes": pdf,
    }
    while len(GENERATED_REPORTS_CACHE) > MAX_REPORTS:
        GENERATED_REPORTS_CACHE.popitem(last=False)
    return report_id, pdf
