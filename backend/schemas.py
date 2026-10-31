from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class ReportRequest(BaseModel):
    incident_id: Optional[str] = None
    title: Optional[str] = "Cyber Incident Investigation Report"
    severity: Optional[str] = "CRITICAL"
    score: Optional[float] = 0.0
    target_asset: Optional[str] = None
    predicted_next_hop: Optional[str] = None
    probability: Optional[float] = 0.0
    language: Optional[str] = "en"
    mitre_tactics: Optional[List[str]] = None
