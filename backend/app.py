# backend/app.py
from datetime import datetime
from typing import List, Literal, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.monitoring.event_store import (
    get_recent_events,
    get_current_status,
    get_suspicious_processes,
    get_recent_scan_results,
    get_mass_alerts,
    add_event,
    add_scan_result,
)
from backend.scanner.file_scanner import scan_file

app = FastAPI(title="Ransomware Detection Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class FileEvent(BaseModel):
    timestamp: datetime
    process_name: str
    pid: int
    operation: Literal["create", "modify", "delete", "rename"]
    path: str
    risk_score: float


class SystemStatus(BaseModel):
    status: Literal["safe", "suspicious", "ransomware_detected"]
    last_detection_time: Optional[datetime]
    total_events_24h: int
    suspicious_processes_count: int
    active_mass_alerts: int


class SuspiciousProcess(BaseModel):
    process_name: str
    pid: int
    files_touched: int
    risk_score: float


class ScanRequest(BaseModel):
    path: str


class ScanResult(BaseModel):
    path: str
    exists: bool
    score: float
    reasons: List[str]
    entropy: float
    malicious: bool
    scanned_at: Optional[datetime] = None
    trigger_op: Optional[str] = None


class MassAlert(BaseModel):
    timestamp: datetime
    process_name: str
    operation: str
    count: int
    window_secs: int
    severity: str


@app.get("/api/status", response_model=SystemStatus)
def api_status():
    return get_current_status()


@app.get("/api/events", response_model=List[FileEvent])
def api_events(limit: int = 100):
    return get_recent_events(limit)


@app.post("/api/events", response_model=FileEvent)
def api_add_event(event: FileEvent):
    add_event(event.model_dump())
    return event


@app.get("/api/scan-results", response_model=List[ScanResult])
def api_scan_results(limit: int = 100):
    return get_recent_scan_results(limit)


@app.post("/api/scan-results", response_model=ScanResult)
def api_add_scan_result(result: ScanResult):
    add_scan_result(result.model_dump())
    return result


@app.get("/api/mass-alerts", response_model=List[MassAlert])
def api_mass_alerts(limit: int = 50):
    return get_mass_alerts(limit)


@app.get("/api/suspicious-processes", response_model=List[SuspiciousProcess])
def api_suspicious_processes():
    return get_suspicious_processes()


@app.post("/api/scan-file", response_model=ScanResult)
def api_scan_file(req: ScanRequest):
    res = scan_file(req.path)
    res["scanned_at"] = datetime.utcnow().isoformat()
    res["trigger_op"] = "manual"
    add_scan_result(res)
    return res