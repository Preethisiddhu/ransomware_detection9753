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
    add_event,
)
from backend.scanner.file_scanner import scan_file

app = FastAPI(title="Ransomware Detection Backend")

# Allow frontend (same machine, different port)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later
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


@app.get("/api/status", response_model=SystemStatus)
def api_status():
    return get_current_status()


@app.get("/api/events", response_model=List[FileEvent])
def api_events(limit: int = 50):
    return get_recent_events(limit)


@app.get("/api/suspicious-processes", response_model=List[SuspiciousProcess])
def api_suspicious_processes():
    return get_suspicious_processes()


@app.post("/api/events", response_model=FileEvent)
def api_add_event(event: FileEvent):
    add_event(event.model_dump())
    return event


@app.post("/api/scan-file", response_model=ScanResult)
def api_scan_file(req: ScanRequest):
    res = scan_file(req.path)
    return res