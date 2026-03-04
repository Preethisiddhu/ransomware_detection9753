# backend/app.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Literal, Optional
from datetime import datetime

from monitoring.event_store import (
    get_recent_events,
    get_current_status,
    get_suspicious_processes,
    add_event,
)

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