# backend/monitoring/event_store.py
from collections import deque, defaultdict
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Literal, Optional

Event = Dict[str, object]

_events: Deque[Event] = deque(maxlen=5000)
_last_detection_time: Optional[datetime] = None

def add_event(event: Event) -> None:
    global _last_detection_time
    _events.append(event)
    if event.get("risk_score", 0.0) >= 0.8:
        _last_detection_time = event["timestamp"]

def get_recent_events(limit: int) -> List[Event]:
    return list(_events)[-limit:][::-1]

def get_current_status() -> Dict[str, object]:
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=24)
    last24 = [e for e in _events if e["timestamp"] >= cutoff]

    max_risk = max((e.get("risk_score", 0.0) for e in last24), default=0.0)

    if max_risk >= 0.9:
        status = "ransomware_detected"
    elif max_risk >= 0.6:
        status = "suspicious"
    else:
        status = "safe"

    return {
        "status": status,
        "last_detection_time": _last_detection_time,
        "total_events_24h": len(last24),
        "suspicious_processes_count": len(get_suspicious_processes()),
    }

def get_suspicious_processes() -> List[Dict[str, object]]:
    per_proc: Dict[tuple, Dict[str, object]] = defaultdict(
        lambda: {"files_touched": 0, "max_risk": 0.0}
    )
    for e in _events:
        key = (e["process_name"], e["pid"])
        per_proc[key]["files_touched"] += 1
        per_proc[key]["max_risk"] = max(
            per_proc[key]["max_risk"], e.get("risk_score", 0.0)
        )

    res = []
    for (name, pid), stats in per_proc.items():
        if stats["max_risk"] >= 0.6:
            res.append(
                {
                    "process_name": name,
                    "pid": pid,
                    "files_touched": stats["files_touched"],
                    "risk_score": stats["max_risk"],
                }
            )
    return res