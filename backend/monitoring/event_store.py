from __future__ import annotations

import os
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

MASS_WINDOW_SECONDS   = 10
MASS_THRESHOLD        = 5
HIGH_RISK_THRESHOLD   = 0.7
SUSPICIOUS_THRESHOLD  = 0.6
STATUS_WINDOW_SECONDS = 5

_lock         = threading.Lock()
_events: deque       = deque(maxlen=5000)
_scan_results: deque = deque(maxlen=2000)
_mass_alerts: deque  = deque(maxlen=500)

_proc_op_times: Dict[str, Dict[str, deque]] = defaultdict(
    lambda: defaultdict(lambda: deque(maxlen=1000))
)
_proc_stats: Dict[str, Dict] = defaultdict(
    lambda: {"files_touched": 0, "risk_score": 0.0, "pid": -1}
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _prune_old(dq: deque, window: float) -> None:
    cutoff = _now() - timedelta(seconds=window)
    while dq and dq[0] < cutoff:
        dq.popleft()


def _parse_dt(ts) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", ""))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _check_mass(process_name: str, op: str) -> Optional[dict]:
    times = _proc_op_times[process_name][op]
    _prune_old(times, MASS_WINDOW_SECONDS)
    count = len(times)
    if count >= MASS_THRESHOLD:
        return {
            "timestamp":    _now().isoformat(),
            "process_name": process_name,
            "operation":    op,
            "count":        count,
            "window_secs":  MASS_WINDOW_SECONDS,
            "severity":     "critical" if count >= MASS_THRESHOLD * 3 else "warning",
        }
    return None


def add_event(event: dict) -> Optional[dict]:
    with _lock:
        _events.append(event)

        proc = event.get("process_name", "unknown")
        op   = event.get("operation", "")
        pid  = event.get("pid", -1)
        risk = float(event.get("risk_score", 0.0))

        stats = _proc_stats[proc]
        stats["files_touched"] += 1
        stats["risk_score"]     = round(max(stats["risk_score"], risk), 2)
        stats["pid"]            = pid

        _proc_op_times[proc][op].append(_now())

        alert = _check_mass(proc, op)
        if alert:
            _mass_alerts.append(alert)
        return alert


def add_scan_result(result: dict) -> None:
    with _lock:
        _scan_results.append(result)


def remove_scan_results_for_path(path: str) -> None:
    """File delete ஆனா அந்த path scan results-ல் இருந்து remove பண்ணு."""
    norm = os.path.normpath(path)
    with _lock:
        to_keep = deque(maxlen=2000)
        for s in _scan_results:
            if os.path.normpath(str(s.get("path", ""))) != norm:
                to_keep.append(s)
        _scan_results.clear()
        _scan_results.extend(to_keep)
    print(f"[store] removed scan results for: {os.path.basename(path)}")


def get_recent_events(limit: int = 50) -> List[dict]:
    with _lock:
        items = list(_events)
    items.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)
    return items[:limit]


def get_recent_scan_results(limit: int = 50) -> List[dict]:
    with _lock:
        items = list(_scan_results)
    items.sort(key=lambda e: str(e.get("scanned_at", "")), reverse=True)
    return items[:limit]


def get_mass_alerts(limit: int = 50) -> List[dict]:
    with _lock:
        items = list(_mass_alerts)
    items.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)
    return items[:limit]


def get_suspicious_processes() -> List[dict]:
    with _lock:
        rows = []
        for name, stats in _proc_stats.items():
            if name == "unknown":
                continue
            if stats["risk_score"] >= SUSPICIOUS_THRESHOLD or stats["files_touched"] >= 3:
                rows.append({
                    "process_name":  name,
                    "pid":           stats["pid"],
                    "files_touched": stats["files_touched"],
                    "risk_score":    stats["risk_score"],
                })
    rows.sort(key=lambda r: r["risk_score"], reverse=True)
    return rows


def get_current_status() -> dict:
    with _lock:
        events_list = list(_events)
        alerts_list = list(_mass_alerts)
        scan_list   = list(_scan_results)
        named_procs = {
            name: stats for name, stats in _proc_stats.items()
            if name != "unknown"
        }

    now          = _now()
    cutoff_24h   = now - timedelta(hours=24)
    cutoff_5sec  = now - timedelta(seconds=STATUS_WINDOW_SECONDS)

    recent_24h  = []
    recent_5sec = []

    for e in events_list:
        dt = _parse_dt(e.get("timestamp", ""))
        if dt is None:
            continue
        if dt >= cutoff_24h:
            recent_24h.append(e)
        if dt >= cutoff_5sec:
            recent_5sec.append(e)

    max_risk = max(
        (float(e.get("risk_score", 0)) for e in recent_5sec),
        default=0.0
    )

    last_high = next(
        (e["timestamp"] for e in reversed(events_list)
         if float(e.get("risk_score", 0)) >= HIGH_RISK_THRESHOLD),
        None,
    )

    recent_procs = set(e.get("process_name", "") for e in recent_5sec)
    susp_count = sum(
        1 for name, stats in named_procs.items()
        if stats["risk_score"] >= SUSPICIOUS_THRESHOLD
        and name in recent_procs
    )

    active_alerts = []
    for a in alerts_list:
        dt = _parse_dt(a.get("timestamp", ""))
        if dt and (now - dt).total_seconds() < 60:
            active_alerts.append(a)

    # Malicious files still on disk — threat still active
    active_malicious = [
        s for s in scan_list
        if bool(s.get("malicious", False))
        and os.path.isfile(str(s.get("path", "")))
    ]

    if max_risk >= HIGH_RISK_THRESHOLD or active_alerts or active_malicious:
        status = "ransomware_detected"
    elif max_risk >= SUSPICIOUS_THRESHOLD or susp_count > 0:
        status = "suspicious"
    else:
        status = "safe"

    return {
        "status":                     status,
        "last_detection_time":        last_high,
        "total_events_24h":           len(recent_24h),
        "suspicious_processes_count": susp_count,
        "active_mass_alerts":         len(active_alerts),
    }
