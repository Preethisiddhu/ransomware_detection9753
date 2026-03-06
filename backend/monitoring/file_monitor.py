import os
import sys
import time
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import requests

from backend.scanner.file_scanner import scan_file

API_BASE = "http://127.0.0.1:8000/api/events"

# Watch multiple important user folders
WATCH_PATHS = [
    r"C:\Users\Admin\Desktop",
    r"C:\Users\Admin\Documents",
    r"C:\Users\Admin\Downloads",
    r"C:\Users\Admin\Pictures",
]

# Keep only existing
WATCH_PATHS = [p for p in WATCH_PATHS if os.path.isdir(p)]
if not WATCH_PATHS:
    print("No valid WATCH_PATHS found, exiting.")
    sys.exit(1)

# Exclude project + venv under Desktop
EXCLUDE_PREFIXES = []
desktop_root = r"C:\Users\Admin\Desktop"
if os.path.isdir(desktop_root):
    EXCLUDE_PREFIXES.extend([
        os.path.join(desktop_root, "Ransomware_Det"),
        os.path.join(desktop_root, ".venv"),
    ])

SUSPICIOUS_EXTS = {".locked", ".enc", ".encrypted"}


def compute_risk(path: str, event_type: str) -> float:
    path_lower = path.lower()
    _, ext = os.path.splitext(path_lower)
    score = 0.1
    if ext in SUSPICIOUS_EXTS:
        score = 0.9
    if event_type in ("delete", "rename"):
        score = max(score, 0.4)
    return score


def send_event(path: str, event_type: str):
    norm_path = os.path.normpath(path)
    for prefix in EXCLUDE_PREFIXES:
        if norm_path.startswith(os.path.normpath(prefix)):
            print("skipping excluded path:", norm_path)
            return

    try:
        proc = psutil.Process()
        process_name = proc.name()
        pid = proc.pid
    except Exception:
        process_name = "unknown"
        pid = -1

    base_score = compute_risk(path, event_type)
    content_score = 0.0

    # For newly created files, also run content scanner
    if event_type == "create" and os.path.isfile(path):
        scan_res = scan_file(path)
        content_score = float(scan_res.get("score", 0.0))

    risk = max(base_score, content_score)

    data = {
        "timestamp": datetime.utcnow().isoformat(),
        "process_name": process_name,
        "pid": pid,
        "operation": event_type,  # create / modify / delete / rename
        "path": path,
        "risk_score": risk,
    }
    print("sending event:", data)
    try:
        r = requests.post(API_BASE, json=data, timeout=1.0)
        print("response status:", r.status_code)
    except Exception as e:
        print("send failed:", e)


class MonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        print("on_created:", event.src_path)
        send_event(event.src_path, "create")

    def on_modified(self, event):
        if event.is_directory:
            return
        print("on_modified:", event.src_path)
        send_event(event.src_path, "modify")

    def on_deleted(self, event):
        if event.is_directory:
            return
        print("on_deleted:", event.src_path)
        send_event(event.src_path, "delete")

    def on_moved(self, event):
        if event.is_directory:
            return
        print("on_moved:", event.src_path, "->", event.dest_path)
        send_event(event.dest_path, "rename")


def run_monitor():
    print("Starting monitor on:")
    observer = Observer()
    handler = MonitorHandler()

    for path in WATCH_PATHS:
        print("  ", path)
        observer.schedule(handler, path=path, recursive=True)

    observer.start()
    print("Monitoring started. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    run_monitor()