import os
import sys
import time
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests

from backend.scanner.file_scanner import scan_file

API_BASE = "http://127.0.0.1:8000/api"

WATCH_PATHS = [
    r"C:\Users\Admin\Desktop",
    r"C:\Users\Admin\Documents",
    r"C:\Users\Admin\Downloads",
    r"C:\Users\Admin\Pictures",
]
WATCH_PATHS = [p for p in WATCH_PATHS if os.path.isdir(p)]
if not WATCH_PATHS:
    print("No valid WATCH_PATHS found, exiting.")
    sys.exit(1)

EXCLUDE_PREFIXES = []
desktop_root = r"C:\Users\Admin\Desktop"
if os.path.isdir(desktop_root):
    EXCLUDE_PREFIXES.extend([
        os.path.join(desktop_root, "Ransomware_Det"),
        os.path.join(desktop_root, ".venv"),
    ])

SUSPICIOUS_EXTS = {
    ".locked", ".enc", ".encrypted", ".crypt",
    ".cry", ".xxx", ".zepto", ".locky"
}

SKIP_SCAN_EXTS = {
    ".tmp", ".crdownload", ".part", ".partial",
    ".download", ".opdownload", ".!ut"
}

FINAL_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip",
    ".rar", ".exe", ".txt", ".csv",
     ".crdownload", ".tmp", ".part"
}

DEBOUNCE_SECONDS = 3
_timers:   dict = {}
_file_ops: dict = {}
MY_PID = os.getpid()
_proc_executor = ThreadPoolExecutor(max_workers=2)


def _is_excluded(path: str) -> bool:
    norm = os.path.normpath(path)
    return any(norm.startswith(os.path.normpath(p)) for p in EXCLUDE_PREFIXES)


def _find_process(path: str) -> str:
    try:
        import psutil
        norm_path = os.path.normpath(path)
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                if proc.info['pid'] == MY_PID:
                    continue
                proc_name = (proc.info['name'] or "").lower()
                if proc_name in ("python.exe", "python", "python3.exe"):
                    continue
                open_files = proc.info.get('open_files') or []
                for f in open_files:
                    if os.path.normpath(f.path) == norm_path:
                        return f"{proc.info['name']} (pid {proc.info['pid']})"
            except Exception:
                continue
    except Exception:
        pass
    return "unknown"


def _get_process_name(path: str) -> str:
    try:
        future = _proc_executor.submit(_find_process, path)
        return future.result(timeout=2.0)
    except FuturesTimeout:
        return "unknown"
    except Exception:
        return "unknown"


def compute_risk(path: str, event_type: str) -> float:
    _, ext = os.path.splitext(path.lower())
    score = 0.1
    # Ransomware extension = immediately high risk
    if ext in SUSPICIOUS_EXTS:
        return 0.9
    # Delete is always suspicious
    if event_type == "delete":
        score = max(score, 0.4)
    # Rename only suspicious if NOT a normal file extension
    # e.g. .pdf rename = Chrome download completing = normal
    if event_type == "rename" and ext not in FINAL_EXTS:
        score = max(score, 0.4)
    return score


def _pick_final_op(ops: list) -> str:
    if "delete" in ops:
        return "delete"
    if "rename" in ops:
        return "rename"
    if "create" in ops:
        return "create"
    return "modify"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _flush_file(path: str):
    try:
        ops = _file_ops.pop(path, [])
        _timers.pop(path, None)

        if not ops:
            return

        print(f"[flush] '{os.path.basename(path)}' ops={ops}")

        final_op      = _pick_final_op(ops)
        base_score    = compute_risk(path, final_op)
        content_score = 0.0
        scan_payload  = None

        file_exists = os.path.isfile(path)
        _, ext = os.path.splitext(path.lower())

        print(f"[debug] exists={file_exists} op={final_op} ext={ext}")

        process_name = _get_process_name(path)
        print(f"[proc] {process_name}")

        should_scan = (
            final_op in ("create", "modify", "rename")
            and file_exists
            and ext not in SKIP_SCAN_EXTS
        )

        if should_scan:
            try:
                scan_res      = scan_file(path)
                content_score = float(scan_res.get("score", 0.0))
                scan_payload  = {
                    "path":       path,
                    "exists":     True,
                    "score":      float(scan_res.get("score", 0.0)),
                    "entropy":    float(scan_res.get("entropy", 0.0)),
                    "malicious":  bool(scan_res.get("malicious", False)),
                    "reasons":    list(scan_res.get("reasons", [])),
                    "scanned_at": _now_iso(),
                    "trigger_op": final_op,
                }
                print(f"[scan] score={scan_payload['score']} "
                      f"entropy={scan_payload['entropy']:.2f} "
                      f"malicious={scan_payload['malicious']} "
                      f"reasons={scan_payload['reasons']}")
            except Exception as exc:
                print(f"[scan error] {exc}")
        else:
            print(f"[skip scan] ext={ext}")

        risk = round(max(base_score, content_score), 2)

        event_data = {
            "timestamp":    _now_iso(),
            "process_name": process_name,
            "pid":          0,
            "operation":    final_op,
            "path":         path,
            "risk_score":   risk,
        }

        print(f"[event] {final_op:8s} | risk={risk:.2f} | {os.path.basename(path)}")
        _post(f"{API_BASE}/events", event_data)

        if scan_payload:
            _post(f"{API_BASE}/scan-results", scan_payload)
            if scan_payload["malicious"]:
                print(f"  MALICIOUS score={scan_payload['score']} "
                      f"reasons={scan_payload['reasons']}")

    except Exception as e:
        import traceback
        print(f"[flush ERROR] {e}")
        traceback.print_exc()


def queue_event(path: str, op: str):
    if _is_excluded(path):
        return

    _, ext = os.path.splitext(path.lower())

    if op == "modify" and ext in SKIP_SCAN_EXTS:
        return

    if op == "modify" and ext in FINAL_EXTS:
        if "rename" in _file_ops.get(path, []):
            return

    print(f"[queue] op={op} path={os.path.basename(path)}")

    if path not in _file_ops:
        _file_ops[path] = []
    _file_ops[path].append(op)

    old_timer = _timers.get(path)
    if old_timer:
        old_timer.cancel()

    wait = 1.0 if (op == "rename" and ext in FINAL_EXTS) else DEBOUNCE_SECONDS

    t = threading.Timer(wait, _flush_file, args=[path])
    t.daemon = True
    t.start()
    _timers[path] = t


def _post(url: str, data: dict):
    try:
        r = requests.post(url, json=data, timeout=2.0)
        if r.status_code not in (200, 201):
            print(f"  [warn] POST {url} → {r.status_code} {r.text[:100]}")
    except Exception as e:
        print(f"  [send fail] {url}: {e}")


class MonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            queue_event(event.src_path, "create")

    def on_modified(self, event):
        if not event.is_directory:
            queue_event(event.src_path, "modify")

    def on_deleted(self, event):
        if not event.is_directory:
            queue_event(event.src_path, "delete")

    def on_moved(self, event):
        if not event.is_directory:
            queue_event(event.dest_path, "rename")


def run_monitor():
    observer = Observer()
    handler  = MonitorHandler()
    print("Starting monitor on:")
    for path in WATCH_PATHS:
        print(f"  {path}")
        observer.schedule(handler, path=path, recursive=True)
    observer.start()
    print("Monitoring started. Ctrl+C to stop.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    run_monitor()
