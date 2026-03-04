import requests
from datetime import datetime, timedelta

API = "http://127.0.0.1:8000/api/events"

now = datetime.utcnow()

events = [
    {
        "timestamp": (now - timedelta(seconds=10)).isoformat(),
        "process_name": "explorer.exe",
        "pid": 1234,
        "operation": "create",
        "path": r"C:\Users\Admin\Documents\report.docx",
        "risk_score": 0.1,
    },
    {
        "timestamp": (now - timedelta(seconds=5)).isoformat(),
        "process_name": "ransom_sim.exe",
        "pid": 5678,
        "operation": "modify",
        "path": r"C:\Users\Admin\Documents\file1.locked",
        "risk_score": 0.95,
    },
    {
        "timestamp": (now - timedelta(seconds=3)).isoformat(),
        "process_name": "ransom_sim.exe",
        "pid": 5678,
        "operation": "rename",
        "path": r"C:\Users\Admin\Documents\file2.locked",
        "risk_score": 0.9,
    },
]

for ev in events:
    r = requests.post(API, json=ev)
    print(r.status_code, r.text)