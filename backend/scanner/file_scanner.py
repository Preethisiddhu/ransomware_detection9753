import os
import math
from typing import Dict, List

SUSPICIOUS_EXTS = {
    ".exe", ".dll", ".js", ".vbs", ".ps1", ".bat", ".cmd",
    ".scr", ".jar", ".hta", ".docm", ".xlsm", ".macro"
}

COMPRESSED_EXTS = {
    ".pdf", ".zip", ".rar", ".7z", ".gz", ".png", ".jpg",
    ".jpeg", ".mp3", ".mp4", ".docx", ".xlsx", ".pptx"
}

SUSPICIOUS_STRINGS = [
    "vssadmin delete shadows",
    "wbadmin delete catalog",
    "bcdedit /set",
    "cipher /w:",
    "powershell -enc",
    "cmd.exe /c",
    "schtasks /create",
    "userprofile%\\AppData\\Roaming",
    "tor.exe",
    "bitcoin",
    "wallet.dat",
]


def _file_entropy(path: str, max_bytes: int = 1024 * 1024) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
    except Exception:
        return 0.0
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = float(len(data))
    for c in counts:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def _scan_strings(path: str, max_bytes: int = 1024 * 1024) -> List[str]:
    hits: List[str] = []
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        text = data.decode("utf-8", errors="ignore").lower()
    except Exception:
        return hits
    for s in SUSPICIOUS_STRINGS:
        if s.lower() in text:
            hits.append(s)
    return hits


def scan_file(path: str) -> Dict[str, object]:
    result: Dict[str, object] = {
        "path":    path,
        "exists":  os.path.isfile(path),
        "score":   0.0,
        "reasons": [],
        "entropy": 0.0,
    }

    if not result["exists"]:
        result["reasons"].append("file_not_found")
        return result

    _, ext = os.path.splitext(path.lower())

    if ext in SUSPICIOUS_EXTS:
        result["score"] = max(result["score"], 0.4)
        result["reasons"].append(f"suspicious_extension:{ext}")

    ent = _file_entropy(path)
    result["entropy"] = ent

    if ext not in COMPRESSED_EXTS:
        if ent > 7.0:
            result["score"] = max(result["score"], 0.6)
            result["reasons"].append(f"high_entropy:{ent:.2f}")

    hits = _scan_strings(path)
    if hits:
        result["score"] = max(result["score"], 0.8)
        result["reasons"].append(f"suspicious_strings:{len(hits)}")

    result["score"]     = round(min(result["score"], 1.0), 2)
    result["malicious"] = result["score"] >= 0.7

    return result
