import json
import os
import threading
from datetime import datetime, timezone

_lock = threading.Lock()


def write_forensics(request, reason: str, path: str):
    evidence = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "ip": _get_client_ip(request),
        "method": request.method,
        "path": request.path,
        "payload": _get_payload(request),
        "headers": dict(request.headers),
    }
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with _lock:
        with open(path, "a") as f:
            f.write(json.dumps(evidence) + "\n")


def _get_client_ip(request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or ""


def _get_payload(request) -> dict:
    payload = {}
    if request.args:
        payload["query_string"] = dict(request.args)
    if request.form:
        payload["form"] = dict(request.form)
    try:
        body = request.get_data(as_text=True)
        if body:
            payload["body"] = body[:4096]
    except Exception:
        pass
    return payload
