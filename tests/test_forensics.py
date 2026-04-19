import json
import os
import tempfile
from unittest.mock import MagicMock
from vcd.forensics import write_forensics


def make_request(ip="1.2.3.4", method="GET", path="/", args=None, form=None, body=""):
    req = MagicMock()
    req.headers = {"User-Agent": "test"}
    req.remote_addr = ip
    req.method = method
    req.path = path
    req.args = args or {}
    req.form = form or {}
    req.get_data = MagicMock(return_value=body)
    return req


def test_write_forensics_creates_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "forensics.jsonl")
        req = make_request(ip="10.0.0.1", path="/search", args={"q": "<script>"})
        write_forensics(req, "XSS pattern detected", path)
        assert os.path.exists(path)
        with open(path) as f:
            entry = json.loads(f.readline())
        assert entry["ip"] == "10.0.0.1"
        assert entry["reason"] == "XSS pattern detected"
        assert "timestamp" in entry


def test_write_forensics_appends():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "forensics.jsonl")
        req = make_request()
        write_forensics(req, "reason1", path)
        write_forensics(req, "reason2", path)
        with open(path) as f:
            lines = f.readlines()
        assert len(lines) == 2


def test_write_forensics_x_forwarded_for():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "forensics.jsonl")
        req = make_request()
        req.headers = {"X-Forwarded-For": "5.6.7.8, 9.10.11.12", "User-Agent": "test"}
        write_forensics(req, "test", path)
        with open(path) as f:
            entry = json.loads(f.readline())
        assert entry["ip"] == "5.6.7.8"
