import pytest
from unittest.mock import MagicMock
from vcd.detector import XSSDetector, SQLiDetector


def make_request(qs=None, form=None, body=b""):
    req = MagicMock()
    req.args = qs or {}
    req.form = form or {}
    req.get_data = MagicMock(return_value=body.decode() if isinstance(body, bytes) else body)
    return req


class TestXSSDetector:
    def setup_method(self):
        self.detector = XSSDetector()

    def test_detects_script_tag(self):
        req = make_request(qs={"q": "<script>alert(1)</script>"})
        detected, reason = self.detector.detect(req)
        assert detected
        assert "XSS" in reason

    def test_detects_onerror(self):
        req = make_request(body=b'<img onerror=alert(1)>')
        detected, _ = self.detector.detect(req)
        assert detected

    def test_clean_request(self):
        req = make_request(qs={"q": "hello world"})
        detected, _ = self.detector.detect(req)
        assert not detected


class TestSQLiDetector:
    def setup_method(self):
        self.detector = SQLiDetector()

    def test_detects_union_select(self):
        req = make_request(qs={"id": "1 UNION SELECT * FROM users"})
        detected, reason = self.detector.detect(req)
        assert detected
        assert "SQLi" in reason

    def test_detects_comment(self):
        req = make_request(body=b"admin'--")
        detected, _ = self.detector.detect(req)
        assert detected

    def test_clean_request(self):
        req = make_request(qs={"name": "John"})
        detected, _ = self.detector.detect(req)
        assert not detected
