import os
import tempfile
from unittest.mock import MagicMock, patch


def make_wsgi_app(status="200 OK", body=b"OK"):
    def app(environ, start_response):
        start_response(status, [("Content-Type", "text/plain")])
        return [body]
    return app


def make_middleware(tmpdir, self_destruct=False, block=False, detectors=None):
    from vcd.middleware import VCDMiddleware
    return VCDMiddleware(
        make_wsgi_app(),
        detectors=detectors,
        self_destruct=self_destruct,
        forensics_path=os.path.join(tmpdir, "forensics.jsonl"),
        block=block,
        blocklist_path=os.path.join(tmpdir, "blocklist.txt"),
    )


def call_middleware(middleware, path="/", query_string="", remote_addr="1.2.3.4", method="GET"):
    from werkzeug.test import EnvironBuilder
    builder = EnvironBuilder(path=path, query_string=query_string, method=method)
    environ = builder.get_environ()
    environ["REMOTE_ADDR"] = remote_addr
    start_response = MagicMock()
    result = middleware(environ, start_response)
    status = start_response.call_args[0][0]
    return status, b"".join(result)


class TestVCDMiddlewareCore:
    """コア機能: 検知 → 証拠保全 → 自壊"""

    def test_clean_request_passes_through(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mw = make_middleware(tmpdir)
            status, body = call_middleware(mw, query_string="q=hello")
            assert status == "200 OK"
            assert body == b"OK"

    def test_xss_returns_403(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mw = make_middleware(tmpdir)
            status, _ = call_middleware(mw, query_string="q=<script>alert(1)</script>")
            assert status == "403 Forbidden"

    def test_sqli_returns_403(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mw = make_middleware(tmpdir)
            status, _ = call_middleware(mw, query_string="id=1 UNION SELECT * FROM users")
            assert status == "403 Forbidden"

    def test_self_destruct_called_on_attack(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mw = make_middleware(tmpdir, self_destruct=True)
            with patch("vcd.middleware._self_destruct_fn") as mock_destruct:
                call_middleware(mw, query_string="q=<script>")
                mock_destruct.assert_called_once()

    def test_self_destruct_not_called_when_disabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mw = make_middleware(tmpdir, self_destruct=False)
            with patch("vcd.middleware._self_destruct_fn") as mock_destruct:
                call_middleware(mw, query_string="q=<script>")
                mock_destruct.assert_not_called()

    def test_on_detect_callback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            callback = MagicMock()
            from vcd.middleware import VCDMiddleware
            mw = VCDMiddleware(
                make_wsgi_app(),
                forensics_path=os.path.join(tmpdir, "f.jsonl"),
                on_detect=callback,
            )
            call_middleware(mw, query_string="q=<script>")
            callback.assert_called_once()

    def test_no_block_by_default_repeat_request_passes(self):
        """ブロック機能が無効なら、同一IPの再リクエストは通過する"""
        with tempfile.TemporaryDirectory() as tmpdir:
            mw = make_middleware(tmpdir, block=False)
            call_middleware(mw, query_string="q=<script>", remote_addr="9.9.9.9")
            status, _ = call_middleware(mw, query_string="q=hello", remote_addr="9.9.9.9")
            assert status == "200 OK"


class TestVCDMiddlewareBlocking:
    """オプション機能: IPブロック（block=True で有効化）"""

    def test_blocked_ip_returns_403(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mw = make_middleware(tmpdir, block=True)
            call_middleware(mw, query_string="q=<script>", remote_addr="9.9.9.9")
            status, _ = call_middleware(mw, query_string="q=hello", remote_addr="9.9.9.9")
            assert status == "403 Forbidden"

    def test_other_ip_not_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mw = make_middleware(tmpdir, block=True)
            call_middleware(mw, query_string="q=<script>", remote_addr="9.9.9.9")
            status, _ = call_middleware(mw, query_string="q=hello", remote_addr="1.2.3.4")
            assert status == "200 OK"
