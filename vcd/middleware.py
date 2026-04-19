from .blocklist import BlockList
from .detector import XSSDetector, SQLiDetector
from .forensics import write_forensics
from .terminator import self_destruct


class VCDMiddleware:
    def __init__(
        self,
        app,
        detectors=None,
        self_destruct=False,
        forensics_path="/var/vcd/forensics.jsonl",
        blocklist_path="/var/vcd/blocklist.txt",
        on_detect=None,
    ):
        self.app = app
        self.detectors = detectors if detectors is not None else [XSSDetector(), SQLiDetector()]
        self._self_destruct = self_destruct
        self.forensics_path = forensics_path
        self.blocklist = BlockList(blocklist_path)
        self.on_detect = on_detect

    def __call__(self, environ, start_response):
        from werkzeug.wrappers import Request
        request = Request(environ)

        client_ip = self._get_ip(request)

        if self.blocklist.is_blocked(client_ip):
            return self._blocked_response(environ, start_response)

        for detector in self.detectors:
            detected, reason = detector.detect(request)
            if detected:
                write_forensics(request, reason, self.forensics_path)
                self.blocklist.block(client_ip)
                if self.on_detect:
                    try:
                        self.on_detect(request, reason)
                    except Exception:
                        pass
                if self._self_destruct:
                    self_destruct()
                return self._blocked_response(environ, start_response)

        return self.app(environ, start_response)

    def _get_ip(self, request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote_addr or ""

    def _blocked_response(self, environ, start_response):
        start_response("403 Forbidden", [("Content-Type", "text/plain")])
        return [b"Forbidden"]
