from .blocklist import BlockList
from .detector import XSSDetector, SQLiDetector
from .forensics import write_forensics
from .terminator import self_destruct as _self_destruct_fn


class VCDMiddleware:
    """Core VCD middleware: detect → preserve evidence → self-destruct.

    Blocking (refusing repeat requests from the same IP) is opt-in via block=True.
    """

    def __init__(
        self,
        app,
        detectors=None,
        self_destruct=False,
        forensics_path="/var/vcd/forensics.jsonl",
        block=False,
        blocklist_path="/var/vcd/blocklist.txt",
        on_detect=None,
    ):
        self.app = app
        self.detectors = detectors if detectors is not None else [XSSDetector(), SQLiDetector()]
        self._self_destruct = self_destruct
        self.forensics_path = forensics_path
        self._block = block
        self.blocklist = BlockList(blocklist_path) if block else None
        self.on_detect = on_detect

    def __call__(self, environ, start_response):
        from werkzeug.wrappers import Request
        request = Request(environ)

        if self._block and self._blocking_check(request):
            return self._forbidden(start_response)

        for detector in self.detectors:
            detected, reason = detector.detect(request)
            if detected:
                write_forensics(request, reason, self.forensics_path)
                if self._block:
                    self._blocking_register(request)
                if self.on_detect:
                    try:
                        self.on_detect(request, reason)
                    except Exception:
                        pass
                if self._self_destruct:
                    _self_destruct_fn()
                return self._forbidden(start_response)

        return self.app(environ, start_response)

    # --- blocking (optional feature) ---

    def _blocking_check(self, request) -> bool:
        return self.blocklist.is_blocked(self._get_ip(request))

    def _blocking_register(self, request):
        self.blocklist.block(self._get_ip(request))

    # --- helpers ---

    def _get_ip(self, request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote_addr or ""

    def _forbidden(self, start_response):
        start_response("403 Forbidden", [("Content-Type", "text/plain")])
        return [b"Forbidden"]
