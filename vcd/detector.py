import re


class BaseDetector:
    def detect(self, request) -> tuple[bool, str]:
        """Return (detected, reason)."""
        raise NotImplementedError


class XSSDetector(BaseDetector):
    _PATTERNS = re.compile(
        r"<script|javascript:|on\w+=|alert\s*\(|<iframe|<img[^>]+src\s*=",
        re.IGNORECASE,
    )

    def detect(self, request) -> tuple[bool, str]:
        target = _collect_text(request)
        if self._PATTERNS.search(target):
            return True, "XSS pattern detected"
        return False, ""


class SQLiDetector(BaseDetector):
    _PATTERNS = re.compile(
        r"(\bOR\b|\bAND\b)\s+[\w'\"]+\s*=\s*[\w'\"]+|--|;.*--|\bUNION\b.*\bSELECT\b"
        r"|\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b.*\bSET\b|' *OR *'",
        re.IGNORECASE,
    )

    def detect(self, request) -> tuple[bool, str]:
        target = _collect_text(request)
        if self._PATTERNS.search(target):
            return True, "SQLi pattern detected"
        return False, ""


def _collect_text(request) -> str:
    parts = []
    if request.args:
        parts.append(" ".join(str(v) for v in request.args.values()))
    if request.form:
        parts.append(" ".join(str(v) for v in request.form.values()))
    try:
        body = request.get_data(as_text=True)
        if body:
            parts.append(body[:4096])
    except Exception:
        pass
    return " ".join(parts)
