import os
import threading


class BlockList:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self.blocked_ips = self._load()

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def block(self, ip: str):
        with self._lock:
            if ip not in self.blocked_ips:
                self.blocked_ips.add(ip)
                self._append(ip)

    def _load(self) -> set:
        if not os.path.exists(self.path):
            return set()
        with open(self.path, "r") as f:
            return {line.strip() for line in f if line.strip()}

    def _append(self, ip: str):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "a") as f:
            f.write(ip + "\n")
