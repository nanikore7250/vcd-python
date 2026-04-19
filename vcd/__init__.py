from .middleware import VCDMiddleware
from .detector import BaseDetector, XSSDetector, SQLiDetector
from .blocklist import BlockList
from .forensics import write_forensics
from .terminator import self_destruct

__version__ = "0.1.0"
__all__ = [
    "VCDMiddleware",
    "BaseDetector",
    "XSSDetector",
    "SQLiDetector",
    "BlockList",
    "write_forensics",
    "self_destruct",
]
