"""
ARES Scanner Module
Web application vulnerability scanner
"""

__version__ = "0.2.0"

from .crawler import WebCrawler, CrawledEndpoint
from .sqli_detector import SQLiDetector, SQLiResult
from .xss_detector import XSSDetector, XSSResult
from .csrf_detector import CSRFDetector, CSRFResult
from .ssrf_detector import SSRFDetector, SSRFResult
from .xxe_detector import XXEDetector, XXEResult
from .deserialization_detector import DeserializationDetector, DeserializationResult
from .auth_detector import AuthDetector, AuthResult

__all__ = [
    'WebCrawler',
    'CrawledEndpoint',
    'SQLiDetector',
    'SQLiResult',
    'XSSDetector',
    'XSSResult',
    'CSRFDetector',
    'CSRFResult',
    'SSRFDetector',
    'SSRFResult',
    'XXEDetector',
    'XXEResult',
    'DeserializationDetector',
    'DeserializationResult',
    'AuthDetector',
    'AuthResult',
]
