"""
ARES Burp Suite Integration Module
Provides REST API client for Burp Suite Pro/Community
"""

from .burp_client import BurpClient, BurpError
from .proxy_manager import ProxyManager
from .scanner_bridge import ScannerBridge

__all__ = ['BurpClient', 'BurpError', 'ProxyManager', 'ScannerBridge']

__version__ = '1.0.0'
