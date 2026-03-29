"""
Proxy Manager for Burp Suite Integration

Manages HTTP/HTTPS traffic routing through Burp proxy,
session handling, and request/response interception.
"""

from typing import Optional, Dict, Any, List
import httpx
from loguru import logger


class ProxyManager:
    """
    Manages HTTP traffic through Burp Suite proxy
    
    Features:
    - Automatic proxy configuration
    - SSL/TLS certificate handling
    - Session cookie management
    - Request/response interception
    """
    
    def __init__(
        self,
        proxy_url: str = "http://127.0.0.1:8080",
        verify_ssl: bool = False
    ):
        """
        Initialize proxy manager
        
        Args:
            proxy_url: Burp proxy URL
            verify_ssl: Whether to verify SSL certificates
        """
        self.proxy_url = proxy_url
        self.verify_ssl = verify_ssl
        self.session_cookies: Dict[str, str] = {}
        
        logger.info(f"Initialized ProxyManager with proxy: {proxy_url}")
    
    def get_httpx_client(
        self,
        timeout: int = 30,
        follow_redirects: bool = True
    ) -> httpx.AsyncClient:
        """
        Create httpx client configured to use Burp proxy
        
        Args:
            timeout: Request timeout in seconds
            follow_redirects: Whether to follow HTTP redirects
            
        Returns:
            Configured httpx AsyncClient
        """
        client = httpx.AsyncClient(
            proxy=self.proxy_url,
            verify=self.verify_ssl,
            timeout=timeout,
            follow_redirects=follow_redirects
        )
        
        logger.debug("Created httpx client with Burp proxy")
        return client
    
    async def request_through_proxy(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, str]] = None,
        include_session: bool = True
    ) -> httpx.Response:
        """
        Make HTTP request through Burp proxy
        
        Args:
            method: HTTP method
            url: Target URL
            headers: Request headers
            data: Form data
            json: JSON data
            params: URL parameters
            include_session: Include session cookies
            
        Returns:
            httpx Response object
        """
        async with self.get_httpx_client() as client:
            # Merge session cookies if requested
            if include_session and self.session_cookies:
                headers = headers or {}
                cookie_header = "; ".join(
                    f"{k}={v}" for k, v in self.session_cookies.items()
                )
                headers['Cookie'] = cookie_header
            
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                json=json,
                params=params
            )
            
            # Update session cookies from response
            if 'Set-Cookie' in response.headers:
                self._update_session_cookies(response.headers['Set-Cookie'])
            
            logger.debug(
                f"Proxied request: {method} {url} -> {response.status_code}"
            )
            return response
    
    def _update_session_cookies(self, cookie_header: str):
        """
        Parse and update session cookies from Set-Cookie header
        
        Args:
            cookie_header: Set-Cookie header value
        """
        # Simple cookie parsing (can be enhanced)
        for cookie in cookie_header.split(';'):
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                self.session_cookies[name.strip()] = value.strip()
    
    def set_session_cookie(self, name: str, value: str):
        """
        Manually set session cookie
        
        Args:
            name: Cookie name
            value: Cookie value
        """
        self.session_cookies[name] = value
        logger.debug(f"Set session cookie: {name}")
    
    def clear_session_cookies(self):
        """Clear all session cookies"""
        self.session_cookies.clear()
        logger.debug("Cleared session cookies")
    
    def get_session_cookies(self) -> Dict[str, str]:
        """
        Get current session cookies
        
        Returns:
            Dict of cookie name->value
        """
        return self.session_cookies.copy()
