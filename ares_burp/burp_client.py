"""
Burp Suite REST API Client

Handles communication with Burp Suite Pro/Community Edition via REST API.
Supports scanning, spidering, proxy management, and session handling.
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
import httpx
from loguru import logger


class BurpError(Exception):
    """Base exception for Burp Suite errors"""
    pass


class BurpClient:
    """
    Async client for Burp Suite REST API
    
    Supports:
    - Active/passive scanning
    - Spider/crawler
    - Proxy history
    - Site map
    - Issue retrieval
    - Session management
    """
    
    def __init__(
        self,
        api_url: str = "http://127.0.0.1:1337",
        api_key: Optional[str] = None,
        timeout: int = 30
    ):
        """
        Initialize Burp API client
        
        Args:
            api_url: Burp REST API base URL
            api_key: API key for authentication (if required)
            timeout: Request timeout in seconds
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.client: Optional[httpx.AsyncClient] = None
        
        logger.info(f"Initialized Burp client for {self.api_url}")
    
    async def __aenter__(self):
        """Async context manager entry"""
        headers = {}
        if self.api_key:
            headers['X-API-Key'] = self.api_key
        
        self.client = httpx.AsyncClient(
            base_url=self.api_url,
            headers=headers,
            timeout=self.timeout
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.client:
            await self.client.aclose()
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Make HTTP request to Burp API
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            **kwargs: Additional request parameters
            
        Returns:
            JSON response as dict
            
        Raises:
            BurpError: If request fails
        """
        if not self.client:
            raise BurpError("Client not initialized. Use 'async with' context manager")
        
        try:
            response = await self.client.request(method, endpoint, **kwargs)
            response.raise_for_status()
            
            # Handle empty responses
            if not response.content:
                return {"success": True}
            
            return response.json()
            
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error from Burp: {e.response.status_code}")
            raise BurpError(f"HTTP {e.response.status_code}: {e.response.text}")
        except httpx.RequestError as e:
            logger.error(f"Connection error to Burp: {e}")
            raise BurpError(f"Failed to connect to Burp API: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise BurpError(f"Unexpected error: {e}")
    
    # ============================================================================
    # Health & Status
    # ============================================================================
    
    async def health_check(self) -> bool:
        """
        Check if Burp API is available
        
        Returns:
            True if Burp is responding, False otherwise
        """
        try:
            await self._request('GET', '/burp/versions')
            logger.info("Burp API health check: OK")
            return True
        except BurpError:
            logger.warning("Burp API health check: FAILED")
            return False
    
    async def get_version(self) -> Dict[str, str]:
        """
        Get Burp Suite version information
        
        Returns:
            Version info dict
        """
        return await self._request('GET', '/burp/versions')
    
    # ============================================================================
    # Scanning
    # ============================================================================
    
    async def start_scan(
        self,
        base_url: str,
        scan_configurations: Optional[List[str]] = None
    ) -> str:
        """
        Start active scan on target
        
        Args:
            base_url: Target URL to scan
            scan_configurations: List of scan config names (default: all)
            
        Returns:
            Task ID for tracking scan progress
        """
        payload = {
            "base_url": base_url
        }
        if scan_configurations:
            payload["scan_configurations"] = scan_configurations
        
        response = await self._request('POST', '/scanner/scans', json=payload)
        task_id = response.get('task_id')
        
        logger.info(f"Started Burp scan for {base_url}, task_id: {task_id}")
        return task_id
    
    async def get_scan_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get status of running scan
        
        Args:
            task_id: Scan task ID
            
        Returns:
            Scan status dict with progress and issue count
        """
        return await self._request('GET', f'/scanner/scans/{task_id}')
    
    async def get_scan_issues(
        self,
        task_id: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get issues found by scanner
        
        Args:
            task_id: Specific scan task (optional)
            severity: Filter by severity (high, medium, low, info)
            
        Returns:
            List of issue dicts
        """
        params = {}
        if task_id:
            params['task_id'] = task_id
        if severity:
            params['severity'] = severity
        
        response = await self._request('GET', '/scanner/issues', params=params)
        return response.get('issues', [])
    
    async def stop_scan(self, task_id: str) -> bool:
        """
        Stop running scan
        
        Args:
            task_id: Scan task ID
            
        Returns:
            True if stopped successfully
        """
        await self._request('DELETE', f'/scanner/scans/{task_id}')
        logger.info(f"Stopped Burp scan: {task_id}")
        return True
    
    # ============================================================================
    # Spider/Crawler
    # ============================================================================
    
    async def start_spider(
        self,
        base_url: str,
        max_depth: int = 10
    ) -> str:
        """
        Start spider/crawler on target
        
        Args:
            base_url: Target URL to crawl
            max_depth: Maximum crawl depth
            
        Returns:
            Task ID for tracking spider progress
        """
        payload = {
            "base_url": base_url,
            "max_depth": max_depth
        }
        
        response = await self._request('POST', '/spider/scans', json=payload)
        task_id = response.get('task_id')
        
        logger.info(f"Started Burp spider for {base_url}, task_id: {task_id}")
        return task_id
    
    async def get_spider_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get spider progress
        
        Args:
            task_id: Spider task ID
            
        Returns:
            Status dict with URLs found
        """
        return await self._request('GET', f'/spider/scans/{task_id}')
    
    # ============================================================================
    # Site Map
    # ============================================================================
    
    async def get_sitemap(
        self,
        url_prefix: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get site map (discovered URLs)
        
        Args:
            url_prefix: Filter by URL prefix
            
        Returns:
            List of URL entries with methods, status codes
        """
        params = {}
        if url_prefix:
            params['url_prefix'] = url_prefix
        
        response = await self._request('GET', '/target/sitemap', params=params)
        return response.get('entries', [])
    
    async def get_scope(self) -> List[str]:
        """
        Get current target scope
        
        Returns:
            List of URLs in scope
        """
        response = await self._request('GET', '/target/scope')
        return response.get('scope', [])
    
    async def add_to_scope(self, url: str) -> bool:
        """
        Add URL to target scope
        
        Args:
            url: URL to add to scope
            
        Returns:
            True if added successfully
        """
        payload = {"url": url}
        await self._request('POST', '/target/scope', json=payload)
        logger.info(f"Added to Burp scope: {url}")
        return True
    
    async def remove_from_scope(self, url: str) -> bool:
        """
        Remove URL from target scope
        
        Args:
            url: URL to remove from scope
            
        Returns:
            True if removed successfully
        """
        payload = {"url": url}
        await self._request('DELETE', '/target/scope', json=payload)
        logger.info(f"Removed from Burp scope: {url}")
        return True
    
    # ============================================================================
    # Proxy History
    # ============================================================================
    
    async def get_proxy_history(
        self,
        url_filter: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get proxy history (intercepted requests)
        
        Args:
            url_filter: Filter by URL pattern
            limit: Maximum number of entries
            
        Returns:
            List of request/response pairs
        """
        params = {"limit": limit}
        if url_filter:
            params['url_filter'] = url_filter
        
        response = await self._request('GET', '/proxy/history', params=params)
        return response.get('entries', [])
    
    async def send_to_repeater(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None
    ) -> str:
        """
        Send request to Burp Repeater
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Request headers
            body: Request body
            
        Returns:
            Repeater tab ID
        """
        payload = {
            "url": url,
            "method": method,
            "headers": headers or {},
            "body": body or ""
        }
        
        response = await self._request('POST', '/repeater/requests', json=payload)
        tab_id = response.get('tab_id')
        
        logger.info(f"Sent to Burp Repeater: {url}")
        return tab_id
    
    # ============================================================================
    # Intruder
    # ============================================================================
    
    async def send_to_intruder(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        payload_positions: Optional[List[str]] = None
    ) -> str:
        """
        Send request to Burp Intruder
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Request headers
            body: Request body
            payload_positions: List of parameter names to fuzz
            
        Returns:
            Intruder attack ID
        """
        payload = {
            "url": url,
            "method": method,
            "headers": headers or {},
            "body": body or "",
            "payload_positions": payload_positions or []
        }
        
        response = await self._request('POST', '/intruder/attacks', json=payload)
        attack_id = response.get('attack_id')
        
        logger.info(f"Sent to Burp Intruder: {url}")
        return attack_id
    
    # ============================================================================
    # Configuration
    # ============================================================================
    
    async def get_config(self) -> Dict[str, Any]:
        """
        Get current Burp configuration
        
        Returns:
            Configuration dict
        """
        return await self._request('GET', '/burp/configuration')
    
    async def update_config(self, config: Dict[str, Any]) -> bool:
        """
        Update Burp configuration
        
        Args:
            config: Configuration dict
            
        Returns:
            True if updated successfully
        """
        await self._request('PUT', '/burp/configuration', json=config)
        logger.info("Updated Burp configuration")
        return True
