"""
Hexstrike-AI MCP Client

Async client for communicating with the Hexstrike-AI MCP server.
Provides methods to discover, execute, and manage security tools.

Features:
- Async HTTP communication using httpx
- Automatic retry logic with exponential backoff
- Connection pooling for performance
- Comprehensive error handling
- Response validation and type safety
"""

import asyncio
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import httpx
from loguru import logger

from ares_core.config import settings


class HexstrikeClientError(Exception):
    """Base exception for Hexstrike client errors"""
    pass


class ToolExecutionError(HexstrikeClientError):
    """Raised when a tool execution fails"""
    pass


class ConnectionError(HexstrikeClientError):
    """Raised when unable to connect to MCP server"""
    pass


class HexstrikeClient:
    """
    Async client for Hexstrike-AI MCP server.
    
    This client communicates with the Hexstrike-AI Flask API server
    that hosts 150+ security testing tools.
    
    Usage:
        async with HexstrikeClient() as client:
            tools = await client.list_tools()
            result = await client.execute_tool("nmap_scan", {"target": "10.0.0.1"})
    """
    
    def __init__(
        self,
        server_url: str = "http://127.0.0.1:8888",
        timeout: int = 300,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        """
        Initialize Hexstrike client.
        
        Args:
            server_url: Base URL of Hexstrike API server
            timeout: Request timeout in seconds (default: 300s for long-running tools)
            max_retries: Maximum number of retry attempts
            retry_delay: Initial delay between retries (exponential backoff)
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        # HTTP client with connection pooling
        self._client: Optional[httpx.AsyncClient] = None
        self._tools_cache: Optional[List[Dict[str, Any]]] = None
        self._cache_timestamp: Optional[datetime] = None
        self._cache_ttl = timedelta(minutes=30)
        
        logger.info(
            f"Initialized HexstrikeClient: server={server_url}, "
            f"timeout={timeout}s, retries={max_retries}"
        )
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._ensure_client()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
    
    async def _ensure_client(self):
        """Ensure HTTP client is initialized"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
                follow_redirects=True,
            )
    
    async def close(self):
        """Close HTTP client and cleanup resources"""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.debug("HexstrikeClient closed")
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        retry_count: int = 0,
    ) -> Dict[str, Any]:
        """
        Make HTTP request with retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            json_data: JSON payload for request body
            params: Query parameters
            retry_count: Current retry attempt
            
        Returns:
            Response JSON data
            
        Raises:
            ConnectionError: If unable to connect after retries
            ToolExecutionError: If tool execution fails
        """
        await self._ensure_client()
        
        url = f"{self.server_url}/{endpoint.lstrip('/')}"
        
        try:
            logger.debug(f"Request: {method} {url} (attempt {retry_count + 1}/{self.max_retries + 1})")
            
            response = await self._client.request(
                method=method,
                url=url,
                json=json_data,
                params=params,
            )
            
            # Log response status
            logger.debug(f"Response: {response.status_code} from {endpoint}")
            
            # Handle different status codes
            if response.status_code == 200:
                data = response.json()
                return data
            
            elif response.status_code == 404:
                raise ToolExecutionError(f"Endpoint not found: {endpoint}")
            
            elif response.status_code == 500:
                error_msg = response.text
                logger.error(f"Server error on {endpoint}: {error_msg}")
                raise ToolExecutionError(f"Server error: {error_msg}")
            
            else:
                response.raise_for_status()
                return response.json()
        
        except httpx.TimeoutException:
            logger.warning(f"Request timeout for {endpoint} (attempt {retry_count + 1})")
            if retry_count < self.max_retries:
                delay = self.retry_delay * (2 ** retry_count)
                logger.info(f"Retrying in {delay}s...")
                await asyncio.sleep(delay)
                return await self._request(method, endpoint, json_data, params, retry_count + 1)
            raise ConnectionError(f"Request timed out after {self.max_retries} retries")
        
        except httpx.ConnectError as e:
            logger.error(f"Connection error to {url}: {e}")
            if retry_count < self.max_retries:
                delay = self.retry_delay * (2 ** retry_count)
                logger.info(f"Retrying in {delay}s...")
                await asyncio.sleep(delay)
                return await self._request(method, endpoint, json_data, params, retry_count + 1)
            raise ConnectionError(f"Unable to connect to Hexstrike server at {self.server_url}")
        
        except Exception as e:
            logger.error(f"Unexpected error during request to {endpoint}: {e}")
            raise HexstrikeClientError(f"Request failed: {e}")
    
    async def health_check(self) -> bool:
        """
        Check if Hexstrike server is healthy and reachable.
        
        Returns:
            True if server is healthy, False otherwise
        """
        try:
            response = await self._request("GET", "/health")
            return response.get("status") == "ok"
        except Exception as e:
            logger.warning(f"Health check failed: {e}")
            return False
    
    async def list_tools(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Get list of available tools from Hexstrike server.
        
        Uses caching to avoid repeated requests. Cache is valid for 30 minutes.
        
        Args:
            force_refresh: Force refresh cache even if valid
            
        Returns:
            List of tool definitions with metadata:
            [
                {
                    "name": "nmap_scan",
                    "category": "network_scanning",
                    "description": "Network scanning with Nmap",
                    "parameters": {...},
                    "timeout": 300
                },
                ...
            ]
        """
        # Check cache validity
        now = datetime.now()
        cache_valid = (
            self._tools_cache is not None
            and self._cache_timestamp is not None
            and (now - self._cache_timestamp) < self._cache_ttl
        )
        
        if cache_valid and not force_refresh:
            logger.debug("Returning cached tools list")
            return self._tools_cache
        
        logger.info("Fetching tools list from Hexstrike server")
        
        try:
            response = await self._request("GET", "/api/tools/list")
            
            if "tools" in response:
                tools = response["tools"]
                self._tools_cache = tools
                self._cache_timestamp = now
                logger.info(f"Retrieved {len(tools)} tools from server")
                return tools
            else:
                logger.warning("Unexpected response format from /api/tools/list")
                return []
        
        except Exception as e:
            logger.error(f"Failed to fetch tools list: {e}")
            # Return cached data if available, even if expired
            if self._tools_cache:
                logger.info("Returning expired cache due to fetch error")
                return self._tools_cache
            return []
    
    async def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific tool.
        
        Args:
            tool_name: Name of the tool (e.g., "nmap_scan")
            
        Returns:
            Tool metadata or None if not found
        """
        tools = await self.list_tools()
        for tool in tools:
            if tool.get("name") == tool_name:
                return tool
        
        logger.warning(f"Tool not found: {tool_name}")
        return None
    
    async def execute_tool(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        timeout_override: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute a security tool on the Hexstrike server.
        
        Args:
            tool_name: Name of the tool to execute
            parameters: Tool-specific parameters
            timeout_override: Override default timeout for this execution
            
        Returns:
            Tool execution result:
            {
                "success": bool,
                "output": str,
                "error": Optional[str],
                "execution_time": float,
                "metadata": {...}
            }
            
        Raises:
            ToolExecutionError: If tool execution fails
        """
        logger.info(f"Executing tool: {tool_name} with params: {parameters}")
        
        # Get tool info to determine endpoint
        tool_info = await self.get_tool_info(tool_name)
        if not tool_info:
            raise ToolExecutionError(f"Unknown tool: {tool_name}")
        
        # Prepare request
        endpoint = tool_info.get("endpoint", f"/api/tools/{tool_name}")
        
        # Temporarily adjust timeout if override specified
        original_timeout = None
        if timeout_override:
            original_timeout = self.timeout
            if self._client:
                self._client.timeout = httpx.Timeout(timeout_override)
        
        try:
            start_time = datetime.now()
            
            response = await self._request("POST", endpoint, json_data=parameters)
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Normalize response format
            result = {
                "success": response.get("success", True),
                "output": response.get("output", response.get("result", "")),
                "error": response.get("error"),
                "execution_time": execution_time,
                "tool_name": tool_name,
                "parameters": parameters,
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "server": self.server_url,
                }
            }
            
            if result["success"]:
                logger.success(f"Tool {tool_name} completed in {execution_time:.2f}s")
            else:
                logger.warning(f"Tool {tool_name} failed: {result['error']}")
            
            return result
        
        except Exception as e:
            logger.error(f"Tool execution failed for {tool_name}: {e}")
            raise ToolExecutionError(f"Failed to execute {tool_name}: {e}")
        
        finally:
            # Restore original timeout
            if original_timeout and self._client:
                self._client.timeout = httpx.Timeout(original_timeout)
    
    async def execute_tools_batch(
        self,
        tool_requests: List[Tuple[str, Dict[str, Any]]],
        max_concurrent: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Execute multiple tools concurrently with rate limiting.
        
        Args:
            tool_requests: List of (tool_name, parameters) tuples
            max_concurrent: Maximum number of concurrent executions
            
        Returns:
            List of execution results in same order as requests
        """
        logger.info(f"Batch executing {len(tool_requests)} tools (max_concurrent={max_concurrent})")
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def execute_with_semaphore(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
            async with semaphore:
                try:
                    return await self.execute_tool(tool_name, params)
                except Exception as e:
                    logger.error(f"Batch execution failed for {tool_name}: {e}")
                    return {
                        "success": False,
                        "output": "",
                        "error": str(e),
                        "execution_time": 0.0,
                        "tool_name": tool_name,
                        "parameters": params,
                    }
        
        tasks = [
            execute_with_semaphore(tool_name, params)
            for tool_name, params in tool_requests
        ]
        
        results = await asyncio.gather(*tasks)
        
        success_count = sum(1 for r in results if r["success"])
        logger.info(f"Batch execution complete: {success_count}/{len(results)} successful")
        
        return results
    
    async def get_tool_categories(self) -> Dict[str, List[str]]:
        """
        Get tools organized by category.
        
        Returns:
            Dictionary mapping category name to list of tool names
        """
        tools = await self.list_tools()
        
        categories: Dict[str, List[str]] = {}
        for tool in tools:
            category = tool.get("category", "uncategorized")
            if category not in categories:
                categories[category] = []
            categories[category].append(tool["name"])
        
        return categories
    
    async def search_tools(
        self,
        query: str,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search for tools by name, description, or category.
        
        Args:
            query: Search query string
            category: Filter by category (optional)
            
        Returns:
            List of matching tools
        """
        tools = await self.list_tools()
        
        query_lower = query.lower()
        results = []
        
        for tool in tools:
            # Filter by category if specified
            if category and tool.get("category") != category:
                continue
            
            # Search in name and description
            name_match = query_lower in tool.get("name", "").lower()
            desc_match = query_lower in tool.get("description", "").lower()
            
            if name_match or desc_match:
                results.append(tool)
        
        logger.debug(f"Search '{query}' found {len(results)} tools")
        return results


# Singleton instance for convenience
_hexstrike_client: Optional[HexstrikeClient] = None


async def get_hexstrike_client() -> HexstrikeClient:
    """
    Get singleton instance of HexstrikeClient.
    
    Returns:
        Initialized HexstrikeClient instance
    """
    global _hexstrike_client
    
    if _hexstrike_client is None:
        _hexstrike_client = HexstrikeClient(
            server_url=getattr(settings, "hexstrike_url", "http://127.0.0.1:8888"),
            timeout=getattr(settings, "hexstrike_timeout", 300),
        )
        await _hexstrike_client._ensure_client()
    
    return _hexstrike_client
