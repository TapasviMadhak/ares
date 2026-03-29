"""
Tests for ARES Burp Suite Integration Module

Tests cover:
- BurpClient API communication
- ProxyManager functionality
- ScannerBridge coordination
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime

from ares_burp import BurpClient, BurpError, ProxyManager, ScannerBridge


class TestBurpClient:
    """Test BurpClient functionality"""
    
    @pytest.mark.asyncio
    async def test_init(self):
        """Test BurpClient initialization"""
        client = BurpClient(
            api_url="http://localhost:1337",
            api_key="test-key",
            timeout=60
        )
        
        assert client.api_url == "http://localhost:1337"
        assert client.api_key == "test-key"
        assert client.timeout == 60
    
    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager"""
        client = BurpClient()
        
        async with client as c:
            assert c.client is not None
            assert c.client.base_url == "http://127.0.0.1:1337"
    
    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Test health check with successful response"""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.json.return_value = {"version": "2023.1"}
            mock_response.raise_for_status = Mock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client
            
            client = BurpClient()
            async with client:
                result = await client.health_check()
                assert result is True
    
    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        """Test health check with failed response"""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(side_effect=Exception("Connection failed"))
            mock_client_class.return_value = mock_client
            
            client = BurpClient()
            async with client:
                result = await client.health_check()
                assert result is False
    
    @pytest.mark.asyncio
    async def test_start_scan(self):
        """Test starting a scan"""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.json.return_value = {"task_id": "scan-123"}
            mock_response.raise_for_status = Mock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client
            
            client = BurpClient()
            async with client:
                task_id = await client.start_scan("https://example.com")
                assert task_id == "scan-123"
    
    @pytest.mark.asyncio
    async def test_get_scan_status(self):
        """Test getting scan status"""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.json.return_value = {
                "status": "running",
                "progress": 50,
                "issues_found": 3
            }
            mock_response.raise_for_status = Mock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client
            
            client = BurpClient()
            async with client:
                status = await client.get_scan_status("scan-123")
                assert status["status"] == "running"
                assert status["progress"] == 50
                assert status["issues_found"] == 3
    
    @pytest.mark.asyncio
    async def test_get_scan_issues(self):
        """Test retrieving scan issues"""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.json.return_value = {
                "issues": [
                    {
                        "issue_type": "SQL Injection",
                        "severity": "high",
                        "url": "https://example.com/login"
                    }
                ]
            }
            mock_response.raise_for_status = Mock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client
            
            client = BurpClient()
            async with client:
                issues = await client.get_scan_issues(severity="high")
                assert len(issues) == 1
                assert issues[0]["issue_type"] == "SQL Injection"
    
    @pytest.mark.asyncio
    async def test_add_to_scope(self):
        """Test adding URL to scope"""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.json.return_value = {"success": True}
            mock_response.raise_for_status = Mock()
            mock_response.content = b'{"success": true}'
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client
            
            client = BurpClient()
            async with client:
                result = await client.add_to_scope("https://example.com")
                assert result is True
    
    @pytest.mark.asyncio
    async def test_request_without_context_manager(self):
        """Test making request without context manager raises error"""
        client = BurpClient()
        
        with pytest.raises(BurpError, match="Client not initialized"):
            await client._request('GET', '/test')


class TestProxyManager:
    """Test ProxyManager functionality"""
    
    def test_init(self):
        """Test ProxyManager initialization"""
        manager = ProxyManager(
            proxy_url="http://localhost:8080",
            verify_ssl=True
        )
        
        assert manager.proxy_url == "http://localhost:8080"
        assert manager.verify_ssl is True
        assert manager.session_cookies == {}
    
    def test_get_httpx_client(self):
        """Test creating httpx client with proxy settings"""
        manager = ProxyManager()
        client = manager.get_httpx_client(timeout=60)
        
        assert client is not None
        assert client.timeout.read == 60
    
    @pytest.mark.asyncio
    async def test_request_through_proxy(self):
        """Test making request through proxy"""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            
            manager = ProxyManager()
            response = await manager.request_through_proxy(
                "GET",
                "https://example.com"
            )
            
            assert response.status_code == 200
    
    def test_set_session_cookie(self):
        """Test setting session cookie"""
        manager = ProxyManager()
        manager.set_session_cookie("session_id", "abc123")
        
        assert manager.session_cookies["session_id"] == "abc123"
    
    def test_clear_session_cookies(self):
        """Test clearing session cookies"""
        manager = ProxyManager()
        manager.set_session_cookie("session_id", "abc123")
        manager.clear_session_cookies()
        
        assert manager.session_cookies == {}
    
    def test_get_session_cookies(self):
        """Test getting session cookies"""
        manager = ProxyManager()
        manager.set_session_cookie("session_id", "abc123")
        
        cookies = manager.get_session_cookies()
        assert cookies == {"session_id": "abc123"}
        
        # Verify it's a copy
        cookies["new_key"] = "value"
        assert "new_key" not in manager.session_cookies


class TestScannerBridge:
    """Test ScannerBridge functionality"""
    
    @pytest.mark.asyncio
    async def test_init(self):
        """Test ScannerBridge initialization"""
        mock_client = Mock(spec=BurpClient)
        bridge = ScannerBridge(mock_client, scan_id=123)
        
        assert bridge.burp_client == mock_client
        assert bridge.scan_id == 123
        assert bridge.burp_task_id is None
    
    @pytest.mark.asyncio
    async def test_start_coordinated_scan(self):
        """Test starting coordinated scan"""
        mock_client = AsyncMock(spec=BurpClient)
        mock_client.add_to_scope = AsyncMock(return_value=True)
        mock_client.start_spider = AsyncMock(return_value="spider-123")
        mock_client.start_scan = AsyncMock(return_value="scan-123")
        
        bridge = ScannerBridge(mock_client, scan_id=123)
        
        result = await bridge.start_coordinated_scan(
            "https://example.com",
            enable_burp_scanner=True,
            enable_burp_spider=True
        )
        
        assert result["target_url"] == "https://example.com"
        assert result["scan_id"] == 123
        assert result["burp_scanner_task_id"] == "scan-123"
        assert result["burp_spider_task_id"] == "spider-123"
        
        mock_client.add_to_scope.assert_called_once_with("https://example.com")
        mock_client.start_spider.assert_called_once()
        mock_client.start_scan.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_start_coordinated_scan_scanner_only(self):
        """Test starting scan with scanner only (no spider)"""
        mock_client = AsyncMock(spec=BurpClient)
        mock_client.add_to_scope = AsyncMock(return_value=True)
        mock_client.start_scan = AsyncMock(return_value="scan-123")
        
        bridge = ScannerBridge(mock_client, scan_id=123)
        
        result = await bridge.start_coordinated_scan(
            "https://example.com",
            enable_burp_scanner=True,
            enable_burp_spider=False
        )
        
        assert result["burp_scanner_task_id"] == "scan-123"
        assert result["burp_spider_task_id"] is None
    
    def test_map_burp_severity(self):
        """Test Burp severity mapping"""
        mock_client = Mock(spec=BurpClient)
        bridge = ScannerBridge(mock_client, scan_id=123)
        
        assert bridge._map_burp_severity("high") == "critical"
        assert bridge._map_burp_severity("medium") == "high"
        assert bridge._map_burp_severity("low") == "medium"
        assert bridge._map_burp_severity("information") == "low"
        assert bridge._map_burp_severity("unknown") == "info"
    
    @pytest.mark.asyncio
    async def test_get_scan_progress(self):
        """Test getting scan progress"""
        mock_client = AsyncMock(spec=BurpClient)
        mock_client.get_scan_status = AsyncMock(return_value={
            "status": "running",
            "progress": 75,
            "requests_made": 150,
            "issues_found": 5
        })
        
        bridge = ScannerBridge(mock_client, scan_id=123)
        bridge.burp_task_id = "scan-123"
        
        progress = await bridge.get_scan_progress()
        
        assert progress["burp_task_id"] == "scan-123"
        assert progress["status"] == "running"
        assert progress["progress"] == 75
        assert progress["issues_found"] == 5
    
    @pytest.mark.asyncio
    async def test_get_scan_progress_not_started(self):
        """Test getting scan progress when scan not started"""
        mock_client = Mock(spec=BurpClient)
        bridge = ScannerBridge(mock_client, scan_id=123)
        
        progress = await bridge.get_scan_progress()
        
        assert progress == {"status": "not_started"}
    
    @pytest.mark.asyncio
    async def test_stop_scan(self):
        """Test stopping scan"""
        mock_client = AsyncMock(spec=BurpClient)
        mock_client.stop_scan = AsyncMock(return_value=True)
        
        bridge = ScannerBridge(mock_client, scan_id=123)
        bridge.burp_task_id = "scan-123"
        
        await bridge.stop_scan()
        
        mock_client.stop_scan.assert_called_once_with("scan-123")
    
    @pytest.mark.asyncio
    async def test_export_sitemap_to_crawler(self):
        """Test exporting sitemap URLs"""
        mock_client = AsyncMock(spec=BurpClient)
        mock_client.get_sitemap = AsyncMock(return_value=[
            {"url": "https://example.com/page1"},
            {"url": "https://example.com/page2"},
            {"url": "https://example.com/api/endpoint"}
        ])
        
        bridge = ScannerBridge(mock_client, scan_id=123)
        
        urls = await bridge.export_sitemap_to_crawler()
        
        assert len(urls) == 3
        assert "https://example.com/page1" in urls
        assert "https://example.com/page2" in urls
        assert "https://example.com/api/endpoint" in urls


class TestBurpError:
    """Test BurpError exception"""
    
    def test_burp_error_creation(self):
        """Test creating BurpError exception"""
        error = BurpError("Test error message")
        assert str(error) == "Test error message"
    
    def test_burp_error_inheritance(self):
        """Test BurpError inherits from Exception"""
        error = BurpError("Test error")
        assert isinstance(error, Exception)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
