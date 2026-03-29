"""
Cross-Site Scripting (XSS) Detector for ARES
Detects XSS vulnerabilities (Reflected, Stored, DOM-based)
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
import re
import asyncio
import httpx
from loguru import logger
from urllib.parse import urljoin


@dataclass
class XSSPayload:
    """XSS test payload"""
    payload: str
    context: str  # html, attribute, javascript, etc.
    detection_pattern: str
    

@dataclass
class XSSResult:
    """Result of XSS test"""
    is_vulnerable: bool
    confidence: float
    xss_type: str  # reflected, stored, dom-based
    payload_used: str
    context: str
    evidence: str
    url: str
    parameter: str


class XSSDetector:
    """Cross-Site Scripting vulnerability detector"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        
        # Unique marker for detection
        self.marker = "ARES_XSS_TEST_123456"
    
    def get_payloads(self) -> List[XSSPayload]:
        """Get XSS test payloads"""
        return [
            # Basic payloads
            XSSPayload(
                f"<script>alert('{self.marker}')</script>",
                "html",
                f"<script>alert\\(['\\\"]?{self.marker}['\\\"]?\\)</script>"
            ),
            XSSPayload(
                f"<img src=x onerror=alert('{self.marker}')>",
                "html",
                f"<img[^>]+onerror[^>]*{self.marker}"
            ),
            XSSPayload(
                f"<svg/onload=alert('{self.marker}')>",
                "html",
                f"<svg[^>]+onload[^>]*{self.marker}"
            ),
            
            # Attribute context
            XSSPayload(
                f"\" onclick=alert('{self.marker}') \"",
                "attribute",
                f"onclick[^>]*{self.marker}"
            ),
            XSSPayload(
                f"' onclick=alert('{self.marker}') '",
                "attribute",
                f"onclick[^>]*{self.marker}"
            ),
            
            # JavaScript context
            XSSPayload(
                f"';alert('{self.marker}');//",
                "javascript",
                f"alert\\(['\\\"]?{self.marker}['\\\"]?\\)"
            ),
            XSSPayload(
                f"\";alert('{self.marker}');//",
                "javascript",
                f"alert\\(['\\\"]?{self.marker}['\\\"]?\\)"
            ),
            
            # Encoded payloads
            XSSPayload(
                f"<img src=x onerror=&#97;lert('{self.marker}')>",
                "html_encoded",
                f"onerror[^>]*{self.marker}"
            ),
            
            # Event handlers
            XSSPayload(
                f"<body onload=alert('{self.marker}')>",
                "html",
                f"onload[^>]*{self.marker}"
            ),
            XSSPayload(
                f"<input onfocus=alert('{self.marker}') autofocus>",
                "html",
                f"onfocus[^>]*{self.marker}"
            ),
            
            # Template injection style
            XSSPayload(
                f"${{alert('{self.marker}')}}",
                "template",
                f"\\$\\{{[^}}]*{self.marker}"
            ),
        ]
    
    async def test_parameter(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        original_value: str = ""
    ) -> List[XSSResult]:
        """
        Test a parameter for XSS vulnerabilities
        
        Args:
            url: Target URL
            parameter: Parameter name
            method: HTTP method
            original_value: Original parameter value
        
        Returns:
            List of XSS findings
        """
        results = []
        
        # Test reflected XSS
        reflected_results = await self._test_reflected(
            url, parameter, method, original_value
        )
        results.extend(reflected_results)
        
        # TODO: Test stored XSS (requires revisiting page)
        # TODO: Test DOM-based XSS (requires JavaScript execution)
        
        return results
    
    async def _test_reflected(
        self,
        url: str,
        parameter: str,
        method: str,
        original_value: str
    ) -> List[XSSResult]:
        """Test for reflected XSS"""
        results = []
        payloads = self.get_payloads()
        
        for payload_obj in payloads:
            try:
                test_value = payload_obj.payload
                
                # Make request with payload
                if method.upper() == "GET":
                    response = await self.client.get(url, params={parameter: test_value})
                else:
                    response = await self.client.post(url, data={parameter: test_value})
                
                content = response.text
                
                # Check if payload is reflected
                if self.marker in content:
                    # Check if it's reflected without proper encoding
                    if re.search(payload_obj.detection_pattern, content, re.IGNORECASE):
                        logger.info(f"Found reflected XSS: {url}?{parameter}")
                        
                        # Determine confidence based on context
                        confidence = self._assess_xss_confidence(
                            content,
                            payload_obj.payload,
                            payload_obj.context
                        )
                        
                        results.append(XSSResult(
                            is_vulnerable=True,
                            confidence=confidence,
                            xss_type="reflected",
                            payload_used=payload_obj.payload,
                            context=payload_obj.context,
                            evidence=f"Payload reflected in {payload_obj.context} context",
                            url=url,
                            parameter=parameter
                        ))
                        
                        # One successful payload is enough for reflected XSS
                        break
                    else:
                        # Marker is reflected but payload is encoded
                        logger.debug(f"Payload reflected but encoded: {url}?{parameter}")
                
            except Exception as e:
                logger.debug(f"XSS test failed for {payload_obj.payload}: {e}")
        
        return results
    
    def _assess_xss_confidence(
        self,
        content: str,
        payload: str,
        context: str
    ) -> float:
        """Assess confidence level of XSS finding"""
        
        # Check for obvious script execution
        if "<script>" in payload.lower() and "<script>" in content.lower():
            return 0.95
        
        # Check for event handlers
        if re.search(r'on\w+\s*=', payload, re.IGNORECASE):
            if re.search(r'on\w+\s*=', content, re.IGNORECASE):
                return 0.9
        
        # Check for SVG/IMG based XSS
        if "<svg" in payload.lower() or "<img" in payload.lower():
            return 0.85
        
        # JavaScript context
        if context == "javascript":
            return 0.8
        
        # Attribute context
        if context == "attribute":
            return 0.75
        
        # Default
        return 0.7
    
    async def test_dom_xss(
        self,
        url: str,
        parameter: str
    ) -> Optional[XSSResult]:
        """
        Test for DOM-based XSS (requires browser automation)
        
        Note: This is a placeholder. Full DOM XSS testing requires
        Playwright/Selenium to execute JavaScript and monitor DOM changes.
        """
        # TODO: Implement with Playwright
        # 1. Navigate to URL with payload
        # 2. Monitor console for errors/alerts
        # 3. Check DOM for injected scripts
        # 4. Monitor network requests triggered by payload
        
        logger.debug("DOM-based XSS testing not yet implemented")
        return None
    
    async def check_stored_xss(
        self,
        submit_url: str,
        view_url: str,
        parameter: str,
        method: str = "POST"
    ) -> Optional[XSSResult]:
        """
        Test for stored XSS
        
        Args:
            submit_url: URL where payload is submitted
            view_url: URL where payload should be displayed
            parameter: Parameter name
            method: HTTP method for submission
        
        Returns:
            XSS result if found
        """
        test_payload = f"<script>alert('{self.marker}')</script>"
        
        try:
            # Submit payload
            if method.upper() == "GET":
                await self.client.get(submit_url, params={parameter: test_payload})
            else:
                await self.client.post(submit_url, data={parameter: test_payload})
            
            # Wait a bit for processing
            await asyncio.sleep(1)
            
            # Check if payload is stored and reflected
            response = await self.client.get(view_url)
            content = response.text
            
            if self.marker in content:
                if re.search(f"<script>.*?{self.marker}.*?</script>", content, re.IGNORECASE):
                    logger.info(f"Found stored XSS: {submit_url} -> {view_url}")
                    return XSSResult(
                        is_vulnerable=True,
                        confidence=0.95,
                        xss_type="stored",
                        payload_used=test_payload,
                        context="html",
                        evidence=f"Payload stored and reflected without encoding",
                        url=submit_url,
                        parameter=parameter
                    )
        
        except Exception as e:
            logger.error(f"Stored XSS test failed: {e}")
        
        return None
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()
