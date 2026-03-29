"""
Insecure Deserialization Detector for ARES
Detects insecure deserialization vulnerabilities across multiple languages
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
import re
import base64
import asyncio
import pickle
import aiohttp
from loguru import logger


@dataclass
class DeserializationPayload:
    """Deserialization test payload"""
    payload: str
    language: str  # python, java, php, dotnet, nodejs
    encoding: str  # base64, raw, hex
    detection_method: str
    description: str


@dataclass
class DeserializationResult:
    """Result of deserialization vulnerability test"""
    is_vulnerable: bool
    confidence: float
    language: str
    payload_type: str
    evidence: str
    url: str
    parameter: str
    severity: str


class DeserializationDetector:
    """Insecure deserialization vulnerability detector"""
    
    MARKER = "ARES_DESER_MARKER_123456"
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(ssl=False)
            )
        return self.session
    
    def get_python_payloads(self) -> List[DeserializationPayload]:
        """Get Python pickle deserialization payloads"""
        payloads = []
        
        # Safe detection payload - just creates a marker string
        try:
            # Create a safe object that will show we can execute code
            class SafeMarker:
                def __reduce__(self):
                    # Returns a callable and args - will create string when unpickled
                    return (str, (self.MARKER,))
            
            safe_obj = SafeMarker()
            pickled = pickle.dumps(safe_obj)
            encoded = base64.b64encode(pickled).decode()
            
            payloads.append(DeserializationPayload(
                payload=encoded,
                language="python",
                encoding="base64",
                detection_method="marker_in_response",
                description="Safe pickle payload that creates marker string"
            ))
        except Exception as e:
            logger.debug(f"Failed to create Python safe payload: {e}")
        
        # Common pickle patterns (signatures)
        # These are recognizable patterns that indicate pickle usage
        payloads.append(DeserializationPayload(
            payload="gASVDgAAAAAAAACMCmFyZXNfbWFya2VylC4=",  # Pickled string
            language="python",
            encoding="base64",
            detection_method="error_message",
            description="Pickle protocol signature test"
        ))
        
        # YAML deserialization (Python)
        yaml_payload = f'''!!python/object/apply:os.system
args: ['echo {self.MARKER}']'''
        
        payloads.append(DeserializationPayload(
            payload=yaml_payload,
            language="python_yaml",
            encoding="raw",
            detection_method="marker_in_response",
            description="YAML unsafe deserialization"
        ))
        
        return payloads
    
    def get_java_payloads(self) -> List[DeserializationPayload]:
        """Get Java deserialization payloads"""
        payloads = []
        
        # Java serialization magic bytes: AC ED 00 05
        # These are safe test payloads that just identify Java serialization
        
        # Common Java serialization signature
        java_sig = "rO0ABQ=="  # Base64 encoded AC ED 00 05
        
        payloads.append(DeserializationPayload(
            payload=java_sig,
            language="java",
            encoding="base64",
            detection_method="error_message",
            description="Java serialization signature test"
        ))
        
        # Commons-Collections gadget chain signature (safe detection)
        # Look for error messages indicating vulnerable libraries
        payloads.append(DeserializationPayload(
            payload="rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",
            language="java",
            encoding="base64",
            detection_method="error_message",
            description="Java PriorityQueue serialization test"
        ))
        
        return payloads
    
    def get_php_payloads(self) -> List[DeserializationPayload]:
        """Get PHP unserialize payloads"""
        payloads = []
        
        # PHP Object injection signature
        # O:8:"stdClass":1:{s:4:"test";s:5:"value";}
        
        # Safe test - stdClass object
        php_obj = 'O:8:"stdClass":1:{s:6:"marker";s:' + str(len(self.MARKER)) + ':"' + self.MARKER + '";}'
        
        payloads.append(DeserializationPayload(
            payload=php_obj,
            language="php",
            encoding="raw",
            detection_method="marker_in_response",
            description="PHP object serialization test"
        ))
        
        # PHP array
        php_array = f'a:1:{{i:0;s:{len(self.MARKER)}:"{self.MARKER}";}}'
        
        payloads.append(DeserializationPayload(
            payload=php_array,
            language="php",
            encoding="raw",
            detection_method="marker_in_response",
            description="PHP array serialization test"
        ))
        
        # Base64 encoded PHP object
        encoded_php = base64.b64encode(php_obj.encode()).decode()
        
        payloads.append(DeserializationPayload(
            payload=encoded_php,
            language="php",
            encoding="base64",
            detection_method="marker_in_response",
            description="Base64 encoded PHP object"
        ))
        
        return payloads
    
    def get_dotnet_payloads(self) -> List[DeserializationPayload]:
        """.NET deserialization payloads"""
        payloads = []
        
        # .NET BinaryFormatter signature
        # These are safe detection payloads
        
        dotnet_sig = "AAEAAAD/////"  # .NET serialization signature
        
        payloads.append(DeserializationPayload(
            payload=dotnet_sig,
            language="dotnet",
            encoding="base64",
            detection_method="error_message",
            description=".NET BinaryFormatter signature"
        ))
        
        return payloads
    
    def get_nodejs_payloads(self) -> List[DeserializationPayload]:
        """Node.js deserialization payloads"""
        payloads = []
        
        # Node-serialize vulnerability
        nodejs_payload = '{"rce":"_$$ND_FUNC$$_function (){console.log(\'' + self.MARKER + '\')}()"}'
        
        payloads.append(DeserializationPayload(
            payload=nodejs_payload,
            language="nodejs",
            encoding="raw",
            detection_method="marker_in_response",
            description="Node-serialize IIFE injection"
        ))
        
        # JSON with __proto__ pollution
        proto_payload = '{"__proto__":{"marker":"' + self.MARKER + '"}}'
        
        payloads.append(DeserializationPayload(
            payload=proto_payload,
            language="nodejs",
            encoding="raw",
            detection_method="prototype_pollution",
            description="Prototype pollution test"
        ))
        
        return payloads
    
    async def test_parameter(
        self,
        url: str,
        parameter: str,
        method: str = "POST",
        original_value: str = ""
    ) -> List[DeserializationResult]:
        """
        Test a parameter for deserialization vulnerabilities
        
        Args:
            url: Target URL
            parameter: Parameter name
            method: HTTP method
            original_value: Original parameter value
        
        Returns:
            List of deserialization findings
        """
        results = []
        session = await self._get_session()
        
        # Get baseline response
        baseline = await self._get_baseline(url, parameter, original_value, method, session)
        
        if not baseline:
            logger.warning(f"Failed to get baseline for {url}?{parameter}")
            return results
        
        # Detect language based on baseline or try all
        detected_language = self._detect_language(baseline)
        
        # Test payloads for each language
        all_payloads = []
        
        if not detected_language or detected_language == "python":
            all_payloads.extend(self.get_python_payloads())
        
        if not detected_language or detected_language == "java":
            all_payloads.extend(self.get_java_payloads())
        
        if not detected_language or detected_language == "php":
            all_payloads.extend(self.get_php_payloads())
        
        if not detected_language or detected_language == "dotnet":
            all_payloads.extend(self.get_dotnet_payloads())
        
        if not detected_language or detected_language == "nodejs":
            all_payloads.extend(self.get_nodejs_payloads())
        
        # Test each payload
        for payload_obj in all_payloads:
            try:
                result = await self._test_payload(
                    url=url,
                    parameter=parameter,
                    method=method,
                    payload_obj=payload_obj,
                    baseline=baseline,
                    session=session
                )
                
                if result:
                    results.append(result)
                    logger.warning(
                        f"Deserialization vulnerability found: {url}?{parameter} ({result.language})"
                    )
            
            except Exception as e:
                logger.debug(f"Deserialization test failed for {payload_obj.language}: {e}")
        
        return results
    
    async def _get_baseline(
        self,
        url: str,
        parameter: str,
        value: str,
        method: str,
        session: aiohttp.ClientSession
    ) -> Optional[Dict]:
        """Get baseline response"""
        try:
            if method.upper() == "GET":
                async with session.get(url, params={parameter: value}) as response:
                    return {
                        'status': response.status,
                        'content': await response.text(),
                        'headers': dict(response.headers)
                    }
            else:
                async with session.post(url, data={parameter: value}) as response:
                    return {
                        'status': response.status,
                        'content': await response.text(),
                        'headers': dict(response.headers)
                    }
        except Exception as e:
            logger.error(f"Baseline request failed: {e}")
            return None
    
    def _detect_language(self, baseline: Dict) -> Optional[str]:
        """Detect backend language from baseline response"""
        
        headers = baseline.get('headers', {})
        content = baseline.get('content', '')
        
        # Check server headers
        server = headers.get('server', '').lower()
        powered_by = headers.get('x-powered-by', '').lower()
        
        # Java indicators
        if 'tomcat' in server or 'jetty' in server or 'jboss' in server:
            return "java"
        if 'jsessionid' in content.lower():
            return "java"
        
        # PHP indicators
        if 'php' in powered_by or 'php' in server:
            return "php"
        if 'phpsessid' in content.lower():
            return "php"
        
        # .NET indicators
        if 'asp.net' in powered_by or 'iis' in server:
            return "dotnet"
        if 'viewstate' in content.lower():
            return "dotnet"
        
        # Python indicators
        if 'werkzeug' in server or 'gunicorn' in server or 'uwsgi' in server:
            return "python"
        
        # Node.js indicators
        if 'express' in powered_by or 'node' in server:
            return "nodejs"
        
        return None
    
    async def _test_payload(
        self,
        url: str,
        parameter: str,
        method: str,
        payload_obj: DeserializationPayload,
        baseline: Dict,
        session: aiohttp.ClientSession
    ) -> Optional[DeserializationResult]:
        """Test a deserialization payload"""
        
        try:
            # Send request with payload
            if method.upper() == "GET":
                async with session.get(
                    url,
                    params={parameter: payload_obj.payload},
                    allow_redirects=False
                ) as response:
                    content = await response.text()
                    status = response.status
            else:
                # Try both data and json
                async with session.post(
                    url,
                    data={parameter: payload_obj.payload},
                    allow_redirects=False
                ) as response:
                    content = await response.text()
                    status = response.status
            
            # Analyze response based on detection method
            if payload_obj.detection_method == "marker_in_response":
                if self.MARKER in content:
                    return DeserializationResult(
                        is_vulnerable=True,
                        confidence=0.95,
                        language=payload_obj.language,
                        payload_type="safe_marker",
                        evidence=f"Deserialization marker reflected: {self.MARKER}",
                        url=url,
                        parameter=parameter,
                        severity="critical"
                    )
            
            elif payload_obj.detection_method == "error_message":
                # Check for deserialization error messages
                result = self._check_error_messages(
                    content=content,
                    language=payload_obj.language,
                    url=url,
                    parameter=parameter,
                    payload_obj=payload_obj
                )
                if result:
                    return result
            
            elif payload_obj.detection_method == "prototype_pollution":
                # For prototype pollution, check if marker appears in unexpected places
                if self.MARKER in content and self.MARKER not in baseline['content']:
                    return DeserializationResult(
                        is_vulnerable=True,
                        confidence=0.7,
                        language=payload_obj.language,
                        payload_type="prototype_pollution",
                        evidence="Possible prototype pollution detected",
                        url=url,
                        parameter=parameter,
                        severity="high"
                    )
        
        except Exception as e:
            logger.debug(f"Payload test failed: {e}")
        
        return None
    
    def _check_error_messages(
        self,
        content: str,
        language: str,
        url: str,
        parameter: str,
        payload_obj: DeserializationPayload
    ) -> Optional[DeserializationResult]:
        """Check for deserialization-specific error messages"""
        
        error_patterns = {
            'python': [
                r'pickle\.loads?',
                r'pickle\.Unpickler',
                r'cPickle',
                r'_pickle\.UnpicklingError',
                r'yaml\.load',
                r'yaml\.unsafe_load'
            ],
            'java': [
                r'ObjectInputStream',
                r'readObject',
                r'java\.io\.InvalidClassException',
                r'ClassNotFoundException',
                r'commons\.collections',
                r'InvocationTargetException'
            ],
            'php': [
                r'unserialize\(\)',
                r'__wakeup',
                r'__destruct',
                r'__toString',
                r'Serialization.*failed',
                r'unserialize.*error'
            ],
            'dotnet': [
                r'BinaryFormatter',
                r'Deserialize',
                r'SerializationException',
                r'System\.Runtime\.Serialization'
            ],
            'nodejs': [
                r'node-serialize',
                r'serialize-javascript',
                r'JSON\.parse',
                r'\_\$\$ND_FUNC\$\$\_'
            ]
        }
        
        if language in error_patterns:
            for pattern in error_patterns[language]:
                if re.search(pattern, content, re.IGNORECASE):
                    return DeserializationResult(
                        is_vulnerable=True,
                        confidence=0.8,
                        language=language,
                        payload_type="signature_detected",
                        evidence=f"Deserialization error pattern detected: {pattern}",
                        url=url,
                        parameter=parameter,
                        severity="high"
                    )
        
        return None
    
    async def test_cookie(
        self,
        url: str,
        cookie_name: str,
        method: str = "GET"
    ) -> List[DeserializationResult]:
        """
        Test a cookie for deserialization vulnerabilities
        
        Args:
            url: Target URL
            cookie_name: Cookie name to test
            method: HTTP method
        
        Returns:
            List of deserialization findings
        """
        results = []
        session = await self._get_session()
        
        # Get all payloads
        all_payloads = (
            self.get_python_payloads() +
            self.get_java_payloads() +
            self.get_php_payloads() +
            self.get_dotnet_payloads() +
            self.get_nodejs_payloads()
        )
        
        for payload_obj in all_payloads:
            try:
                # Set cookie with payload
                cookies = {cookie_name: payload_obj.payload}
                
                if method.upper() == "GET":
                    async with session.get(url, cookies=cookies) as response:
                        content = await response.text()
                else:
                    async with session.post(url, cookies=cookies) as response:
                        content = await response.text()
                
                # Check for marker
                if self.MARKER in content:
                    results.append(DeserializationResult(
                        is_vulnerable=True,
                        confidence=0.9,
                        language=payload_obj.language,
                        payload_type="cookie_deserialization",
                        evidence=f"Cookie deserialization vulnerability in '{cookie_name}'",
                        url=url,
                        parameter=cookie_name,
                        severity="critical"
                    ))
                    logger.warning(f"Cookie deserialization found: {cookie_name}")
                    break
            
            except Exception as e:
                logger.debug(f"Cookie test failed for {payload_obj.language}: {e}")
        
        return results
    
    async def test_viewstate(
        self,
        url: str,
        viewstate_value: str = None
    ) -> Optional[DeserializationResult]:
        """
        Test ASP.NET ViewState for deserialization vulnerabilities
        
        Args:
            url: Target URL
            viewstate_value: ViewState value (if known)
        
        Returns:
            Deserialization result if vulnerable
        """
        session = await self._get_session()
        
        try:
            # If no viewstate provided, get it from the page
            if not viewstate_value:
                async with session.get(url) as response:
                    content = await response.text()
                    
                    # Extract ViewState
                    match = re.search(
                        r'__VIEWSTATE["\s]*value=["\'](.*?)["\']',
                        content
                    )
                    
                    if match:
                        viewstate_value = match.group(1)
                    else:
                        logger.debug("No ViewState found")
                        return None
            
            # Check if ViewState is MAC protected
            # Unprotected ViewState is a vulnerability
            if viewstate_value:
                # Try to decode and check structure
                try:
                    decoded = base64.b64decode(viewstate_value)
                    
                    # Check for MAC signature (last 20-32 bytes typically)
                    if len(decoded) < 32:
                        return DeserializationResult(
                            is_vulnerable=True,
                            confidence=0.7,
                            language="dotnet",
                            payload_type="viewstate_no_mac",
                            evidence="ViewState appears to lack MAC protection",
                            url=url,
                            parameter="__VIEWSTATE",
                            severity="high"
                        )
                except Exception:
                    pass
        
        except Exception as e:
            logger.debug(f"ViewState test failed: {e}")
        
        return None
    
    async def close(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None
