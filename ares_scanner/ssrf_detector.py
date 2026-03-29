"""
Server-Side Request Forgery (SSRF) Detector for ARES
Detects SSRF vulnerabilities including cloud metadata access
"""

from typing import List, Dict, Optional, Set
from dataclasses import dataclass
import re
import asyncio
import time
from urllib.parse import urlparse, urljoin
import aiohttp
from loguru import logger


@dataclass
class SSRFPayload:
    """SSRF test payload"""
    payload: str
    target_type: str  # internal_ip, metadata, localhost, dns_rebind
    expected_behavior: str


@dataclass
class SSRFResult:
    """Result of SSRF vulnerability test"""
    is_vulnerable: bool
    confidence: float
    ssrf_type: str
    payload_used: str
    evidence: str
    url: str
    parameter: str
    severity: str


class SSRFDetector:
    """Server-Side Request Forgery vulnerability detector"""
    
    # Cloud metadata endpoints
    CLOUD_METADATA = {
        'aws': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/',
        ],
        'gcp': [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/computeMetadata/v1/',
        ],
        'azure': [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token',
        ],
        'digitalocean': [
            'http://169.254.169.254/metadata/v1/',
        ],
        'oracle': [
            'http://169.254.169.254/opc/v1/instance/',
        ]
    }
    
    # Internal IP ranges (RFC 1918)
    INTERNAL_IPS = [
        'http://127.0.0.1',
        'http://localhost',
        'http://0.0.0.0',
        'http://10.0.0.1',
        'http://172.16.0.1',
        'http://192.168.0.1',
        'http://192.168.1.1',
    ]
    
    # URL bypass techniques
    BYPASS_TECHNIQUES = [
        # Localhost variations
        'http://127.0.0.1',
        'http://127.1',
        'http://0',
        'http://0.0.0.0',
        'http://[::1]',
        'http://localhost',
        
        # IP encoding
        'http://2130706433',  # 127.0.0.1 in decimal
        'http://0x7f000001',  # 127.0.0.1 in hex
        'http://017700000001',  # 127.0.0.1 in octal
        
        # DNS tricks
        'http://127.0.0.1.nip.io',
        'http://localtest.me',
        'http://customer1.app.localhost.my.company.127.0.0.1.nip.io',
    ]
    
    def __init__(
        self,
        timeout: int = 10,
        callback_server: str = None
    ):
        self.timeout = timeout
        self.callback_server = callback_server  # For out-of-band detection
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(ssl=False)
            )
        return self.session
    
    async def test_parameter(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        original_value: str = ""
    ) -> List[SSRFResult]:
        """
        Test a parameter for SSRF vulnerabilities
        
        Args:
            url: Target URL
            parameter: Parameter name to test
            method: HTTP method
            original_value: Original parameter value
        
        Returns:
            List of SSRF findings
        """
        results = []
        session = await self._get_session()
        
        # Get baseline response
        baseline = await self._get_baseline(url, parameter, original_value, method, session)
        
        if not baseline:
            logger.warning(f"Failed to get baseline for {url}?{parameter}")
            return results
        
        # Test 1: Cloud metadata endpoints
        metadata_results = await self._test_cloud_metadata(
            url, parameter, method, baseline, session
        )
        results.extend(metadata_results)
        
        # Test 2: Internal IP access
        internal_results = await self._test_internal_ips(
            url, parameter, method, baseline, session
        )
        results.extend(internal_results)
        
        # Test 3: Localhost access
        localhost_results = await self._test_localhost_access(
            url, parameter, method, baseline, session
        )
        results.extend(localhost_results)
        
        # Test 4: Bypass techniques
        bypass_results = await self._test_bypass_techniques(
            url, parameter, method, baseline, session
        )
        results.extend(bypass_results)
        
        # Test 5: Out-of-band callbacks (if callback server configured)
        if self.callback_server:
            oob_result = await self._test_oob_callback(
                url, parameter, method, session
            )
            if oob_result:
                results.append(oob_result)
        
        return results
    
    async def _get_baseline(
        self,
        url: str,
        parameter: str,
        value: str,
        method: str,
        session: aiohttp.ClientSession
    ) -> Optional[Dict]:
        """Get baseline response for comparison"""
        try:
            if method.upper() == "GET":
                async with session.get(url, params={parameter: value}) as response:
                    return {
                        'status': response.status,
                        'content': await response.text(),
                        'length': len(await response.text()),
                        'headers': dict(response.headers)
                    }
            else:
                async with session.post(url, data={parameter: value}) as response:
                    return {
                        'status': response.status,
                        'content': await response.text(),
                        'length': len(await response.text()),
                        'headers': dict(response.headers)
                    }
        except Exception as e:
            logger.error(f"Baseline request failed: {e}")
            return None
    
    async def _test_cloud_metadata(
        self,
        url: str,
        parameter: str,
        method: str,
        baseline: Dict,
        session: aiohttp.ClientSession
    ) -> List[SSRFResult]:
        """Test access to cloud metadata endpoints"""
        results = []
        
        for cloud_provider, endpoints in self.CLOUD_METADATA.items():
            for endpoint in endpoints:
                try:
                    # Test if we can access the metadata endpoint
                    if method.upper() == "GET":
                        async with session.get(
                            url,
                            params={parameter: endpoint},
                            allow_redirects=False
                        ) as response:
                            content = await response.text()
                    else:
                        async with session.post(
                            url,
                            data={parameter: endpoint},
                            allow_redirects=False
                        ) as response:
                            content = await response.text()
                    
                    # Check for metadata-specific indicators
                    indicators = self._check_metadata_indicators(
                        cloud_provider, content
                    )
                    
                    if indicators:
                        logger.warning(
                            f"SSRF to {cloud_provider} metadata: {url}?{parameter}"
                        )
                        results.append(SSRFResult(
                            is_vulnerable=True,
                            confidence=0.95,
                            ssrf_type=f"cloud_metadata_{cloud_provider}",
                            payload_used=endpoint,
                            evidence=f"Accessed {cloud_provider} metadata: {indicators}",
                            url=url,
                            parameter=parameter,
                            severity="critical"
                        ))
                        break  # One success per cloud provider is enough
                    
                    # Even without specific indicators, check response differences
                    elif len(content) > 0 and content != baseline['content']:
                        # Response is different and non-empty
                        if len(content) > 100:  # Substantial response
                            results.append(SSRFResult(
                                is_vulnerable=True,
                                confidence=0.7,
                                ssrf_type=f"possible_cloud_metadata_{cloud_provider}",
                                payload_used=endpoint,
                                evidence=f"Received non-empty response ({len(content)} bytes) from metadata endpoint",
                                url=url,
                                parameter=parameter,
                                severity="high"
                            ))
                
                except Exception as e:
                    logger.debug(f"Metadata test failed for {endpoint}: {e}")
        
        return results
    
    def _check_metadata_indicators(
        self,
        cloud_provider: str,
        content: str
    ) -> str:
        """Check for cloud-specific metadata indicators in response"""
        
        indicators = {
            'aws': [
                'ami-id', 'instance-id', 'instance-type',
                'security-credentials', 'iam/security-credentials'
            ],
            'gcp': [
                'computeMetadata', 'instance/id', 'instance/name',
                'service-accounts'
            ],
            'azure': [
                'azEnvironment', 'subscriptionId', 'vmId',
                'resourceGroupName'
            ],
            'digitalocean': [
                'droplet_id', 'hostname', 'vendor_data'
            ],
            'oracle': [
                'instance/id', 'instance/displayName'
            ]
        }
        
        if cloud_provider in indicators:
            for indicator in indicators[cloud_provider]:
                if indicator in content:
                    return f"Found indicator: {indicator}"
        
        return ""
    
    async def _test_internal_ips(
        self,
        url: str,
        parameter: str,
        method: str,
        baseline: Dict,
        session: aiohttp.ClientSession
    ) -> List[SSRFResult]:
        """Test access to internal IP addresses"""
        results = []
        
        for internal_ip in self.INTERNAL_IPS:
            try:
                if method.upper() == "GET":
                    async with session.get(
                        url,
                        params={parameter: internal_ip},
                        allow_redirects=False
                    ) as response:
                        content = await response.text()
                        status = response.status
                else:
                    async with session.post(
                        url,
                        data={parameter: internal_ip},
                        allow_redirects=False
                    ) as response:
                        content = await response.text()
                        status = response.status
                
                # Check if response indicates successful internal access
                if self._indicates_internal_access(content, status, baseline):
                    logger.warning(f"SSRF to internal IP: {url}?{parameter}={internal_ip}")
                    results.append(SSRFResult(
                        is_vulnerable=True,
                        confidence=0.8,
                        ssrf_type="internal_ip_access",
                        payload_used=internal_ip,
                        evidence=f"Successfully accessed internal IP (status: {status}, length: {len(content)})",
                        url=url,
                        parameter=parameter,
                        severity="high"
                    ))
                    break  # One success is enough
            
            except Exception as e:
                logger.debug(f"Internal IP test failed for {internal_ip}: {e}")
        
        return results
    
    async def _test_localhost_access(
        self,
        url: str,
        parameter: str,
        method: str,
        baseline: Dict,
        session: aiohttp.ClientSession
    ) -> List[SSRFResult]:
        """Test localhost access via various techniques"""
        results = []
        
        # Test common localhost ports
        localhost_targets = [
            'http://127.0.0.1:80',
            'http://127.0.0.1:8080',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:5000',
            'http://127.0.0.1:6379',  # Redis
            'http://127.0.0.1:27017',  # MongoDB
            'http://127.0.0.1:9200',  # Elasticsearch
        ]
        
        for target in localhost_targets:
            try:
                if method.upper() == "GET":
                    async with session.get(
                        url,
                        params={parameter: target},
                        allow_redirects=False
                    ) as response:
                        content = await response.text()
                        status = response.status
                else:
                    async with session.post(
                        url,
                        data={parameter: target},
                        allow_redirects=False
                    ) as response:
                        content = await response.text()
                        status = response.status
                
                # Check for service-specific indicators
                service_detected = self._detect_internal_service(content)
                
                if service_detected:
                    port = target.split(':')[-1]
                    logger.warning(f"SSRF to localhost port {port}: {url}?{parameter}")
                    results.append(SSRFResult(
                        is_vulnerable=True,
                        confidence=0.9,
                        ssrf_type="localhost_service_access",
                        payload_used=target,
                        evidence=f"Accessed internal service: {service_detected}",
                        url=url,
                        parameter=parameter,
                        severity="critical"
                    ))
                    break
            
            except Exception as e:
                logger.debug(f"Localhost test failed for {target}: {e}")
        
        return results
    
    def _detect_internal_service(self, content: str) -> str:
        """Detect internal services from response content"""
        
        services = {
            'Redis': ['redis_version', '-ERR', '+PONG'],
            'MongoDB': ['MongoDB', 'dbStats', 'listDatabases'],
            'Elasticsearch': ['elasticsearch', 'cluster_name', 'lucene_version'],
            'Memcached': ['STAT', 'VERSION'],
            'Jenkins': ['Jenkins', 'X-Jenkins'],
            'Tomcat': ['Apache Tomcat'],
            'Jetty': ['Powered by Jetty'],
        }
        
        for service_name, indicators in services.items():
            if any(indicator in content for indicator in indicators):
                return service_name
        
        return ""
    
    async def _test_bypass_techniques(
        self,
        url: str,
        parameter: str,
        method: str,
        baseline: Dict,
        session: aiohttp.ClientSession
    ) -> List[SSRFResult]:
        """Test SSRF filter bypass techniques"""
        results = []
        
        for bypass_payload in self.BYPASS_TECHNIQUES:
            try:
                if method.upper() == "GET":
                    async with session.get(
                        url,
                        params={parameter: bypass_payload},
                        allow_redirects=False
                    ) as response:
                        content = await response.text()
                        status = response.status
                else:
                    async with session.post(
                        url,
                        data={parameter: bypass_payload},
                        allow_redirects=False
                    ) as response:
                        content = await response.text()
                        status = response.status
                
                # Check if bypass was successful
                if self._indicates_internal_access(content, status, baseline):
                    logger.warning(f"SSRF bypass successful: {url}?{parameter}={bypass_payload}")
                    results.append(SSRFResult(
                        is_vulnerable=True,
                        confidence=0.85,
                        ssrf_type="bypass_localhost_filter",
                        payload_used=bypass_payload,
                        evidence=f"Bypassed localhost filter using: {bypass_payload}",
                        url=url,
                        parameter=parameter,
                        severity="high"
                    ))
                    break
            
            except Exception as e:
                logger.debug(f"Bypass test failed for {bypass_payload}: {e}")
        
        return results
    
    def _indicates_internal_access(
        self,
        content: str,
        status: int,
        baseline: Dict
    ) -> bool:
        """Check if response indicates successful internal access"""
        
        # Successful response codes
        if status in [200, 301, 302]:
            # Response is different from baseline
            if len(content) > 0 and content != baseline['content']:
                # Check for common localhost indicators
                localhost_indicators = [
                    'localhost', '127.0.0.1', 'index of /',
                    'apache', 'nginx', 'welcome to',
                    'it works', 'default page'
                ]
                
                content_lower = content.lower()
                if any(indicator in content_lower for indicator in localhost_indicators):
                    return True
                
                # Significant response size difference
                if abs(len(content) - baseline['length']) > 100:
                    return True
        
        return False
    
    async def _test_oob_callback(
        self,
        url: str,
        parameter: str,
        method: str,
        session: aiohttp.ClientSession
    ) -> Optional[SSRFResult]:
        """
        Test for SSRF using out-of-band callbacks
        
        Requires a callback server (e.g., Burp Collaborator, interactsh)
        """
        if not self.callback_server:
            return None
        
        try:
            # Generate unique identifier
            import uuid
            unique_id = str(uuid.uuid4())[:8]
            callback_url = f"http://{unique_id}.{self.callback_server}"
            
            # Send request with callback URL
            if method.upper() == "GET":
                async with session.get(
                    url,
                    params={parameter: callback_url},
                    allow_redirects=False
                ) as response:
                    pass
            else:
                async with session.post(
                    url,
                    data={parameter: callback_url},
                    allow_redirects=False
                ) as response:
                    pass
            
            # Wait for callback (would need to check callback server)
            await asyncio.sleep(2)
            
            # In real implementation, check callback server for hits
            # For now, this is a placeholder
            # if self._check_callback_received(unique_id):
            #     return SSRFResult(...)
            
            logger.debug(f"OOB callback test sent: {callback_url}")
        
        except Exception as e:
            logger.debug(f"OOB callback test failed: {e}")
        
        return None
    
    async def test_url_parameter(
        self,
        url: str,
        parameter: str,
        method: str = "GET"
    ) -> List[SSRFResult]:
        """
        Test URL parameter for SSRF (convenience method)
        
        Args:
            url: Target URL
            parameter: Parameter name that accepts URLs
            method: HTTP method
        
        Returns:
            List of SSRF findings
        """
        return await self.test_parameter(
            url=url,
            parameter=parameter,
            method=method,
            original_value="http://example.com"
        )
    
    async def close(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None
