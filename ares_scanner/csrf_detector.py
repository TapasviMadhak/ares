"""
Cross-Site Request Forgery (CSRF) Detector for ARES
Detects missing/weak CSRF tokens and related vulnerabilities
"""

from typing import List, Dict, Optional, Set
from dataclasses import dataclass
import re
import asyncio
import hashlib
from urllib.parse import urljoin, urlparse
import aiohttp
from loguru import logger


@dataclass
class CSRFResult:
    """Result of CSRF vulnerability test"""
    is_vulnerable: bool
    confidence: float
    vulnerability_type: str
    evidence: str
    url: str
    form_action: str
    severity: str  # critical, high, medium, low


class CSRFDetector:
    """CSRF vulnerability detector"""
    
    # Common CSRF token parameter names
    TOKEN_NAMES = [
        'csrf', 'csrf_token', 'csrftoken', 'csrf-token',
        'token', '_token', 'authenticity_token',
        'anti_csrf', 'xsrf', 'xsrf_token', 'xsrf-token',
        '__requestverificationtoken', 'nonce', '_csrf'
    ]
    
    # State-changing HTTP methods
    STATE_CHANGING_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH']
    
    def __init__(self, timeout: int = 10):
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
    
    async def test_form(
        self,
        url: str,
        form: Dict,
        base_url: str = None
    ) -> List[CSRFResult]:
        """
        Test a form for CSRF vulnerabilities
        
        Args:
            url: URL where form is located
            form: Form data dict with 'action', 'method', 'inputs'
            base_url: Base URL for resolving relative actions
        
        Returns:
            List of CSRF findings
        """
        results = []
        session = await self._get_session()
        
        # Determine form action URL
        form_action = form.get('action', '')
        if not form_action:
            form_action = url
        else:
            form_action = urljoin(base_url or url, form_action)
        
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        # Only test state-changing methods
        if method not in self.STATE_CHANGING_METHODS:
            logger.debug(f"Skipping non-state-changing form: {method} {form_action}")
            return results
        
        # Check 1: Missing CSRF token
        token_result = await self._check_missing_token(
            url, form_action, method, inputs, session
        )
        if token_result:
            results.append(token_result)
        
        # Check 2: Weak CSRF token (if present)
        weak_token_result = await self._check_weak_token(
            url, form_action, method, inputs, session
        )
        if weak_token_result:
            results.append(weak_token_result)
        
        # Check 3: CSRF token in URL (GET parameter)
        url_token_result = await self._check_token_in_url(
            url, form_action, inputs
        )
        if url_token_result:
            results.append(url_token_result)
        
        # Check 4: SameSite cookie attribute
        samesite_result = await self._check_samesite_cookie(
            url, session
        )
        if samesite_result:
            results.append(samesite_result)
        
        return results
    
    async def _check_missing_token(
        self,
        url: str,
        form_action: str,
        method: str,
        inputs: List[Dict],
        session: aiohttp.ClientSession
    ) -> Optional[CSRFResult]:
        """Check if form is missing CSRF token"""
        
        # Look for CSRF token in form inputs
        has_csrf_token = False
        for input_field in inputs:
            name = input_field.get('name', '').lower()
            if any(token_name in name for token_name in self.TOKEN_NAMES):
                has_csrf_token = True
                break
        
        if has_csrf_token:
            logger.debug(f"CSRF token found in form: {form_action}")
            return None
        
        # No token found - test if form accepts submission without it
        try:
            # Build form data from inputs
            form_data = {}
            for input_field in inputs:
                name = input_field.get('name')
                value = input_field.get('value', 'test')
                input_type = input_field.get('type', 'text')
                
                if name and input_type not in ['submit', 'button', 'image']:
                    form_data[name] = value
            
            # Attempt submission without CSRF token
            async with session.request(
                method,
                form_action,
                data=form_data,
                allow_redirects=False
            ) as response:
                # If request is accepted (not rejected with 403/400)
                if response.status not in [403, 400, 401]:
                    logger.warning(f"Form accepts submission without CSRF token: {form_action}")
                    return CSRFResult(
                        is_vulnerable=True,
                        confidence=0.9,
                        vulnerability_type="missing_csrf_token",
                        evidence=f"Form accepted {method} request without CSRF token (status: {response.status})",
                        url=url,
                        form_action=form_action,
                        severity="high"
                    )
        
        except Exception as e:
            logger.debug(f"Error testing missing token: {e}")
        
        return None
    
    async def _check_weak_token(
        self,
        url: str,
        form_action: str,
        method: str,
        inputs: List[Dict],
        session: aiohttp.ClientSession
    ) -> Optional[CSRFResult]:
        """Check if CSRF token is weak or predictable"""
        
        # Find CSRF token field
        csrf_token = None
        csrf_field_name = None
        
        for input_field in inputs:
            name = input_field.get('name', '').lower()
            value = input_field.get('value', '')
            
            if any(token_name in name for token_name in self.TOKEN_NAMES):
                csrf_token = value
                csrf_field_name = input_field.get('name')
                break
        
        if not csrf_token:
            return None
        
        # Check token characteristics
        issues = []
        
        # Too short
        if len(csrf_token) < 16:
            issues.append(f"Token too short ({len(csrf_token)} chars)")
        
        # Only numeric
        if csrf_token.isdigit():
            issues.append("Token is only numeric (predictable)")
        
        # Appears to be a simple hash of predictable data
        if len(csrf_token) == 32 and all(c in '0123456789abcdef' for c in csrf_token.lower()):
            # Might be MD5 of something predictable
            issues.append("Token appears to be MD5 hash (potentially weak)")
        
        # Check if token is the same across multiple requests
        try:
            # Request the form page again
            async with session.get(url) as response:
                content = await response.text()
                
                # Look for the same token value
                if csrf_token in content:
                    # Token appears multiple times - might be reused
                    token_count = content.count(csrf_token)
                    if token_count > 1:
                        issues.append(f"Same token appears {token_count} times (possibly reused)")
        
        except Exception as e:
            logger.debug(f"Error checking token reuse: {e}")
        
        if issues:
            return CSRFResult(
                is_vulnerable=True,
                confidence=0.7,
                vulnerability_type="weak_csrf_token",
                evidence=f"Weak CSRF token detected: {', '.join(issues)}",
                url=url,
                form_action=form_action,
                severity="medium"
            )
        
        return None
    
    async def _check_token_in_url(
        self,
        url: str,
        form_action: str,
        inputs: List[Dict]
    ) -> Optional[CSRFResult]:
        """Check if CSRF token is exposed in URL parameters"""
        
        # Parse form action URL
        parsed = urlparse(form_action)
        
        # Check if query string contains token-like parameters
        if parsed.query:
            query_lower = parsed.query.lower()
            
            for token_name in self.TOKEN_NAMES:
                if token_name in query_lower:
                    logger.warning(f"CSRF token in URL: {form_action}")
                    return CSRFResult(
                        is_vulnerable=True,
                        confidence=0.85,
                        vulnerability_type="csrf_token_in_url",
                        evidence=f"CSRF token exposed in URL query string: {token_name}",
                        url=url,
                        form_action=form_action,
                        severity="medium"
                    )
        
        return None
    
    async def _check_samesite_cookie(
        self,
        url: str,
        session: aiohttp.ClientSession
    ) -> Optional[CSRFResult]:
        """Check for missing SameSite cookie attribute"""
        
        try:
            async with session.get(url) as response:
                cookies = response.cookies
                
                vulnerable_cookies = []
                
                for cookie_name, cookie in cookies.items():
                    # Check for session cookies without SameSite
                    cookie_lower = cookie_name.lower()
                    
                    # Likely session cookie names
                    if any(name in cookie_lower for name in ['session', 'sid', 'sessionid', 'jsessionid', 'phpsessid']):
                        # Check SameSite attribute
                        samesite = cookie.get('samesite', '').lower()
                        
                        if not samesite or samesite == 'none':
                            vulnerable_cookies.append(cookie_name)
                
                if vulnerable_cookies:
                    return CSRFResult(
                        is_vulnerable=True,
                        confidence=0.75,
                        vulnerability_type="missing_samesite_cookie",
                        evidence=f"Session cookies without SameSite=Strict/Lax: {', '.join(vulnerable_cookies)}",
                        url=url,
                        form_action=url,
                        severity="medium"
                    )
        
        except Exception as e:
            logger.debug(f"Error checking SameSite: {e}")
        
        return None
    
    async def test_oauth_flow(
        self,
        authorization_url: str,
        client_id: str
    ) -> List[CSRFResult]:
        """
        Test OAuth flow for CSRF vulnerabilities
        
        Args:
            authorization_url: OAuth authorization endpoint
            client_id: OAuth client ID
        
        Returns:
            List of CSRF findings
        """
        results = []
        session = await self._get_session()
        
        try:
            # Build OAuth authorization request
            params = {
                'client_id': client_id,
                'redirect_uri': 'http://localhost/callback',
                'response_type': 'code',
                'scope': 'read'
            }
            
            # Test 1: Missing state parameter
            async with session.get(
                authorization_url,
                params=params,
                allow_redirects=False
            ) as response:
                
                # If server accepts request without state parameter
                if response.status in [200, 302]:
                    location = response.headers.get('Location', '')
                    
                    # Check if 'state' is in response
                    if 'state=' not in location.lower() and 'state' not in params:
                        results.append(CSRFResult(
                            is_vulnerable=True,
                            confidence=0.85,
                            vulnerability_type="oauth_missing_state",
                            evidence="OAuth flow accepts authorization without 'state' parameter",
                            url=authorization_url,
                            form_action=authorization_url,
                            severity="high"
                        ))
            
            # Test 2: Weak state parameter
            weak_states = ['123', 'test', 'state', '1']
            
            for weak_state in weak_states:
                params['state'] = weak_state
                
                async with session.get(
                    authorization_url,
                    params=params,
                    allow_redirects=False
                ) as response:
                    
                    if response.status in [200, 302]:
                        results.append(CSRFResult(
                            is_vulnerable=True,
                            confidence=0.7,
                            vulnerability_type="oauth_weak_state",
                            evidence=f"OAuth accepts weak state parameter: '{weak_state}'",
                            url=authorization_url,
                            form_action=authorization_url,
                            severity="medium"
                        ))
                        break
        
        except Exception as e:
            logger.error(f"Error testing OAuth flow: {e}")
        
        return results
    
    async def test_json_endpoint(
        self,
        url: str,
        method: str = "POST",
        json_data: Dict = None
    ) -> Optional[CSRFResult]:
        """
        Test JSON API endpoint for CSRF protection
        
        Args:
            url: API endpoint URL
            method: HTTP method
            json_data: JSON payload
        
        Returns:
            CSRF result if vulnerable
        """
        if method not in self.STATE_CHANGING_METHODS:
            return None
        
        session = await self._get_session()
        
        try:
            # Test if JSON endpoint accepts requests without CSRF token
            # and with simple content-type that can be sent via form
            
            headers = {
                'Content-Type': 'application/json',
                'Origin': 'http://evil.com',
                'Referer': 'http://evil.com'
            }
            
            test_data = json_data or {'test': 'data'}
            
            async with session.request(
                method,
                url,
                json=test_data,
                headers=headers,
                allow_redirects=False
            ) as response:
                
                # Check if request is accepted
                if response.status not in [403, 400, 401]:
                    # Check if CORS is properly configured
                    cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                    
                    if cors_header == '*' or 'evil.com' in cors_header:
                        return CSRFResult(
                            is_vulnerable=True,
                            confidence=0.8,
                            vulnerability_type="json_csrf",
                            evidence=f"JSON endpoint accepts cross-origin requests (status: {response.status}, CORS: {cors_header})",
                            url=url,
                            form_action=url,
                            severity="high"
                        )
        
        except Exception as e:
            logger.debug(f"Error testing JSON endpoint: {e}")
        
        return None
    
    async def close(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None
