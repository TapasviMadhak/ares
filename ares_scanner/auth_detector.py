"""
Authentication & Authorization Detector for ARES
Detects authentication flaws, session issues, and access control vulnerabilities
"""

from typing import List, Dict, Optional, Set
from dataclasses import dataclass
import re
import jwt
import hashlib
import asyncio
from urllib.parse import urlparse, parse_qs
import aiohttp
from loguru import logger


@dataclass
class AuthResult:
    """Result of authentication vulnerability test"""
    is_vulnerable: bool
    confidence: float
    vulnerability_type: str
    evidence: str
    url: str
    severity: str
    remediation: str


class AuthDetector:
    """Authentication and authorization vulnerability detector"""
    
    # Common weak passwords
    WEAK_PASSWORDS = [
        'password', 'Password123', '123456', 'admin', 'test',
        'qwerty', 'letmein', 'welcome', 'monkey', '1234'
    ]
    
    # Common admin paths
    ADMIN_PATHS = [
        '/admin', '/admin/', '/administrator', '/admin/dashboard',
        '/wp-admin', '/phpmyadmin', '/admin.php', '/admin/login',
        '/backend', '/panel', '/console', '/manager'
    ]
    
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
    
    async def test_weak_password_policy(
        self,
        url: str,
        username_field: str = "username",
        password_field: str = "password",
        method: str = "POST"
    ) -> List[AuthResult]:
        """
        Test for weak password policy
        
        Args:
            url: Login/registration endpoint
            username_field: Username field name
            password_field: Password field name
            method: HTTP method
        
        Returns:
            List of findings
        """
        results = []
        session = await self._get_session()
        
        # Test common weak passwords
        for weak_password in self.WEAK_PASSWORDS[:5]:  # Test first 5
            try:
                test_username = f"testuser_{weak_password}"
                
                data = {
                    username_field: test_username,
                    password_field: weak_password
                }
                
                async with session.request(
                    method,
                    url,
                    data=data,
                    allow_redirects=False
                ) as response:
                    content = await response.text()
                    status = response.status
                
                # Check if weak password was accepted
                # Look for success indicators
                if self._indicates_success(content, status):
                    results.append(AuthResult(
                        is_vulnerable=True,
                        confidence=0.8,
                        vulnerability_type="weak_password_accepted",
                        evidence=f"Weak password '{weak_password}' accepted during registration/login",
                        url=url,
                        severity="medium",
                        remediation="Implement strong password policy (min length, complexity requirements)"
                    ))
                    break
            
            except Exception as e:
                logger.debug(f"Weak password test failed: {e}")
        
        # Test very short password
        try:
            data = {
                username_field: "testuser123",
                password_field: "12"  # 2 characters
            }
            
            async with session.request(
                method,
                url,
                data=data,
                allow_redirects=False
            ) as response:
                content = await response.text()
                status = response.status
            
            if self._indicates_success(content, status):
                results.append(AuthResult(
                    is_vulnerable=True,
                    confidence=0.85,
                    vulnerability_type="no_password_length_requirement",
                    evidence="System accepts very short passwords (2 characters)",
                    url=url,
                    severity="medium",
                    remediation="Enforce minimum password length (8-12 characters)"
                ))
        
        except Exception as e:
            logger.debug(f"Short password test failed: {e}")
        
        return results
    
    def _indicates_success(self, content: str, status: int) -> bool:
        """Check if response indicates successful operation"""
        
        success_indicators = [
            'success', 'welcome', 'dashboard', 'logged in',
            'registration complete', 'account created'
        ]
        
        error_indicators = [
            'error', 'invalid', 'failed', 'incorrect',
            'too short', 'too weak', 'must contain'
        ]
        
        content_lower = content.lower()
        
        # Check for error indicators first
        if any(indicator in content_lower for indicator in error_indicators):
            return False
        
        # Check for success indicators
        if status in [200, 201, 302] and any(indicator in content_lower for indicator in success_indicators):
            return True
        
        # Redirect might indicate success
        if status == 302:
            return True
        
        return False
    
    async def test_session_fixation(
        self,
        login_url: str,
        username_field: str = "username",
        password_field: str = "password",
        test_credentials: Dict[str, str] = None
    ) -> Optional[AuthResult]:
        """
        Test for session fixation vulnerability
        
        Args:
            login_url: Login endpoint
            username_field: Username field name
            password_field: Password field name
            test_credentials: Valid test credentials
        
        Returns:
            Auth result if vulnerable
        """
        if not test_credentials:
            logger.debug("Session fixation test requires valid credentials")
            return None
        
        session = await self._get_session()
        
        try:
            # Step 1: Get session before login
            async with session.get(login_url) as response:
                cookies_before = response.cookies
                session_cookie_before = self._get_session_cookie(cookies_before)
            
            if not session_cookie_before:
                logger.debug("No session cookie found before login")
                return None
            
            # Step 2: Login with credentials
            data = {
                username_field: test_credentials.get('username'),
                password_field: test_credentials.get('password')
            }
            
            async with session.post(login_url, data=data) as response:
                cookies_after = response.cookies
                session_cookie_after = self._get_session_cookie(cookies_after)
            
            # Step 3: Check if session ID changed
            if session_cookie_before and session_cookie_after:
                if session_cookie_before == session_cookie_after:
                    return AuthResult(
                        is_vulnerable=True,
                        confidence=0.9,
                        vulnerability_type="session_fixation",
                        evidence="Session ID not regenerated after authentication",
                        url=login_url,
                        severity="high",
                        remediation="Regenerate session ID after successful authentication"
                    )
        
        except Exception as e:
            logger.debug(f"Session fixation test failed: {e}")
        
        return None
    
    def _get_session_cookie(self, cookies) -> Optional[str]:
        """Extract session cookie value"""
        
        session_cookie_names = [
            'sessionid', 'session', 'jsessionid', 'phpsessid',
            'asp.net_sessionid', 'sid', 'connect.sid'
        ]
        
        for cookie_name in cookies:
            if cookie_name.lower() in session_cookie_names:
                return str(cookies[cookie_name])
        
        return None
    
    async def test_jwt_vulnerabilities(
        self,
        url: str,
        jwt_token: str = None
    ) -> List[AuthResult]:
        """
        Test for JWT security issues
        
        Args:
            url: Protected endpoint that uses JWT
            jwt_token: JWT token to test
        
        Returns:
            List of JWT vulnerabilities
        """
        results = []
        session = await self._get_session()
        
        if not jwt_token:
            # Try to get JWT from response
            try:
                async with session.get(url) as response:
                    # Check Authorization header or cookies
                    auth_header = response.headers.get('Authorization', '')
                    if 'Bearer' in auth_header:
                        jwt_token = auth_header.replace('Bearer ', '').strip()
            except Exception:
                pass
        
        if not jwt_token:
            logger.debug("No JWT token available for testing")
            return results
        
        # Test 1: Algorithm confusion (alg: none)
        none_result = await self._test_jwt_alg_none(url, jwt_token, session)
        if none_result:
            results.append(none_result)
        
        # Test 2: Weak secret
        weak_secret_result = await self._test_jwt_weak_secret(url, jwt_token, session)
        if weak_secret_result:
            results.append(weak_secret_result)
        
        # Test 3: Missing signature verification
        no_sig_result = await self._test_jwt_no_signature(url, jwt_token, session)
        if no_sig_result:
            results.append(no_sig_result)
        
        # Test 4: Token expiration not enforced
        expired_result = await self._test_jwt_expiration(url, jwt_token, session)
        if expired_result:
            results.append(expired_result)
        
        return results
    
    async def _test_jwt_alg_none(
        self,
        url: str,
        jwt_token: str,
        session: aiohttp.ClientSession
    ) -> Optional[AuthResult]:
        """Test for JWT alg:none vulnerability"""
        
        try:
            # Decode JWT without verification
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode header and payload
            import base64
            import json
            
            header = json.loads(base64.b64decode(parts[0] + '=='))
            payload = json.loads(base64.b64decode(parts[1] + '=='))
            
            # Modify header to use alg: none
            header['alg'] = 'none'
            
            # Create new token with no signature
            new_header = base64.b64encode(
                json.dumps(header).encode()
            ).decode().rstrip('=')
            
            new_payload = base64.b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')
            
            # Token with alg:none should have empty signature
            modified_token = f"{new_header}.{new_payload}."
            
            # Test if server accepts it
            headers = {'Authorization': f'Bearer {modified_token}'}
            
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    return AuthResult(
                        is_vulnerable=True,
                        confidence=0.95,
                        vulnerability_type="jwt_alg_none",
                        evidence="Server accepts JWT with 'alg: none' (no signature)",
                        url=url,
                        severity="critical",
                        remediation="Explicitly reject tokens with 'alg: none' algorithm"
                    )
        
        except Exception as e:
            logger.debug(f"JWT alg:none test failed: {e}")
        
        return None
    
    async def _test_jwt_weak_secret(
        self,
        url: str,
        jwt_token: str,
        session: aiohttp.ClientSession
    ) -> Optional[AuthResult]:
        """Test for weak JWT signing secret"""
        
        weak_secrets = [
            'secret', 'key', 'password', '123456',
            'jwt_secret', 'mysecret', 'changeme'
        ]
        
        try:
            # Try to decode with weak secrets
            for secret in weak_secrets:
                try:
                    decoded = jwt.decode(
                        jwt_token,
                        secret,
                        algorithms=['HS256', 'HS512']
                    )
                    
                    # Successfully decoded with weak secret
                    return AuthResult(
                        is_vulnerable=True,
                        confidence=1.0,
                        vulnerability_type="jwt_weak_secret",
                        evidence=f"JWT signed with weak secret: '{secret}'",
                        url=url,
                        severity="critical",
                        remediation="Use strong, random secret key (256+ bits) for JWT signing"
                    )
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
        
        except Exception as e:
            logger.debug(f"JWT weak secret test failed: {e}")
        
        return None
    
    async def _test_jwt_no_signature(
        self,
        url: str,
        jwt_token: str,
        session: aiohttp.ClientSession
    ) -> Optional[AuthResult]:
        """Test if server validates JWT signature"""
        
        try:
            # Modify token payload without updating signature
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return None
            
            import base64
            import json
            
            # Decode and modify payload
            payload = json.loads(base64.b64decode(parts[1] + '=='))
            
            # Add or modify a claim
            payload['admin'] = True
            payload['role'] = 'administrator'
            
            # Encode modified payload
            new_payload = base64.b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')
            
            # Keep original header and signature
            modified_token = f"{parts[0]}.{new_payload}.{parts[2]}"
            
            # Test if server accepts modified token
            headers = {'Authorization': f'Bearer {modified_token}'}
            
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    return AuthResult(
                        is_vulnerable=True,
                        confidence=0.9,
                        vulnerability_type="jwt_no_signature_verification",
                        evidence="Server accepts modified JWT without signature verification",
                        url=url,
                        severity="critical",
                        remediation="Always verify JWT signature before trusting claims"
                    )
        
        except Exception as e:
            logger.debug(f"JWT signature test failed: {e}")
        
        return None
    
    async def _test_jwt_expiration(
        self,
        url: str,
        jwt_token: str,
        session: aiohttp.ClientSession
    ) -> Optional[AuthResult]:
        """Test if JWT expiration is enforced"""
        
        try:
            # Decode token without verification
            import base64
            import json
            
            parts = jwt_token.split('.')
            payload = json.loads(base64.b64decode(parts[1] + '=='))
            
            # Check if token has exp claim
            if 'exp' not in payload:
                return AuthResult(
                    is_vulnerable=True,
                    confidence=0.7,
                    vulnerability_type="jwt_no_expiration",
                    evidence="JWT does not include expiration claim (exp)",
                    url=url,
                    severity="medium",
                    remediation="Include 'exp' claim in JWT with reasonable expiration time"
                )
            
            # If token has exp, we could test if server enforces it
            # by modifying exp to past time, but that requires re-signing
            
        except Exception as e:
            logger.debug(f"JWT expiration test failed: {e}")
        
        return None
    
    async def test_broken_access_control(
        self,
        url: str,
        authenticated_cookie: Dict[str, str] = None
    ) -> List[AuthResult]:
        """
        Test for broken access control (IDOR, privilege escalation)
        
        Args:
            url: URL to test (e.g., /api/user/123)
            authenticated_cookie: Valid session cookie
        
        Returns:
            List of access control findings
        """
        results = []
        session = await self._get_session()
        
        # Test 1: Unauthenticated access
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Check if sensitive data is exposed
                    if self._contains_sensitive_data(content):
                        results.append(AuthResult(
                            is_vulnerable=True,
                            confidence=0.9,
                            vulnerability_type="missing_authentication",
                            evidence="Protected resource accessible without authentication",
                            url=url,
                            severity="high",
                            remediation="Require authentication for protected resources"
                        ))
        except Exception as e:
            logger.debug(f"Unauthenticated access test failed: {e}")
        
        # Test 2: IDOR (Insecure Direct Object Reference)
        idor_result = await self._test_idor(url, authenticated_cookie, session)
        if idor_result:
            results.append(idor_result)
        
        # Test 3: Parameter manipulation
        param_result = await self._test_parameter_manipulation(url, authenticated_cookie, session)
        if param_result:
            results.append(param_result)
        
        return results
    
    def _contains_sensitive_data(self, content: str) -> bool:
        """Check if content contains sensitive data"""
        
        sensitive_patterns = [
            r'password',
            r'email.*@',
            r'credit.*card',
            r'ssn',
            r'api.*key',
            r'secret',
            r'token',
            r'"id"\s*:\s*\d+',
            r'"user"',
            r'"admin"'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    async def _test_idor(
        self,
        url: str,
        authenticated_cookie: Dict[str, str],
        session: aiohttp.ClientSession
    ) -> Optional[AuthResult]:
        """Test for Insecure Direct Object Reference"""
        
        try:
            # Extract ID from URL
            id_match = re.search(r'/(\d+)/?', url)
            if not id_match:
                return None
            
            current_id = int(id_match.group(1))
            
            # Try accessing other user's resource
            test_ids = [current_id - 1, current_id + 1, 1, 999]
            
            for test_id in test_ids:
                if test_id == current_id:
                    continue
                
                test_url = url.replace(str(current_id), str(test_id))
                
                cookies = authenticated_cookie if authenticated_cookie else {}
                
                async with session.get(test_url, cookies=cookies) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # If we get different data, it's IDOR
                        if len(content) > 100 and self._contains_sensitive_data(content):
                            return AuthResult(
                                is_vulnerable=True,
                                confidence=0.85,
                                vulnerability_type="idor",
                                evidence=f"Can access other users' data by changing ID ({current_id} -> {test_id})",
                                url=url,
                                severity="high",
                                remediation="Implement proper authorization checks for resource access"
                            )
        
        except Exception as e:
            logger.debug(f"IDOR test failed: {e}")
        
        return None
    
    async def _test_parameter_manipulation(
        self,
        url: str,
        authenticated_cookie: Dict[str, str],
        session: aiohttp.ClientSession
    ) -> Optional[AuthResult]:
        """Test for privilege escalation via parameter manipulation"""
        
        try:
            # Test adding admin/role parameters
            privilege_params = [
                {'admin': 'true'},
                {'admin': '1'},
                {'role': 'admin'},
                {'role': 'administrator'},
                {'isAdmin': 'true'},
                {'privilege': 'admin'}
            ]
            
            cookies = authenticated_cookie if authenticated_cookie else {}
            
            for params in privilege_params:
                async with session.get(url, params=params, cookies=cookies) as response:
                    content = await response.text()
                    
                    # Check for admin indicators
                    admin_indicators = [
                        'admin panel', 'administrator', 'manage users',
                        'delete user', 'system settings'
                    ]
                    
                    if any(indicator in content.lower() for indicator in admin_indicators):
                        return AuthResult(
                            is_vulnerable=True,
                            confidence=0.75,
                            vulnerability_type="privilege_escalation_param",
                            evidence=f"Privilege escalation via parameter manipulation: {params}",
                            url=url,
                            severity="critical",
                            remediation="Validate user privileges server-side, not via client parameters"
                        )
        
        except Exception as e:
            logger.debug(f"Parameter manipulation test failed: {e}")
        
        return None
    
    async def test_oauth_misconfiguration(
        self,
        authorization_url: str,
        client_id: str,
        redirect_uri: str = None
    ) -> List[AuthResult]:
        """
        Test for OAuth misconfigurations
        
        Args:
            authorization_url: OAuth authorization endpoint
            client_id: OAuth client ID
            redirect_uri: Registered redirect URI
        
        Returns:
            List of OAuth vulnerabilities
        """
        results = []
        session = await self._get_session()
        
        # Test 1: Open redirect via redirect_uri
        if redirect_uri:
            malicious_redirects = [
                'http://evil.com',
                redirect_uri + '@evil.com',
                redirect_uri + '.evil.com',
                'http://evil.com@' + redirect_uri,
            ]
            
            for malicious_uri in malicious_redirects:
                try:
                    params = {
                        'client_id': client_id,
                        'redirect_uri': malicious_uri,
                        'response_type': 'code',
                        'state': 'test123'
                    }
                    
                    async with session.get(
                        authorization_url,
                        params=params,
                        allow_redirects=False
                    ) as response:
                        location = response.headers.get('Location', '')
                        
                        if 'evil.com' in location:
                            results.append(AuthResult(
                                is_vulnerable=True,
                                confidence=0.9,
                                vulnerability_type="oauth_open_redirect",
                                evidence=f"OAuth accepts unregistered redirect_uri: {malicious_uri}",
                                url=authorization_url,
                                severity="high",
                                remediation="Strictly validate redirect_uri against registered URIs"
                            ))
                            break
                
                except Exception as e:
                    logger.debug(f"OAuth redirect test failed: {e}")
        
        return results
    
    async def close(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None
