"""
SQL Injection Detector for ARES
Detects SQL injection vulnerabilities using various techniques
"""

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import re
import asyncio
import httpx
from loguru import logger


@dataclass
class SQLiPayload:
    """SQL injection test payload"""
    payload: str
    technique: str  # error-based, boolean-based, time-based, union-based
    expected_behavior: str
    
    
@dataclass
class SQLiResult:
    """Result of SQL injection test"""
    is_vulnerable: bool
    confidence: float  # 0.0 to 1.0
    technique: str
    payload_used: str
    evidence: str
    url: str
    parameter: str


class SQLiDetector:
    """SQL Injection vulnerability detector"""
    
    # Error patterns indicating SQL injection
    ERROR_PATTERNS = [
        r"SQL syntax.*?MySQL",
        r"Warning.*?mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"PostgreSQL.*?ERROR",
        r"Warning.*?pg_.*",
        r"valid PostgreSQL result",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Unclosed quotation mark",
        r"Microsoft SQL Native Client error",
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"SQLiteException",
        r"SQLITE_ERROR",
        r"Oracle error",
        r"Oracle.*?Driver",
        r"ORA-[0-9]+",
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
    
    async def test_parameter(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        original_value: str = ""
    ) -> List[SQLiResult]:
        """
        Test a parameter for SQL injection vulnerabilities
        
        Args:
            url: Target URL
            parameter: Parameter name to test
            method: HTTP method
            original_value: Original parameter value
        
        Returns:
            List of SQLi findings
        """
        results = []
        
        # Get baseline response
        baseline = await self._get_baseline_response(url, parameter, original_value, method)
        
        if not baseline:
            logger.warning(f"Failed to get baseline for {url}?{parameter}")
            return results
        
        # Test different techniques
        error_result = await self._test_error_based(
            url, parameter, method, baseline, original_value
        )
        if error_result:
            results.append(error_result)
        
        boolean_result = await self._test_boolean_based(
            url, parameter, method, baseline, original_value
        )
        if boolean_result:
            results.append(boolean_result)
        
        time_result = await self._test_time_based(
            url, parameter, method, original_value
        )
        if time_result:
            results.append(time_result)
        
        return results
    
    async def _get_baseline_response(
        self,
        url: str,
        parameter: str,
        value: str,
        method: str
    ) -> Optional[Dict]:
        """Get baseline response for comparison"""
        try:
            if method.upper() == "GET":
                response = await self.client.get(url, params={parameter: value})
            else:
                response = await self.client.post(url, data={parameter: value})
            
            return {
                'status_code': response.status_code,
                'content': response.text,
                'length': len(response.text),
                'time': response.elapsed.total_seconds()
            }
        except Exception as e:
            logger.error(f"Baseline request failed: {e}")
            return None
    
    async def _test_error_based(
        self,
        url: str,
        parameter: str,
        method: str,
        baseline: Dict,
        original_value: str
    ) -> Optional[SQLiResult]:
        """Test for error-based SQL injection"""
        
        error_payloads = [
            SQLiPayload("'", "error-based", "SQL error message"),
            SQLiPayload("\"", "error-based", "SQL error message"),
            SQLiPayload("' OR '1'='1", "error-based", "SQL error or different response"),
            SQLiPayload("1' AND '1'='2", "error-based", "SQL error"),
            SQLiPayload("1' UNION SELECT NULL--", "error-based", "SQL error about columns"),
        ]
        
        for payload_obj in error_payloads:
            try:
                test_value = original_value + payload_obj.payload
                
                if method.upper() == "GET":
                    response = await self.client.get(url, params={parameter: test_value})
                else:
                    response = await self.client.post(url, data={parameter: test_value})
                
                content = response.text
                
                # Check for SQL error patterns
                for pattern in self.ERROR_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        logger.info(f"Found SQLi via error-based: {url}?{parameter}")
                        return SQLiResult(
                            is_vulnerable=True,
                            confidence=0.9,
                            technique="error-based",
                            payload_used=payload_obj.payload,
                            evidence=f"SQL error pattern matched: {pattern}",
                            url=url,
                            parameter=parameter
                        )
                
            except Exception as e:
                logger.debug(f"Error-based test failed: {e}")
        
        return None
    
    async def _test_boolean_based(
        self,
        url: str,
        parameter: str,
        method: str,
        baseline: Dict,
        original_value: str
    ) -> Optional[SQLiResult]:
        """Test for boolean-based blind SQL injection"""
        
        # True condition payloads
        true_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "1' AND '1'='1",
        ]
        
        # False condition payloads
        false_payloads = [
            "' OR '1'='2",
            "' OR 1=2--",
            "1' AND '1'='2",
        ]
        
        true_responses = []
        false_responses = []
        
        # Test true conditions
        for payload in true_payloads:
            try:
                test_value = original_value + payload
                
                if method.upper() == "GET":
                    response = await self.client.get(url, params={parameter: test_value})
                else:
                    response = await self.client.post(url, data={parameter: test_value})
                
                true_responses.append({
                    'length': len(response.text),
                    'status': response.status_code,
                    'payload': payload
                })
                
            except Exception as e:
                logger.debug(f"Boolean true test failed: {e}")
        
        # Test false conditions
        for payload in false_payloads:
            try:
                test_value = original_value + payload
                
                if method.upper() == "GET":
                    response = await self.client.get(url, params={parameter: test_value})
                else:
                    response = await self.client.post(url, data={parameter: test_value})
                
                false_responses.append({
                    'length': len(response.text),
                    'status': response.status_code,
                    'payload': payload
                })
                
            except Exception as e:
                logger.debug(f"Boolean false test failed: {e}")
        
        # Compare responses
        if true_responses and false_responses:
            # Check if true conditions consistently return different results than false
            true_lengths = [r['length'] for r in true_responses]
            false_lengths = [r['length'] for r in false_responses]
            
            # If true and false responses are consistently different
            if (all(t > max(false_lengths) for t in true_lengths) or
                all(t < min(false_lengths) for t in true_lengths)):
                
                logger.info(f"Found SQLi via boolean-based: {url}?{parameter}")
                return SQLiResult(
                    is_vulnerable=True,
                    confidence=0.7,
                    technique="boolean-based",
                    payload_used=true_responses[0]['payload'],
                    evidence=f"True/False responses differ consistently: {true_lengths} vs {false_lengths}",
                    url=url,
                    parameter=parameter
                )
        
        return None
    
    async def _test_time_based(
        self,
        url: str,
        parameter: str,
        method: str,
        original_value: str
    ) -> Optional[SQLiResult]:
        """Test for time-based blind SQL injection"""
        
        time_payloads = [
            SQLiPayload(
                "'; WAITFOR DELAY '00:00:05'--",
                "time-based",
                "5 second delay (MSSQL)"
            ),
            SQLiPayload(
                "' AND SLEEP(5)--",
                "time-based",
                "5 second delay (MySQL)"
            ),
            SQLiPayload(
                "' AND pg_sleep(5)--",
                "time-based",
                "5 second delay (PostgreSQL)"
            ),
        ]
        
        for payload_obj in time_payloads:
            try:
                test_value = original_value + payload_obj.payload
                
                start_time = asyncio.get_event_loop().time()
                
                if method.upper() == "GET":
                    response = await self.client.get(url, params={parameter: test_value})
                else:
                    response = await self.client.post(url, data={parameter: test_value})
                
                elapsed = asyncio.get_event_loop().time() - start_time
                
                # If response took significantly longer (at least 4 seconds for a 5 second delay)
                if elapsed >= 4.0:
                    logger.info(f"Found SQLi via time-based: {url}?{parameter}")
                    return SQLiResult(
                        is_vulnerable=True,
                        confidence=0.8,
                        technique="time-based",
                        payload_used=payload_obj.payload,
                        evidence=f"Response delayed by {elapsed:.2f} seconds",
                        url=url,
                        parameter=parameter
                    )
                
            except asyncio.TimeoutError:
                # Timeout might indicate successful time-based SQLi
                logger.info(f"Possible time-based SQLi (timeout): {url}?{parameter}")
                return SQLiResult(
                    is_vulnerable=True,
                    confidence=0.6,
                    technique="time-based",
                    payload_used=payload_obj.payload,
                    evidence="Request timed out, indicating possible time delay",
                    url=url,
                    parameter=parameter
                )
            except Exception as e:
                logger.debug(f"Time-based test failed: {e}")
        
        return None
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()
