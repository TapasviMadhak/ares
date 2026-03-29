"""
Enhanced ARES Scan Workflow
Integrates Hexstrike-AI and Ollama for comprehensive scanning

Workflow:
1. Discovery Phase - Use Hexstrike to crawl and discover the website
2. Analysis Phase - Use Ollama to understand the application structure
3. Testing Phase - Use Hexstrike tools + custom scanners to test vulnerabilities
4. Validation Phase - Use Ollama to validate and prioritize findings
"""

import asyncio
from typing import Dict, List, Any, Optional
from loguru import logger
import httpx

from ares_mcp.hexstrike_client import HexstrikeClient
from ares_core.ollama_client import get_ollama_client
from ares_scanner.crawler import WebCrawler
from ares_scanner.xss_detector import XSSDetector


class IntegratedScanner:
    """
    Enhanced scanner that coordinates Hexstrike-AI and Ollama
    """
    
    def __init__(self, target_url: str, scan_id: str):
        self.target_url = target_url
        self.scan_id = scan_id
        self.hexstrike = None
        self.ollama = get_ollama_client()
        self.vulnerabilities = []
        
    async def run_full_scan(self) -> Dict[str, Any]:
        """
        Execute comprehensive scan using all available tools
        
        Returns:
            Scan results with discovered vulnerabilities
        """
        logger.info(f"🚀 Starting integrated scan on {self.target_url}")
        
        results = {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "phase": "starting",
            "vulnerabilities": [],
            "endpoints_discovered": 0,
            "forms_discovered": 0,
            "ollama_analysis": None,
            "hexstrike_tools_used": []
        }
        
        try:
            # Phase 1: Discovery with Hexstrike
            logger.info("📡 Phase 1: Discovery")
            results["phase"] = "discovery"
            
            discovery_results = await self._discovery_phase()
            results["endpoints_discovered"] = discovery_results.get("endpoints_count", 0)
            results["forms_discovered"] = discovery_results.get("forms_count", 0)
            
            # Phase 2: Analysis with Ollama
            logger.info("🧠 Phase 2: AI Analysis")
            results["phase"] = "analysis"
            
            analysis = await self._analysis_phase(discovery_results)
            results["ollama_analysis"] = analysis
            
            # Phase 3: Vulnerability Testing
            logger.info("🎯 Phase 3: Vulnerability Testing")
            results["phase"] = "testing"
            
            vulns = await self._testing_phase(discovery_results, analysis)
            results["vulnerabilities"] = vulns
            
            # Phase 4: Validation with Ollama
            logger.info("✅ Phase 4: Validation")
            results["phase"] = "validation"
            
            validated_vulns = await self._validation_phase(vulns)
            results["vulnerabilities"] = validated_vulns
            
            results["phase"] = "completed"
            logger.success(f"✅ Scan complete: Found {len(validated_vulns)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            results["phase"] = "failed"
            results["error"] = str(e)
        
        return results
    
    async def _discovery_phase(self) -> Dict[str, Any]:
        """
        Phase 1: Discover website structure using Hexstrike and crawler
        """
        results = {
            "endpoints": [],
            "forms": [],
            "endpoints_count": 0,
            "forms_count": 0,
            "technologies": []
        }
        
        try:
            # Initialize Hexstrike client
            async with HexstrikeClient() as hexstrike:
                # Check if Hexstrike is available
                if await hexstrike.health_check():
                    logger.info("✓ Hexstrike-AI connected")
                    
                    # Use Hexstrike web crawler
                    try:
                        crawler_result = await hexstrike.execute_tool(
                            "web_crawler",
                            {
                                "target": self.target_url,
                                "depth": 3,
                                "max_pages": 50
                            },
                            timeout_override=120
                        )
                        
                        if crawler_result.get("success"):
                            output = crawler_result.get("output", {})
                            if isinstance(output, dict):
                                results["endpoints"] = output.get("urls", [])
                                results["forms"] = output.get("forms", [])
                            logger.info(f"Hexstrike discovered {len(results['endpoints'])} endpoints")
                    
                    except Exception as e:
                        logger.warning(f"Hexstrike crawler unavailable: {e}")
            
            # Fallback: Use local crawler if Hexstrike didn't find anything
            if not results["endpoints"]:
                logger.info("Using local WebCrawler as fallback")
                crawler = WebCrawler(
                    target_url=self.target_url,
                    max_depth=2,
                    max_pages=30
                )
                
                endpoints = await crawler.crawl()
                results["endpoints"] = [
                    {
                        "url": ep.url,
                        "method": ep.method,
                        "parameters": ep.parameters,
                        "forms": ep.forms
                    }
                    for ep in endpoints
                ]
                
                # Extract forms
                for ep in endpoints:
                    if ep.forms:
                        results["forms"].extend(ep.forms)
            
            results["endpoints_count"] = len(results["endpoints"])
            results["forms_count"] = len(results["forms"])
            
            logger.info(f"📊 Discovery complete: {results['endpoints_count']} endpoints, {results['forms_count']} forms")
            
        except Exception as e:
            logger.error(f"Discovery phase error: {e}")
        
        return results
    
    async def _analysis_phase(self, discovery_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Phase 2: Analyze discovered data with Ollama
        """
        analysis = {
            "attack_surface": "",
            "recommended_tests": [],
            "priority_targets": [],
            "technologies_detected": []
        }
        
        try:
            # Prepare context for Ollama
            context = f"""
You are analyzing a web application scan target: {self.target_url}

Discovery Results:
- Endpoints found: {discovery_data.get('endpoints_count', 0)}
- Forms found: {discovery_data.get('forms_count', 0)}

Sample endpoints:
{discovery_data.get('endpoints', [])[:5]}

Sample forms:
{discovery_data.get('forms', [])[:3]}

Based on this information, provide:
1. Assessment of the attack surface
2. Recommended vulnerability tests to prioritize
3. Priority targets (specific URLs or forms)
4. Any detected technologies or frameworks

Keep response concise and actionable.
"""
            
            response = await self.ollama.generate(
                model="llama3.2:3b",
                prompt=context,
                system="You are a security expert analyzing web applications for vulnerabilities."
            )
            
            if response:
                analysis_text = response.get("response", "")
                analysis["attack_surface"] = analysis_text
                
                # Parse recommendations from response
                if "xss" in analysis_text.lower() or "cross-site" in analysis_text.lower():
                    analysis["recommended_tests"].append("xss")
                if "sql" in analysis_text.lower() or "injection" in analysis_text.lower():
                    analysis["recommended_tests"].append("sqli")
                if "csrf" in analysis_text.lower():
                    analysis["recommended_tests"].append("csrf")
                if "xxe" in analysis_text.lower():
                    analysis["recommended_tests"].append("xxe")
                
                # Extract priority targets (forms with inputs)
                for form in discovery_data.get("forms", []):
                    if form.get("inputs"):
                        analysis["priority_targets"].append(form.get("action", ""))
                
                logger.info(f"🧠 Ollama recommends testing: {', '.join(analysis['recommended_tests'])}")
            
        except Exception as e:
            logger.error(f"Analysis phase error: {e}")
        
        return analysis
    
    async def _testing_phase(
        self,
        discovery_data: Dict[str, Any],
        analysis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Phase 3: Test for vulnerabilities using recommended tests
        """
        vulnerabilities = []
        
        recommended_tests = analysis.get("recommended_tests", ["xss", "sqli", "csrf"])
        
        # Test XSS on forms
        if "xss" in recommended_tests:
            logger.info("Testing for XSS vulnerabilities...")
            xss_vulns = await self._test_xss(discovery_data)
            vulnerabilities.extend(xss_vulns)
        
        # Test SQLi on endpoints
        if "sqli" in recommended_tests:
            logger.info("Testing for SQL injection...")
            sqli_vulns = await self._test_sqli(discovery_data)
            vulnerabilities.extend(sqli_vulns)
        
        # Use Hexstrike for additional scans if available
        try:
            async with HexstrikeClient() as hexstrike:
                if await hexstrike.health_check():
                    # Try Hexstrike's built-in XSS scanner
                    for form in discovery_data.get("forms", [])[:5]:  # Limit to first 5 forms
                        try:
                            result = await hexstrike.execute_tool(
                                "xss_scanner",
                                {
                                    "url": form.get("action", self.target_url),
                                    "method": form.get("method", "POST"),
                                    "parameters": {inp.get("name"): "test" for inp in form.get("inputs", [])}
                                },
                                timeout_override=60
                            )
                            
                            if result.get("success") and "vulnerable" in result.get("output", "").lower():
                                vulnerabilities.append({
                                    "type": "Cross-Site Scripting (XSS)",
                                    "severity": "high",
                                    "url": form.get("action", self.target_url),
                                    "evidence": "Hexstrike XSS scanner detected vulnerability",
                                    "tool": "hexstrike"
                                })
                        except Exception as e:
                            logger.debug(f"Hexstrike XSS scan error: {e}")
        
        except Exception as e:
            logger.debug(f"Hexstrike not available for testing: {e}")
        
        return vulnerabilities
    
    async def _test_xss(self, discovery_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            xss_detector = XSSDetector(timeout=15)
            
            # Test forms
            for form in discovery_data.get("forms", [])[:10]:  # Limit to first 10 forms
                for input_field in form.get("inputs", []):
                    param_name = input_field.get("name", "")
                    if param_name:
                        try:
                            results = await xss_detector.test_parameter(
                                url=form.get("action", self.target_url),
                                parameter=param_name,
                                method=form.get("method", "POST")
                            )
                            
                            for result in results:
                                if result.is_vulnerable:
                                    vulnerabilities.append({
                                        "type": "Cross-Site Scripting (XSS)",
                                        "severity": "high" if result.confidence > 0.7 else "medium",
                                        "url": result.url,
                                        "parameter": result.parameter,
                                        "payload": result.payload_used,
                                        "evidence": result.evidence,
                                        "confidence": result.confidence,
                                        "tool": "xss_detector"
                                    })
                        except Exception as e:
                            logger.debug(f"XSS test error for {param_name}: {e}")
            
            # Also test URL parameters from endpoints
            for endpoint in discovery_data.get("endpoints", [])[:10]:
                for param in endpoint.get("parameters", {}).keys():
                    try:
                        results = await xss_detector.test_parameter(
                            url=endpoint["url"],
                            parameter=param,
                            method="GET"
                        )
                        
                        for result in results:
                            if result.is_vulnerable:
                                vulnerabilities.append({
                                    "type": "Cross-Site Scripting (XSS)",
                                    "severity": "high" if result.confidence > 0.7 else "medium",
                                    "url": result.url,
                                    "parameter": result.parameter,
                                    "payload": result.payload_used,
                                    "evidence": result.evidence,
                                    "confidence": result.confidence,
                                    "tool": "xss_detector"
                                })
                    except Exception as e:
                        logger.debug(f"XSS test error for {param}: {e}")
            
            await xss_detector.client.aclose()
        
        except Exception as e:
            logger.error(f"XSS testing error: {e}")
        
        return vulnerabilities
    
    async def _test_sqli(self, discovery_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        sqli_payloads = ["'", "1' OR '1'='1", "' OR '1'='1' --", "1' AND '1'='2"]
        
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                # Test URL parameters
                for endpoint in discovery_data.get("endpoints", [])[:10]:
                    for param in endpoint.get("parameters", {}).keys():
                        for payload in sqli_payloads:
                            try:
                                test_url = f"{endpoint['url']}?{param}={payload}"
                                response = await client.get(test_url)
                                text = response.text.lower()
                                
                                # Check for SQL errors
                                error_keywords = [
                                    'sql', 'mysql', 'mysqli', 'syntax error',
                                    'query failed', 'database error', 'sqlstate',
                                    'warning: mysql', 'error in your sql'
                                ]
                                
                                if any(kw in text for kw in error_keywords):
                                    vulnerabilities.append({
                                        "type": "SQL Injection",
                                        "severity": "critical",
                                        "url": test_url,
                                        "parameter": param,
                                        "payload": payload,
                                        "evidence": f"SQL error detected with payload: {payload}",
                                        "tool": "sqli_detector"
                                    })
                                    break  # One positive is enough per parameter
                            except Exception as e:
                                logger.debug(f"SQLi test error: {e}")
        
        except Exception as e:
            logger.error(f"SQLi testing error: {e}")
        
        return vulnerabilities
    
    async def _validation_phase(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Phase 4: Validate findings with Ollama and prioritize
        """
        if not vulnerabilities:
            return []
        
        try:
            # Ask Ollama to validate and prioritize findings
            context = f"""
You discovered the following vulnerabilities in {self.target_url}:

{vulnerabilities[:10]}  # Limit to first 10 for context

Please:
1. Validate these findings (are they likely true positives?)
2. Prioritize by criticality
3. Suggest exploitation steps for the most critical ones

Be concise.
"""
            
            response = await self.ollama.generate(
                model="llama3.2:3b",
                prompt=context,
                system="You are a security expert validating vulnerability findings."
            )
            
            if response:
                validation_text = response.get("response", "")
                # Add validation notes to each vulnerability
                for vuln in vulnerabilities:
                    vuln["ollama_validation"] = validation_text[:200]  # Truncate
        
        except Exception as e:
            logger.error(f"Validation phase error: {e}")
        
        return vulnerabilities


async def run_integrated_scan(scan_id: str, target_url: str) -> Dict[str, Any]:
    """
    Main entry point for integrated scanning
    
    Args:
        scan_id: Unique scan identifier
        target_url: Target URL to scan
        
    Returns:
        Complete scan results
    """
    scanner = IntegratedScanner(target_url, scan_id)
    return await scanner.run_full_scan()
