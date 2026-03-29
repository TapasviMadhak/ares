"""
ARES Architecture Integration Layer

This module coordinates the different components:
- Ollama: Reasoning engine for vulnerability analysis and strategic decisions  
- Hexstrike-AI: Payload generation and tool execution (150+ security tools)
- Burp Suite: Web proxy and advanced HTTP testing
- Browser: JavaScript execution and dynamic page interaction
"""

from typing import Dict, List, Optional, Any
from loguru import logger
import asyncio
from datetime import datetime

from ares_core.config import settings
from ares_core.ollama_client import get_ollama_client
from ares_core.ai_decision_maker import AIDecisionMaker


class ARESOrchestrator:
    """
    Main orchestrator coordinating all ARES components.
    
    Architecture:
    1. Ollama (LLM): Reasoning and vulnerability analysis
       - Identifies complex logical flaws
       - Analyzes business logic vulnerabilities
       - Makes strategic decisions
       - Prioritizes attack vectors
    
    2. Hexstrike-AI (MCP): Payload generation and execution
       - Generates exploitation payloads
       - Executes 150+ security tools
       - Fuzzing and brute-forcing
       - Tool chaining
    
    3. Burp Suite: HTTP proxy and advanced testing
       - Intercepts and modifies traffic
       - Session handling
       - Scanner integration
       - Collaboration features
    
    4. Browser Control: Dynamic page testing
       - JavaScript execution
       - XSS validation
       - CSRF testing
       - Client-side vulnerability discovery
    """
    
    def __init__(self, scan_id: str, target_url: str):
        """
        Initialize ARES orchestrator.
        
        Args:
            scan_id: Unique scan identifier
            target_url: Target application URL
        """
        self.scan_id = scan_id
        self.target_url = target_url
        
        # Component: Ollama for reasoning
        self.ollama = get_ollama_client()
        self.decision_maker = AIDecisionMaker(scan_id)
        
        # Component: Hexstrike-AI (will be initialized by MCP client)
        self.hexstrike_client = None
        
        # Component: Burp Suite (will be initialized by Burp client)
        self.burp_client = None
        
        # Component: Browser control (Playwright)
        self.browser = None
        
        # State
        self.scan_state = {
            "phase": "initialization",
            "vulnerabilities": [],
            "tested_endpoints": [],
            "current_focus": None
        }
        
        logger.info(f"ARES Orchestrator initialized for {target_url} (scan: {scan_id})")
    
    async def analyze_with_ollama(
        self,
        vulnerability_data: Dict[str, Any],
        context: str = ""
    ) -> Dict[str, Any]:
        """
        Use Ollama to analyze vulnerabilities and identify logical flaws.
        
        This is where Ollama shines - reasoning about complex issues:
        - Business logic flaws
        - Race conditions
        - Access control issues  
        - Complex authentication bypasses
        - Multi-step exploitation chains
        
        Args:
            vulnerability_data: Raw vulnerability findings
            context: Additional context for analysis
            
        Returns:
            Analysis with insights and recommendations
        """
        prompt = f"""
Analyze this web application security finding for logical flaws and complex vulnerabilities:

Vulnerability Type: {vulnerability_data.get('type', 'Unknown')}
Location: {vulnerability_data.get('url', 'Unknown')}
Evidence: {vulnerability_data.get('evidence', 'None')}

Context: {context}

Focus on:
1. **Business Logic Flaws**: Are there workflow issues, improper state transitions, or business rule violations?
2. **Access Control**: Can this be exploited for privilege escalation or unauthorized access?
3. **Complex Chains**: Can this vulnerability be chained with others for greater impact?
4. **Root Cause**: What is the fundamental security issue causing this?
5. **Real-World Impact**: How would an attacker actually exploit this?

Provide strategic analysis, not just technical details.
"""
        
        try:
            analysis = await self.ollama.generate(
                prompt=prompt,
                system="You are an expert security analyst identifying complex logical vulnerabilities."
            )
            
            logger.info(f"Ollama analyzed vulnerability: {vulnerability_data.get('type', 'unknown')}")
            
            return {
                "status": "success",
                "analysis": analysis,
                "complexity": "high",  # Ollama handles complex reasoning
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Ollama analysis failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def generate_payload_with_hexstrike(
        self,
        vulnerability_type: str,
        target_endpoint: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Use Hexstrike-AI to generate and execute payloads.
        
        Hexstrike excels at:
        - Generating targeted exploitation payloads
        - Fuzzing inputs
        - Tool selection and chaining
        - Automated exploitation
        
        Args:
            vulnerability_type: Type of vulnerability (SQLi, XSS, etc.)
            target_endpoint: Where to test
            context: Additional context (parameters, headers, etc.)
            
        Returns:
            Payload and execution results
        """
        if not self.hexstrike_client:
            logger.warning("Hexstrike-AI not initialized yet")
            return {
                "status": "pending",
                "message": "Hexstrike-AI integration in progress"
            }
        
        # Hexstrike-AI will handle payload generation and execution
        # This will be implemented by the MCP integration agent
        try:
            result = await self.hexstrike_client.generate_and_execute(
                vuln_type=vulnerability_type,
                target=target_endpoint,
                context=context
            )
            
            logger.info(f"Hexstrike generated payload for {vulnerability_type}")
            return result
            
        except Exception as e:
            logger.error(f"Hexstrike payload generation failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def test_with_burp(
        self,
        request_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Use Burp Suite for advanced HTTP testing.
        
        Burp Suite provides:
        - Traffic interception and modification
        - Session handling
        - Advanced scanner capabilities
        - Collaboration features
        
        Args:
            request_data: HTTP request to send through Burp
            
        Returns:
            Burp scan results
        """
        if not self.burp_client:
            logger.warning("Burp Suite not initialized yet")
            return {
                "status": "pending",
                "message": "Burp Suite integration in progress"
            }
        
        try:
            result = await self.burp_client.send_to_scanner(request_data)
            logger.info(f"Burp tested: {request_data.get('url', 'unknown')}")
            return result
            
        except Exception as e:
            logger.error(f"Burp testing failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def execute_in_browser(
        self,
        script: str,
        url: str
    ) -> Dict[str, Any]:
        """
        Execute JavaScript in browser for dynamic testing.
        
        Browser control enables:
        - XSS validation (does the payload actually execute?)
        - Client-side vulnerability discovery
        - CSRF testing
        - DOM-based attacks
        
        Args:
            script: JavaScript to execute
            url: URL to navigate to
            
        Returns:
            Execution results
        """
        if not self.browser:
            logger.warning("Browser not initialized yet")
            return {
                "status": "pending",
                "message": "Browser initialization in progress"
            }
        
        try:
            from ares_scanner.crawler import WebCrawler
            crawler = WebCrawler(base_url=url)
            
            # Execute script in browser context
            result = await crawler.execute_script(script, url)
            
            logger.info(f"Browser executed script at {url}")
            return {"status": "success", "result": result}
            
        except Exception as e:
            logger.error(f"Browser execution failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def autonomous_scan_workflow(self) -> Dict[str, Any]:
        """
        Execute autonomous penetration testing workflow.
        
        Workflow:
        1. Ollama analyzes target and creates strategy
        2. Hexstrike generates payloads based on strategy
        3. Burp Suite tests the payloads
        4. Browser validates exploits
        5. Ollama analyzes results and decides next steps
        6. Repeat until objective achieved or scan complete
        
        Returns:
            Complete scan results
        """
        logger.info(f"Starting autonomous scan of {self.target_url}")
        
        results = {
            "scan_id": self.scan_id,
            "target": self.target_url,
            "start_time": datetime.utcnow().isoformat(),
            "vulnerabilities": [],
            "decisions": []
        }
        
        # Phase 1: Ollama creates initial strategy
        strategy = await self.decision_maker.make_decision(
            current_state=self.scan_state,
            available_actions=[
                "enumerate_endpoints",
                "test_authentication",
                "scan_for_common_vulns",
                "test_business_logic"
            ],
            constraints={
                "time_limit": 3600,
                "stealth_mode": False,
                "aggressive": True
            }
        )
        
        results["decisions"].append(strategy)
        logger.info(f"Strategy: {strategy.get('action', 'unknown')}")
        
        # Phase 2-N: Execute based on Ollama's decisions
        # This will be expanded as components come online
        
        results["end_time"] = datetime.utcnow().isoformat()
        results["status"] = "completed"
        
        return results


def get_orchestrator(scan_id: str, target_url: str) -> ARESOrchestrator:
    """
    Get ARES orchestrator instance.
    
    Args:
        scan_id: Scan identifier
        target_url: Target URL
        
    Returns:
        ARESOrchestrator instance
    """
    return ARESOrchestrator(scan_id, target_url)
