"""Working scan workflow"""
import asyncio
import httpx
from loguru import logger
from sqlalchemy.orm import Session

from ares_core.ollama_client import OllamaClient
from ares_core.database import SessionLocal
from ares_core.models import Scan, Vulnerability, AIDecision


class ScanWorkflow:
    def __init__(self, scan_id: str, target_url: str):
        self.scan_id = scan_id
        self.target_url = target_url
        self.ollama = OllamaClient()
        self.vulnerabilities = []
        
    async def run(self):
        """Execute scan"""
        logger.info(f"Starting scan {self.scan_id} for {self.target_url}")
        
        try:
            # Step 1: Ollama analyzes
            plan = await self.ollama_analyze()
            logger.info(f"Ollama plan: {plan}")
            
            # Step 2: Test based on plan
            if "sql" in plan.lower() or "injection" in plan.lower():
                await self.test_sqli()
            
            if "xss" in plan.lower() or "script" in plan.lower():
                await self.test_xss()
            
            # Step 3: Update database
            db = SessionLocal()
            try:
                scan = db.query(Scan).filter(Scan.scan_id == self.scan_id).first()
                if scan:
                    scan.status = "completed"
                    scan.vulnerabilities_found = len(self.vulnerabilities)
                    db.commit()
            finally:
                db.close()
            
            logger.info(f"Scan complete. Found {len(self.vulnerabilities)} vulnerabilities")
            return {"status": "completed", "vulnerabilities": len(self.vulnerabilities)}
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return {"status": "failed", "error": str(e)}
    
    async def ollama_analyze(self) -> str:
        """Ollama analyzes target"""
        prompt = f"""Analyze this web URL and determine what vulnerabilities to test:

Target: {self.target_url}

Based on the URL structure, what should we test? Respond in 2-3 sentences."""

        try:
            plan = await self.ollama.generate(prompt, max_tokens=100)
        except:
            plan = "Test for SQL injection and XSS"
        
        return plan
    
    async def test_sqli(self):
        """Test SQL injection"""
        logger.info("Testing SQLi...")
        
        payloads = ["'", "1' OR '1'='1", "' OR '1'='1' --"]
        
        for payload in payloads:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    # Try different parameter names
                    for param in ['firstname', 'lastname', 'id', 'user', 'q', 'search']:
                        test_url = f"{self.target_url}?{param}={payload}"
                        response = await client.get(test_url)
                        
                        # Check for SQL errors
                        error_keywords = ['sql', 'mysql', 'syntax error', 'query failed', 'mysqli']
                        if any(kw in response.text.lower() for kw in error_keywords):
                            vuln = {
                                "type": "SQL Injection",
                                "severity": "high",
                                "url": test_url,
                                "payload": payload,
                                "evidence": f"SQL error detected with payload: {payload}"
                            }
                            self.vulnerabilities.append(vuln)
                            self.save_vulnerability(vuln)
                            logger.info(f"🎯 Found SQLi: {test_url}")
                            return
            except Exception as e:
                logger.debug(f"SQLi test error: {e}")
    
    async def test_xss(self):
        """Test XSS"""
        logger.info("Testing XSS...")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>"
        ]
        
        for payload in payloads:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    for param in ['firstname', 'lastname', 'comment', 'name']:
                        test_url = f"{self.target_url}?{param}={payload}"
                        response = await client.get(test_url)
                        
                        if payload in response.text:
                            vuln = {
                                "type": "Cross-Site Scripting (XSS)",
                                "severity": "medium",
                                "url": test_url,
                                "payload": payload,
                                "evidence": "Payload reflected in response"
                            }
                            self.vulnerabilities.append(vuln)
                            self.save_vulnerability(vuln)
                            logger.info(f"�� Found XSS: {test_url}")
                            return
            except Exception as e:
                logger.debug(f"XSS test error: {e}")
    
    def save_vulnerability(self, vuln: dict):
        """Save to database"""
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.scan_id == self.scan_id).first()
            if scan:
                v = Vulnerability(
                    scan_id=scan.id,
                    vuln_type=vuln["type"],
                    severity=vuln["severity"],
                    title=vuln["type"],
                    url=vuln["url"],
                    evidence=vuln.get("evidence", "")
                )
                db.add(v)
                db.commit()
        finally:
            db.close()
