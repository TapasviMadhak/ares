"""
Scanner Bridge - Integrates ARES scanners with Burp Suite

Coordinates between ARES vulnerability scanners and Burp Suite
for enhanced scanning capabilities and centralized issue management.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from loguru import logger

from .burp_client import BurpClient
from ares_core.models import Scan, Vulnerability
from ares_core.database import get_db


class ScannerBridge:
    """
    Bridge between ARES scanners and Burp Suite
    
    Coordinates:
    - Burp active/passive scanning with ARES custom scanners
    - Issue deduplication across both systems
    - Centralized vulnerability reporting
    - Session sharing between tools
    """
    
    def __init__(
        self,
        burp_client: BurpClient,
        scan_id: int
    ):
        """
        Initialize scanner bridge
        
        Args:
            burp_client: Initialized BurpClient instance
            scan_id: ARES scan ID
        """
        self.burp_client = burp_client
        self.scan_id = scan_id
        self.burp_task_id: Optional[str] = None
        
        logger.info(f"Initialized ScannerBridge for scan_id: {scan_id}")
    
    async def start_coordinated_scan(
        self,
        target_url: str,
        enable_burp_scanner: bool = True,
        enable_burp_spider: bool = True
    ) -> Dict[str, Any]:
        """
        Start coordinated scan using both ARES and Burp
        
        Args:
            target_url: Target URL to scan
            enable_burp_scanner: Enable Burp active scanner
            enable_burp_spider: Enable Burp spider
            
        Returns:
            Dict with task IDs and status
        """
        results = {
            "target_url": target_url,
            "scan_id": self.scan_id,
            "burp_scanner_task_id": None,
            "burp_spider_task_id": None,
            "started_at": datetime.now(timezone.utc).isoformat()
        }
        
        # Add to Burp scope
        await self.burp_client.add_to_scope(target_url)
        
        # Start Burp spider
        if enable_burp_spider:
            spider_task_id = await self.burp_client.start_spider(target_url)
            results["burp_spider_task_id"] = spider_task_id
            logger.info(f"Started Burp spider: {spider_task_id}")
        
        # Start Burp active scanner
        if enable_burp_scanner:
            scanner_task_id = await self.burp_client.start_scan(target_url)
            results["burp_scanner_task_id"] = scanner_task_id
            self.burp_task_id = scanner_task_id
            logger.info(f"Started Burp scanner: {scanner_task_id}")
        
        return results
    
    async def sync_burp_issues_to_db(
        self,
        severity_filter: Optional[str] = None
    ) -> int:
        """
        Sync Burp issues to ARES database
        
        Args:
            severity_filter: Filter by severity (high, medium, low)
            
        Returns:
            Number of issues synced
        """
        # Get issues from Burp
        burp_issues = await self.burp_client.get_scan_issues(
            task_id=self.burp_task_id,
            severity=severity_filter
        )
        
        synced_count = 0
        
        async for db in get_db():
            for issue in burp_issues:
                # Check if issue already exists (deduplication)
                existing = db.query(Vulnerability).filter(
                    Vulnerability.scan_id == self.scan_id,
                    Vulnerability.url == issue.get('url'),
                    Vulnerability.vulnerability_type == issue.get('issue_type')
                ).first()
                
                if existing:
                    logger.debug(f"Issue already exists: {issue.get('issue_type')}")
                    continue
                
                # Create new vulnerability record
                vuln = Vulnerability(
                    scan_id=self.scan_id,
                    vulnerability_type=issue.get('issue_type', 'unknown'),
                    severity=self._map_burp_severity(issue.get('severity')),
                    url=issue.get('url', ''),
                    parameter=issue.get('parameter', ''),
                    payload=issue.get('evidence', ''),
                    evidence=issue.get('description', ''),
                    confidence=issue.get('confidence', 'tentative'),
                    remediation=issue.get('remediation', ''),
                    source='burp'
                )
                
                db.add(vuln)
                synced_count += 1
            
            db.commit()
        
        logger.info(f"Synced {synced_count} issues from Burp to database")
        return synced_count
    
    def _map_burp_severity(self, burp_severity: str) -> str:
        """
        Map Burp severity to ARES severity
        
        Args:
            burp_severity: Burp severity string
            
        Returns:
            ARES severity string
        """
        mapping = {
            'high': 'critical',
            'medium': 'high',
            'low': 'medium',
            'information': 'low'
        }
        return mapping.get(burp_severity.lower(), 'info')
    
    async def get_scan_progress(self) -> Dict[str, Any]:
        """
        Get combined scan progress from Burp
        
        Returns:
            Progress dict with status and metrics
        """
        if not self.burp_task_id:
            return {"status": "not_started"}
        
        status = await self.burp_client.get_scan_status(self.burp_task_id)
        
        return {
            "burp_task_id": self.burp_task_id,
            "status": status.get('status'),
            "progress": status.get('progress', 0),
            "requests_made": status.get('requests_made', 0),
            "issues_found": status.get('issues_found', 0)
        }
    
    async def stop_scan(self):
        """Stop Burp scan"""
        if self.burp_task_id:
            await self.burp_client.stop_scan(self.burp_task_id)
            logger.info(f"Stopped Burp scan: {self.burp_task_id}")
    
    async def export_sitemap_to_crawler(self) -> List[str]:
        """
        Export Burp sitemap URLs for ARES crawler
        
        Returns:
            List of discovered URLs
        """
        sitemap = await self.burp_client.get_sitemap()
        urls = [entry['url'] for entry in sitemap]
        
        logger.info(f"Exported {len(urls)} URLs from Burp sitemap")
        return urls
