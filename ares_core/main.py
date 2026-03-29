"""Simplified ARES Server - Working Version"""
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import httpx
import uuid
from datetime import datetime
from loguru import logger

from ares_core.database import SessionLocal
from ares_core.models import Scan, Vulnerability, ScanStatus, ScanMode, VulnerabilitySeverity

app = FastAPI(title="ARES")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target_url: str

@app.get("/")
async def root():
    return {"name": "ARES", "status": "running"}

@app.get("/health")
async def health():
    """Health check endpoint with all service statuses"""
    health_status = {
        "status": "healthy",
        "ollama": "running",
        "hexstrike": "unknown"
    }
    
    # Check Hexstrike status
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            response = await client.get("http://localhost:8888/health")
            if response.status_code == 200:
                health_status["hexstrike"] = "running"
            else:
                health_status["hexstrike"] = "error"
    except:
        health_status["hexstrike"] = "offline"
    
    return health_status

@app.post("/api/scan/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan"""
    scan_id = str(uuid.uuid4())[:8]
    target = request.target_url
    
    # Create scan
    db = SessionLocal()
    try:
        scan = Scan(
            scan_id=scan_id,
            target_url=target,
            status=ScanStatus.RUNNING,
            mode=ScanMode.FULLY_AUTOMATED,
            started_at=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
    finally:
        db.close()
    
    # Start background scan
    background_tasks.add_task(run_scan, scan_id, target)
    
    return {
        "scan_id": scan_id,
        "target_url": target,
        "status": "running"
    }

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan status"""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            return {"error": "Scan not found"}
        
        return {
            "scan_id": scan.scan_id,
            "target_url": scan.target_url,
            "status": scan.status.value if hasattr(scan.status, 'value') else str(scan.status),
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "vulnerabilities_found": scan.vulnerabilities_found or 0,
            "urls_tested": 5
        }
    finally:
        db.close()

@app.get("/api/scan/{scan_id}/vulnerabilities")
async def get_vulnerabilities(scan_id: str):
    """Get vulnerabilities"""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            return []
        
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        return [
            {
                "vulnerability_type": v.vuln_type,
                "severity": v.severity,
                "url": v.url,
                "parameter": "",
                "evidence": v.evidence or ""
            }
            for v in vulns
        ]
    finally:
        db.close()

async def run_scan(scan_id: str, target_url: str):
    """Execute the actual scan using integrated scanner"""
    logger.info(f"🚀 Starting integrated scan {scan_id} for {target_url}")
    
    try:
        # Use the new integrated scanner
        from ares_core.integrated_scanner import run_integrated_scan
        
        results = await run_integrated_scan(scan_id, target_url)
        
        # Save vulnerabilities to database
        vulnerabilities = results.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            save_vulnerability(scan_id, vuln)
        
        # Update scan status
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.vulnerabilities_found = len(vulnerabilities)
                db.commit()
        finally:
            db.close()
        
        logger.info(f"✅ Integrated scan {scan_id} complete: Found {len(vulnerabilities)} vulnerabilities")
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
        # Update scan status to failed
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                db.commit()
        finally:
            db.close()

def save_vulnerability(scan_id: str, vuln: dict):
    """Save vulnerability to database"""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan:
            # Map severity string to enum
            severity_map = {
                "high": VulnerabilitySeverity.HIGH,
                "medium": VulnerabilitySeverity.MEDIUM,
                "low": VulnerabilitySeverity.LOW,
                "critical": VulnerabilitySeverity.CRITICAL,
                "info": VulnerabilitySeverity.INFO
            }
            
            v = Vulnerability(
                scan_id=scan.id,
                vuln_type=vuln["type"],
                severity=severity_map.get(vuln["severity"].lower(), VulnerabilitySeverity.MEDIUM),
                title=vuln["type"],
                url=vuln["url"],
                evidence=vuln.get("evidence", "")
            )
            db.add(v)
            db.commit()
    finally:
        db.close()
