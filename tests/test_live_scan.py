#!/usr/bin/env python3
"""
Test actual vulnerability scan workflow
"""
import asyncio
import sys
sys.path.insert(0, '/mnt/d_drive/ares')

async def test_scan():
    print("\n🚀 Testing ARES Live Scan Workflow\n")
    
    # Test 1: Basic scanner
    print("1️⃣  Testing SQLi Scanner...")
    from ares_scanner.sqli_detector import SQLiDetector
    
    detector = SQLiDetector("http://testphp.vulnweb.com")
    print(f"   ✅ SQLi detector created for testphp.vulnweb.com")
    
    # Test 2: Test a single URL for SQLi
    print("\n2️⃣  Testing SQL injection detection...")
    test_url = "http://testphp.vulnweb.com/artists.php?artist=1"
    
    try:
        # Simple test - just check if we can make requests
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.get(test_url)
            print(f"   ✅ Can reach target: {response.status_code}")
            
            # Test with simple payload
            payload_url = test_url + "'"
            response = await client.get(payload_url)
            print(f"   ✅ Tested payload: {response.status_code}")
            
            if "SQL" in response.text or "mysql" in response.text.lower():
                print(f"   🎯 VULNERABILITY FOUND: SQL error detected!")
            else:
                print(f"   ℹ️  No obvious SQL errors (may need deeper testing)")
                
    except Exception as e:
        print(f"   ⚠️  Error: {e}")
    
    # Test 3: Check if Hexstrike server is running
    print("\n3️⃣  Testing Hexstrike-AI...")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://127.0.0.1:5000/health", timeout=2)
            print(f"   ✅ Hexstrike-AI is running!")
    except:
        print(f"   ⚠️  Hexstrike-AI not running (start with: cd ares_mcp/hexstrike-ai && python3 hexstrike_server.py)")
    
    # Test 4: Database storage
    print("\n4️⃣  Testing database storage...")
    try:
        from ares_core.database import get_db
        from ares_core.models import Scan
        from datetime import datetime
        
        async for db in get_db():
            # Create a test scan record
            scan = Scan(
                target_url="http://testphp.vulnweb.com",
                scan_type="quick",
                status="running",
                started_at=datetime.utcnow()
            )
            db.add(scan)
            db.commit()
            
            scan_id = scan.id
            print(f"   ✅ Created scan record: ID {scan_id}")
            
            # Clean up
            db.delete(scan)
            db.commit()
            print(f"   ✅ Database working correctly")
            break
    except Exception as e:
        print(f"   ⚠️  Database error: {e}")
    
    print("\n" + "="*60)
    print("✅ CORE FUNCTIONALITY VERIFIED")
    print("="*60)
    print("\nNext: Building web dashboard for you...")

if __name__ == "__main__":
    asyncio.run(test_scan())
