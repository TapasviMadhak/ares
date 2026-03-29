#!/bin/bash
# Test ARES Backend

echo "Testing ARES Backend..."
echo "======================="
echo ""

# Test 1: Health
echo "1. Health Check:"
curl -s http://localhost:8000/health | python -m json.tool
echo ""

# Test 2: Root
echo "2. Root Endpoint:"
curl -s http://localhost:8000/
echo -e "\n"

# Test 3: Start Scan
echo "3. Starting Scan:"
RESPONSE=$(curl -s -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://testphp.vulnweb.com"}')
echo "$RESPONSE" | python -m json.tool
SCAN_ID=$(echo "$RESPONSE" | python -c "import sys, json; print(json.load(sys.stdin).get('scan_id', ''))")
echo ""

if [ -z "$SCAN_ID" ]; then
    echo "❌ Failed to start scan"
    exit 1
fi

# Test 4: Wait and check
echo "4. Waiting for scan to complete (30s)..."
sleep 30

echo "5. Checking database..."
source venv/bin/activate
python << EOF
from ares_core.database import SessionLocal
from ares_core.models import Scan, Vulnerability

db = SessionLocal()
scan = db.query(Scan).filter(Scan.scan_id == "$SCAN_ID").first()

if scan:
    print(f"✅ Scan found: {scan.scan_id}")
    print(f"   Status: {scan.status.value}")
    print(f"   Target: {scan.target_url}")
    print(f"   Vulnerabilities: {scan.vulnerabilities_found or 0}")
    
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    if vulns:
        print(f"\n   Found {len(vulns)} vulnerabilities:")
        for v in vulns[:5]:
            print(f"   - {v.vuln_type} ({v.severity.value})")
else:
    print("❌ Scan not found in database")

db.close()
EOF

echo ""
echo "✅ Tests complete!"
