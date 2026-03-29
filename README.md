# ARES - AI-Powered Automated Red-Teaming Evaluation System

## ✅ Status: TESTED & WORKING

Last tested: 2026-03-27 11:04  
Backend: ✅ Running  
Database: ✅ Connected  
Scans: ✅ Operational  

## 🚀 Quick Start

```bash
cd /mnt/d_drive/ares
./START.sh
```

Backend will be available at: `http://localhost:8000`

## 📊 Test the API

```bash
# Health check
curl http://localhost:8000/health

# Start a scan
curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://testphp.vulnweb.com"}'
```

## 🛑 Stop Services

```bash
./STOP.sh
```

## 📁 Project Structure

```
ares/
├── ares_core/      # Backend API, database, orchestration
├── ares_scanner/   # 7 vulnerability detectors + web crawler
├── ares_mcp/       # Hexstrike-AI integration (150+ tools)
├── ares_web/       # Web interface components
├── tests/          # Test files
├── frontend/       # React dashboard (optional)
├── venv/           # Python virtual environment
├── START.sh        # Start script
├── STOP.sh         # Stop script
└── test_ares.sh    # Test script
```

## 🔧 Components

### Vulnerability Scanners
- ✅ SQL Injection (SQLi) Detector
- ✅ Cross-Site Scripting (XSS) Detector
- ✅ CSRF Detector
- ✅ SSRF Detector
- ✅ XXE Detector
- ✅ Deserialization Detector
- ✅ Authentication Bypass Detector

### Core Features
- ✅ FastAPI backend
- ✅ PostgreSQL database
- ✅ Ollama AI integration (optional)
- ✅ Async web crawler
- ✅ MCP tool orchestration

## 📖 API Documentation

Interactive docs available at: `http://localhost:8000/docs`

### Endpoints

**GET** `/health` - Health check  
**GET** `/` - Root endpoint  
**POST** `/api/scan/start` - Start a new scan  
**GET** `/api/scan/status/{scan_id}` - Get scan status  
**GET** `/api/scan/results/{scan_id}` - Get scan results  

## 💾 Disk Space

- Root partition: 94% full (7.9GB free)
- D drive: 6% full (288GB free)
- Ollama models stored in: `/mnt/d_drive/ares/ollama_models`

## 🔍 Logs

- Backend: `logs/backend.log`
- Ollama: `logs/ollama.log`

## ⚙️ Requirements

- Python 3.10+
- PostgreSQL
- Ollama (optional, for AI features)
- Node.js (optional, for frontend)

## 📝 Notes

- Backend works without Ollama (AI features disabled)
- External scans tested and working (testphp.vulnweb.com)
- Local scans supported (192.168.x.x)
- Project cleaned and optimized (11 unnecessary files removed)

## 🎯 Example Scan

```bash
# Start a scan
SCAN_ID=$(curl -s -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://testphp.vulnweb.com"}' \
  | python -c "import sys, json; print(json.load(sys.stdin)['scan_id'])")

echo "Scan ID: $SCAN_ID"

# Wait for results
sleep 30

# Check results
curl http://localhost:8000/api/scan/results/$SCAN_ID
```

## 🐛 Troubleshooting

**Backend won't start:**
```bash
# Check logs
tail -f logs/backend.log

# Check if port is in use
lsof -i :8000

# Stop and restart
./STOP.sh && ./START.sh
```

**Database connection issues:**
```bash
# Check PostgreSQL is running
systemctl status postgresql

# Test connection
psql -U $USER -d ares_db -c "SELECT 1;"
```

## 📚 Documentation

Full documentation: See `DEPLOYMENT_STATUS.txt` for detailed deployment information.

---

**Built with:** FastAPI, SQLAlchemy, Playwright, Ollama, React  
**License:** Proprietary  
**Version:** 0.1.0
