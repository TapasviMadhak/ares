#!/bin/bash
# ARES Startup Script

set -e

ARES_DIR="/mnt/d_drive/ares"
OLLAMA_MODELS_DIR="$ARES_DIR/ollama_models"
LOG_DIR="$ARES_DIR/logs"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "🚀 Starting ARES - AI Bug Hunter"
echo "================================"

mkdir -p "$LOG_DIR"

# 1. Start Ollama with custom model path
echo ""
echo "1️⃣  Starting Ollama..."
if pgrep -x "ollama" > /dev/null; then
    echo -e "   ${GREEN}✅ Ollama already running${NC}"
else
    if [ -d "$OLLAMA_MODELS_DIR" ]; then
        export OLLAMA_MODELS="$OLLAMA_MODELS_DIR"
        echo "   Using model directory: $OLLAMA_MODELS_DIR"
    fi
    
    nohup ollama serve > "$LOG_DIR/ollama.log" 2>&1 &
    OLLAMA_PID=$!
    echo -e "   ${GREEN}✅ Started Ollama (PID: $OLLAMA_PID)${NC}"
    sleep 3
    
    # Verify Ollama is running
    if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo -e "   ${YELLOW}⚠️  Ollama may not be responding${NC}"
    fi
fi

# Check for model
if [ -d "$OLLAMA_MODELS_DIR" ]; then
    export OLLAMA_MODELS="$OLLAMA_MODELS_DIR"
fi

if ollama list 2>/dev/null | grep -q "llama3.2:3b"; then
    echo -e "   ${GREEN}✅ Model llama3.2:3b available${NC}"
else
    echo -e "   ${YELLOW}⚠️  Model llama3.2:3b not found${NC}"
    echo "   Run: ./setup_ollama.sh to download it"
    echo "   Backend will work without it (AI features disabled)"
fi

# 2. Start Hexstrike-AI Server
echo ""
echo "2️⃣  Starting Hexstrike-AI Server..."

# Make sure venv is activated
if [ ! -d "$ARES_DIR/venv" ]; then
    echo -e "${RED}   ❌ Virtual environment not found!${NC}"
    exit 1
fi

source "$ARES_DIR/venv/bin/activate"

# Stop existing hexstrike
EXISTING_PIDS=$(lsof -ti :8888 2>/dev/null || true)
if [ -n "$EXISTING_PIDS" ]; then
    echo "   Stopping existing Hexstrike..."
    for pid in $EXISTING_PIDS; do
        kill -9 $pid 2>/dev/null || true
    done
    sleep 2
fi

# Start Hexstrike server
echo "   Starting Hexstrike API server..."
nohup "$ARES_DIR/venv/bin/python" "$ARES_DIR/ares_mcp/hexstrike-ai/hexstrike_server.py" > "$LOG_DIR/hexstrike.log" 2>&1 &
HEXSTRIKE_PID=$!

# Wait for Hexstrike
echo "   Waiting for Hexstrike to be ready..."
for i in {1..20}; do
    if curl -s http://localhost:8888/health > /dev/null 2>&1; then
        echo -e "   ${GREEN}✅ Hexstrike ready!${NC}"
        break
    fi
    if [ $i -eq 20 ]; then
        echo -e "   ${YELLOW}⚠️  Hexstrike may be slow to start${NC}"
        echo "   Check logs: tail -f $LOG_DIR/hexstrike.log"
    fi
    sleep 3
done

# 3. Start Backend API
echo ""
echo "3️⃣  Starting Backend API..."
cd "$ARES_DIR"

if [ ! -d "venv" ]; then
    echo -e "${RED}   ❌ Virtual environment not found!${NC}"
    exit 1
fi

source venv/bin/activate

# Stop existing backend
EXISTING_PIDS=$(lsof -ti :8000 2>/dev/null || true)
if [ -n "$EXISTING_PIDS" ]; then
    echo "   Stopping existing backend..."
    for pid in $EXISTING_PIDS; do
        kill -9 $pid 2>/dev/null || true
    done
    sleep 2
fi

# Start backend
echo "   Starting FastAPI server..."
nohup python -m uvicorn ares_core.main:app --host 0.0.0.0 --port 8000 > "$LOG_DIR/backend.log" 2>&1 &
BACKEND_PID=$!

# Wait for backend
echo "   Waiting for backend to be ready..."
for i in {1..15}; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "   ${GREEN}✅ Backend ready!${NC}"
        break
    fi
    if [ $i -eq 15 ]; then
        echo -e "   ${RED}❌ Backend failed to start${NC}"
        echo "   Check logs: tail -f $LOG_DIR/backend.log"
        exit 1
    fi
    sleep 2
done

# 4. Start Frontend
echo ""
echo "4️⃣  Starting Frontend..."
cd "$ARES_DIR/frontend"

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo -e "   ${YELLOW}⚠️  node_modules not found, installing...${NC}"
    npm install
fi

# Stop existing frontend
EXISTING_PIDS=$(lsof -ti :3000 2>/dev/null || true)
if [ -n "$EXISTING_PIDS" ]; then
    echo "   Stopping existing frontend..."
    for pid in $EXISTING_PIDS; do
        kill -9 $pid 2>/dev/null || true
    done
    sleep 2
fi

# Start frontend
echo "   Starting Vite dev server..."
nohup npm run dev > "$LOG_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!

# Wait for frontend
echo "   Waiting for frontend to be ready..."
for i in {1..20}; do
    if curl -s http://localhost:3000 > /dev/null 2>&1; then
        echo -e "   ${GREEN}✅ Frontend ready!${NC}"
        break
    fi
    if [ $i -eq 20 ]; then
        echo -e "   ${YELLOW}⚠️  Frontend may be slow to start${NC}"
        echo "   Check logs: tail -f $LOG_DIR/frontend.log"
    fi
    sleep 1
done

echo ""
echo "================================"
echo -e "${GREEN}✅ ARES is running!${NC}"
echo "================================"
echo ""
echo "🌐 Frontend:     http://localhost:3000"
echo "🔧 Backend API:  http://localhost:8000"
echo "⚡ Hexstrike AI: http://localhost:8888"
echo "📍 API Docs:     http://localhost:8000/docs"
echo "📍 Health Check: http://localhost:8000/health"
echo ""
echo "📊 Quick test:"
echo "   curl http://localhost:8000/health"
echo ""
echo "🔍 Start a scan:"
echo '   curl -X POST http://localhost:8000/api/scan/start \'
echo '     -H "Content-Type: application/json" \'
echo '     -d '"'"'{"target_url": "http://testphp.vulnweb.com"}'"'"
echo ""
echo "📝 Logs:"
echo "   Frontend:   tail -f logs/frontend.log"
echo "   Backend:    tail -f logs/backend.log"
echo "   Hexstrike:  tail -f logs/hexstrike.log"
echo "   Ollama:     tail -f logs/ollama.log"
echo ""
echo "🛑 Stop: ./STOP.sh"
echo ""
