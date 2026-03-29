#!/bin/bash
# ARES Stop Script

echo "🛑 Stopping ARES..."
echo ""

# Stop frontend (port 3000)
echo "Stopping frontend (port 3000)..."
FRONTEND_PIDS=$(lsof -ti :3000 2>/dev/null || true)
if [ -n "$FRONTEND_PIDS" ]; then
    for pid in $FRONTEND_PIDS; do
        kill -9 $pid 2>/dev/null && echo "  ✓ Stopped frontend PID: $pid"
    done
else
    echo "  • No frontend running"
fi

# Also kill any npm/node processes for vite
NPM_PIDS=$(ps aux | grep -E "npm run dev|vite" | grep -v grep | awk '{print $2}' || true)
if [ -n "$NPM_PIDS" ]; then
    for pid in $NPM_PIDS; do
        kill -9 $pid 2>/dev/null && echo "  ✓ Stopped npm/vite PID: $pid"
    done
fi

# Stop backend (port 8000)
echo "Stopping backend (port 8000)..."
BACKEND_PIDS=$(lsof -ti :8000 2>/dev/null || true)
if [ -n "$BACKEND_PIDS" ]; then
    for pid in $BACKEND_PIDS; do
        kill -9 $pid 2>/dev/null && echo "  ✓ Stopped backend PID: $pid"
    done
else
    echo "  • No backend running"
fi

# Stop Hexstrike (port 8888)
echo "Stopping Hexstrike (port 8888)..."
HEXSTRIKE_PIDS=$(lsof -ti :8888 2>/dev/null || true)
if [ -n "$HEXSTRIKE_PIDS" ]; then
    for pid in $HEXSTRIKE_PIDS; do
        kill -9 $pid 2>/dev/null && echo "  ✓ Stopped Hexstrike PID: $pid"
    done
else
    echo "  • No Hexstrike running"
fi

# Stop Ollama
echo "Stopping Ollama..."
OLLAMA_PIDS=$(pgrep -x ollama || true)
if [ -n "$OLLAMA_PIDS" ]; then
    for pid in $OLLAMA_PIDS; do
        kill $pid 2>/dev/null && echo "  ✓ Stopped Ollama PID: $pid"
    done
else
    echo "  • Ollama not running"
fi

sleep 2
echo ""
echo "✅ ARES stopped (all services)"
