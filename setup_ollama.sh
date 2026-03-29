#!/bin/bash
# One-time Ollama Model Setup Script
# Downloads llama3.2:3b to /mnt/d_drive/ares/ollama_models

set -e

ARES_DIR="/mnt/d_drive/ares"
OLLAMA_MODELS_DIR="$ARES_DIR/ollama_models"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "╔════════════════════════════════════════════╗"
echo "║   Ollama Model Setup for ARES              ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# Check if Ollama is installed
if ! command -v ollama &> /dev/null; then
    echo -e "${RED}❌ Ollama is not installed!${NC}"
    echo "Install it with: curl -fsSL https://ollama.com/install.sh | sh"
    exit 1
fi

echo -e "${GREEN}✅ Ollama is installed${NC}"
echo ""

# Create model directory
echo "Creating model directory..."
mkdir -p "$OLLAMA_MODELS_DIR"
chmod 777 "$OLLAMA_MODELS_DIR"
echo -e "${GREEN}✅ Directory ready: $OLLAMA_MODELS_DIR${NC}"
echo ""

# Check disk space
echo "Checking disk space..."
AVAILABLE=$(df -BG /mnt/d_drive | tail -1 | awk '{print $4}' | sed 's/G//')
echo "Available space on /mnt/d_drive: ${AVAILABLE}GB"

if [ "$AVAILABLE" -lt 3 ]; then
    echo -e "${RED}❌ Not enough space! Need at least 3GB, have ${AVAILABLE}GB${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Sufficient space available${NC}"
echo ""

# Stop any running Ollama
echo "Checking for running Ollama instances..."
OLLAMA_PIDS=$(pgrep -x ollama || true)
if [ -n "$OLLAMA_PIDS" ]; then
    echo -e "${YELLOW}⚠️  Ollama is running. Please stop it first:${NC}"
    for pid in $OLLAMA_PIDS; do
        echo "   sudo kill $pid"
    done
    echo ""
    read -p "Stop Ollama now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        for pid in $OLLAMA_PIDS; do
            sudo kill $pid 2>/dev/null || kill $pid 2>/dev/null || true
        done
        sleep 3
        echo -e "${GREEN}✅ Stopped Ollama${NC}"
    else
        echo "Please stop Ollama manually and run this script again"
        exit 1
    fi
fi
echo ""

# Start Ollama with custom path
echo "Starting Ollama with custom model path..."
export OLLAMA_MODELS="$OLLAMA_MODELS_DIR"
nohup ollama serve > "$ARES_DIR/logs/ollama_setup.log" 2>&1 &
OLLAMA_PID=$!
echo -e "${GREEN}✅ Started Ollama (PID: $OLLAMA_PID)${NC}"
sleep 5

# Check if Ollama is responding
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo -e "${RED}❌ Ollama failed to start. Check logs/ollama_setup.log${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Ollama is responding${NC}"
echo ""

# Download model
echo "╔════════════════════════════════════════════╗"
echo "║   Downloading llama3.2:3b Model            ║"
echo "║   This will take 5-10 minutes (~2GB)       ║"
echo "╚════════════════════════════════════════════╝"
echo ""
echo "Model will be stored in: $OLLAMA_MODELS_DIR"
echo ""

export OLLAMA_MODELS="$OLLAMA_MODELS_DIR"
ollama pull llama3.2:3b

# Verify download
echo ""
echo "Verifying model..."
if ollama list | grep -q "llama3.2:3b"; then
    echo -e "${GREEN}✅ Model downloaded successfully!${NC}"
    echo ""
    ollama list
else
    echo -e "${RED}❌ Model download failed${NC}"
    exit 1
fi

# Show model location
echo ""
echo "Model files stored in:"
du -sh "$OLLAMA_MODELS_DIR"
echo ""

# Stop the temporary Ollama instance
echo "Stopping temporary Ollama instance..."
kill $OLLAMA_PID 2>/dev/null || true
sleep 2

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║   ✅ Setup Complete!                       ║"
echo "╚════════════════════════════════════════════╝"
echo ""
echo "The model is ready to use."
echo "START.sh will now automatically:"
echo "  1. Start Ollama with custom model path"
echo "  2. Use llama3.2:3b for AI features"
echo "  3. Start the backend API"
echo ""
echo "Run: ./START.sh"
echo ""
