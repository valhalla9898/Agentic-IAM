#!/bin/bash
# Agentic-IAM Project Launcher for Linux/macOS

set -e

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo ""
echo "========================================"
echo " Agentic-IAM Project Launcher"
echo "========================================"
echo ""

# Check if virtual environment exists
if [ ! -d venv ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "Virtual environment created."
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies if needed
if ! pip list | grep -q fastapi; then
    echo "Installing dependencies..."
    pip install -e .
fi

# Open VS Code
echo "Opening VS Code..."
code . &

# Wait for VS Code to open
sleep 2

# Start API server in background
echo "Starting API server on http://localhost:8000..."
gnome-terminal -- bash -c "cd '$SCRIPT_DIR' && source venv/bin/activate && uvicorn api.main:app --reload --port 8000; exec bash" &

# Wait for API to start
sleep 3

# Start Streamlit dashboard in background
echo "Starting Streamlit dashboard on http://localhost:8501..."
gnome-terminal -- bash -c "cd '$SCRIPT_DIR' && source venv/bin/activate && streamlit run dashboard/components/agent_management.py; exec bash" &

echo ""
echo "========================================"
echo "Project launched successfully!"
echo ""
echo "Services:"
echo "- VS Code IDE: Now opening..."
echo "- API Server: http://localhost:8000"
echo "- API Docs: http://localhost:8000/docs"
echo "- Dashboard: http://localhost:8501"
echo ""
echo "Close the terminals when done."
echo "========================================"
echo ""
