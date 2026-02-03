#!/bin/bash
# Quick run script that activates venv and starts the app

echo ""
echo "================================================================"
echo "              AGENTIC-IAM - Starting with venv"
echo "================================================================"
echo ""

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "ERROR: Virtual environment not found!"
    echo ""
    echo "Please run setup_venv.sh first to create the virtual environment:"
    echo "  chmod +x setup_venv.sh"
    echo "  ./setup_venv.sh"
    echo ""
    exit 1
fi

# Activate venv
echo "Activating virtual environment..."
source venv/bin/activate

echo "Virtual environment activated!"
echo ""
echo "Starting Agentic-IAM Dashboard..."
echo ""
echo "Default Login Credentials:"
echo "  Admin: admin / admin123"
echo "  User:  user / user123"
echo ""
echo "Application will open at: http://localhost:8501"
echo ""
echo "Press Ctrl+C to stop the application"
echo ""
echo "================================================================"
echo ""

# Run the application
streamlit run app.py

# Deactivate on exit
deactivate
