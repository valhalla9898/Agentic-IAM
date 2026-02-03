#!/bin/bash
# Automated Virtual Environment Setup for Agentic-IAM
# This script creates a venv, installs dependencies, and starts the app

echo ""
echo "================================================================"
echo "          AGENTIC-IAM - Virtual Environment Setup"
echo "================================================================"
echo ""

# Check if venv already exists
if [ -d "venv" ]; then
    echo "Virtual environment already exists."
    read -p "Do you want to recreate it? (y/n): " choice
    if [ "$choice" != "y" ] && [ "$choice" != "Y" ]; then
        echo "Using existing virtual environment..."
        source venv/bin/activate
    else
        echo "Removing existing venv..."
        rm -rf venv
        python3 -m venv venv
        source venv/bin/activate
    fi
else
    echo "[1/4] Creating virtual environment..."
    echo "----------------------------------------------------------------"
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to create virtual environment"
        echo "Make sure Python 3 is installed"
        exit 1
    fi
    echo "✓ Virtual environment created successfully"
    echo ""
    
    echo "[2/4] Activating virtual environment..."
    echo "----------------------------------------------------------------"
    source venv/bin/activate
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to activate virtual environment"
        exit 1
    fi
    echo "✓ Virtual environment activated"
    echo ""
fi

echo "[3/4] Installing dependencies..."
echo "----------------------------------------------------------------"
echo "Upgrading pip..."
python -m pip install --upgrade pip
echo ""
echo "Installing requirements..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "WARNING: Some packages may not have installed correctly"
    echo "You can try manually with: pip install -r requirements.txt"
fi
echo "✓ Dependencies installed"
echo ""

echo "[4/4] Verifying installation..."
echo "----------------------------------------------------------------"
python --version
pip --version
streamlit --version
echo ""

echo "================================================================"
echo "                    SETUP COMPLETE!"
echo "================================================================"
echo ""
echo "Virtual environment is ready and activated!"
echo ""
echo "Default Login Credentials:"
echo "  Admin: admin / admin123"
echo "  User:  user / user123"
echo ""
echo "================================================================"
echo ""

read -p "Do you want to start the application now? (y/n): " start_choice
if [ "$start_choice" = "y" ] || [ "$start_choice" = "Y" ]; then
    echo ""
    echo "Starting Agentic-IAM Dashboard..."
    echo ""
    echo "The application will open in your browser at:"
    echo "http://localhost:8501"
    echo ""
    echo "Press Ctrl+C to stop the application"
    echo ""
    streamlit run app.py
else
    echo ""
    echo "To manually start the application later:"
    echo "  1. Activate venv:    source venv/bin/activate"
    echo "  2. Run application:  streamlit run app.py"
    echo "  3. Deactivate venv:  deactivate"
    echo ""
fi
