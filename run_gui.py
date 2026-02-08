"""
Quick start guide for Agentic-IAM Dashboard
"""
import subprocess
import sys
from pathlib import Path

def main():
    print("\n" + "=" * 70)
    print("🚀 AGENTIC-IAM DASHBOARD LAUNCHER")
    print("=" * 70 + "\n")
    
    # Run test setup
    print("📋 Verifying system setup...")
    result = subprocess.run([sys.executable, "test_setup.py"], capture_output=True, text=True)
    
    # Print the output
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    # Check for success indicators
    success_indicators = ["SYSTEM READY TO RUN", "SUCCESS: SYSTEM READY"]
    is_ready = any(indicator in result.stdout for indicator in success_indicators)
    
    if is_ready:
        print("\n✅ System verification passed!")
        print("\n🌐 Starting Streamlit dashboard on http://localhost:8501...\n")
        
        # Start streamlit
        subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py"])
    else:
        print("\n❌ System verification failed. Please check the output above.")
        print(f"Exit code: {result.returncode}")
        sys.exit(1)

if __name__ == "__main__":
    main()
