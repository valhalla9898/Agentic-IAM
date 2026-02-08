Agentic-IAM — How To Use (English)

This document explains how to install, run, and use the Agentic-IAM project and its Streamlit dashboard.

Prerequisites
- Python 3.11+ recommended
- Git
- On Windows: PowerShell or Command Prompt

Quick setup
1. Clone the repository

```bash
git clone https://github.com/valhalla9898/Agentic-IAM.git
cd Agentic-IAM
```

2. Create and activate virtual environment

On Windows (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

On Windows (cmd.exe):
```bat
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

On macOS / Linux:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the Streamlit dashboard

```bash
# inside project root and venv activated
streamlit run app.py --server.port 8501
```

Open the browser:
- Local: http://localhost:8501

Run quick authentication tests (optional)

```bash
# inside venv
python test_login.py
```

Files and purpose (short)
- `app.py`: Main Streamlit dashboard entrypoint
- `dashboard/`: Streamlit components and views
- `api/`: FastAPI REST API and routers
- `database.py`: SQLite helper used by the dashboard and tests
- `README.md`: Project overview and top-level docs
- `HOW_TO_USE.md`: This file (quick usage)
- `dashboard/report_after_merge.py`: Streamlit viewer for the "Report After Merge" section

Desktop launcher
A Windows batch file `Open-Agentic-IAM.bat` is provided (created on your Desktop). Double-clicking it will open the project and run the Streamlit dashboard on port 8501.

If you need any changes (different port, run in background, or start with a different script), update the `.bat` file accordingly.

Support and Troubleshooting
- If the Streamlit page does not appear, check that the venv is activated and dependencies are installed.
- If login fails: default credentials are `admin / admin123` and `user / user123`. If you changed the DB file, delete `data/agentic_iam.db` and re-start to recreate default users.

Contact
For any clarifications, open an issue in the repository or contact the maintainer via the project's GitHub.
