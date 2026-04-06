# Agentic-IAM Delivery Runbook

## 1) Startup (Windows)
1. Open terminal in project folder.
2. Activate venv: `.venv\Scripts\activate`
3. Run app: `python run_gui.py`
4. Open dashboard: `http://localhost:8501`

## 2) Quick Credentials
- Admin: `admin` / `admin123`
- Operator: `operator` / `operator123`
- User: `user` / `user123`

## 3) AI Commands
- Package CLI: `agentic-iam-ai "How to enable mTLS?"`
- PowerShell wrapper: `.\ask_ai.ps1 "How to enable mTLS?"`
- Batch wrapper: `ask_ai.bat "How to enable mTLS?"`
- Knowledge mode: `--model knowledge`
- Cloud mode (needs key): `--model openai:gpt-3.5-turbo`

## 4) Pre-Delivery Verification
- Full checks: `python scripts/check_all.py`
- Quick checks: `python scripts/check_all.py --quick`
- PowerShell wrapper: `.\check_all.ps1`

## 5) GitHub CI Expectations
- CI workflow: lint + tests
- Playwright workflow: E2E UI checks
- Security workflow: scans
- AI CLI smoke workflow: validates `tests/test_unit/test_ai_cli.py`

## 6) Troubleshooting
- If AI cloud mode fails: confirm `OPENAI_API_KEY` is set.
- If E2E fails locally: rerun `pytest tests/e2e/... -q` and verify Streamlit starts.
- If command wrappers fail: ensure `.venv` exists or use `python scripts/...` directly.
