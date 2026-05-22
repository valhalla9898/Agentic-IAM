Report: Automated fixes applied to Agentic-IAM

Summary:
- Ran automated linters and formatters (ruff, isort, black).
- Fixed multiple linting issues (F712, F821, F841, F601) and replaced insecure random calls with `secrets` where appropriate.
- Fixed runtime `db` undefined errors in Streamlit dashboard components.
- Converted duplicate-key dictionaries to lists of pairs to avoid F601 where placeholders existed.
- Tests: `pytest` completed successfully (132 passed, 8 skipped).
- Security: Ran `bandit` scans; fixed project-level issues related to pseudo-random usage. Many Bandit findings are in third-party packages within `venv` and not actionable in-repo.

Files modified (high level):
- dashboard/components/agent_management.py
- api/routers/security_alerts.py
- core/attack_detection.py
- api/routers/mobile.py
- qa_utilities.py
- utils/faq_engine.py
- qa_dashboard.py
- qa_database.py
- dashboard/realtime.py
- api/routers/qa.py

Remaining manual review items:
- Replace placeholder empty strings and Arabic text that appear as enum values or dict keys in `qa_database.py`, `qa_utilities.py`, `utils/faq_engine.py`. These are semantic changes that require domain/language review.
- Review any remaining flake8 warnings shown by the final run (unused imports/vars where semantics unclear).

Commands to reproduce locally:
```powershell
# Activate virtualenv
& .\venv\Scripts\Activate.ps1

# Auto-fix and format
ruff check --fix . --exclude venv
isort . --profile black --skip venv
black . --line-length 120 --exclude "(venv)"

# Lint and test
flake8 . --exclude venv --max-line-length=120
python -m pytest -q

# Security scan
bandit -r . -x venv
```

Next recommended steps:
1. Human review of Arabic/text placeholders and replacement with intended content.
2. Commit changes and open a PR for code review.
3. (Optional) Run full `bandit` and triage any high/medium severity findings relating to your code.

If you want, I can:
- Commit changes and create a PR.
- Produce a patch set showing diffs for each modified file.
- Start a branch `auto/fix-lints` and push changes (requires git credentials/local push).

