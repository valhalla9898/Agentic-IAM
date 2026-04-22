README content with all English only
# 🚀 Agentic-IAM - Enterprise AI Agent Identity & Access Management

Production-ready IAM system for managing AI agents

## Quick Start
- Clone: git clone https://github.com/valhalla9898/Agentic-IAM.git
- Setup: python -m venv .venv && .\.venv\Scripts\Activate
- Install: pip install -r requirements.txt
- Run: python run_gui.py (Dashboard) or python api/main.py (API)

## Documentation
- Dashboard: http://localhost:8501
- API Docs: http://localhost:8000/docs
- GraphQL: http://localhost:8000/graphql

## Core Features
✅ Secure Authentication (mTLS, OAuth 2.0)
✅ Authorization & Permissions (RBAC, ABAC)
✅ Session Management
✅ Credential Management
✅ Audit & Compliance (GDPR, HIPAA, SOX)
✅ Dashboard & APIs

## Test Status
- 88/88 tests passing
- 6 E2E tests
- 82 unit tests
- 0 critical errors

## Deployment
```bash
docker build -t agentic-iam:latest .
docker run -p 8501:8501 -p 8000:8000 agentic-iam:latest
```

## Links
- GitHub: https://github.com/valhalla9898/Agentic-IAM
- License: MIT
- Status: Production Ready

---

For detailed documentation, see docs/ folder (ARCHITECTURE_EN.md, EXAMPLES_EN.md, FILES_EN.md, QUICK_START_EN.md)

Last Updated: April 22, 2026
