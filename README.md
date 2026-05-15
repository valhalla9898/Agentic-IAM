# Agentic-IAM

Agentic-IAM is an agent-centric Identity & Access Management (IAM) toolkit implemented in Python. It combines a Streamlit-based administration dashboard, REST API endpoints, audit and compliance tooling, and deployment scaffolding for local, containerized, and cloud environments.

**Status:** Active — development and maintenance in this repository.

---

**Table of contents**

- **Project overview**
- **Quickstart**
- **Architecture & components**
- **Configuration**
- **Running locally**
- **Testing**
- **Docker & deployment**
- **Security**
- **Contributing**
- **Repository layout**
- **License & contact**

---

**Project overview**

Agentic-IAM provides the building blocks necessary to run and manage agent-driven workflows where agents require authenticated identities, role-based access control, and full auditing of actions. Typical use cases include secure automation, operator consoles, and internal tooling where traceability and compliance are required.

Core features:

- Streamlit admin dashboard for managing users, agents, and audit logs
- FastAPI-based API for integrations and programmatic access
- Audit logging and compliance utilities
- Scripts and manifests for container and Azure deployments
- CLI utilities for bootstrapping and local maintenance

---

**Quickstart**

Prerequisites

- Python 3.9 or later
- Git
- (Optional) Docker for containerized runs

Local quickstart (recommended for development)

1. Clone the repository:

```bash
git clone https://github.com/valhalla9898/Agentic-IAM
cd Agentic-IAM-main
```

2. Create and activate a virtual environment:

PowerShell:

```powershell
python -m venv .venv
.venv\\Scripts\\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

macOS / Linux:

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

3. Bootstrap an admin user (interactive):

```bash
python setup_admin.py
```

4. Launch the Streamlit dashboard:

```bash
python run_gui.py
```

Open your browser at http://localhost:8501

---

**Architecture & components**

- `app.py` / `run_gui.py` — Streamlit dashboard entry points and UI components
- `api/` — FastAPI application and router modules (API surface)
- `audit_compliance.py`, `qa_*` — audit, QA, and analytics helpers
- `session_manager.py`, `credential_manager.py` — session and credential utilities
- `deploy-*`, `azure.yaml`, `infra/` — deployment artifacts and automation

This repository intentionally separates UI, API, and infrastructure code to make deployments flexible.

---

**Configuration**

Configuration defaults live in `config/settings.py`. For production, prefer environment variables or a secret manager.

Important configuration keys

- `ENVIRONMENT` — development | staging | production
- `SECRET_KEY` / `ENCRYPTION_KEY` — keep these secret; do not commit them
- `API_HOST`, `API_PORT` — API binding
- `LOG_LEVEL` — DEBUG | INFO | WARN | ERROR
- `ENABLE_AUDIT_LOGGING` — true | false

Recommended practice: Use `.env` files for local development (excluded from VCS) and a managed secrets service (e.g., Azure Key Vault) in production.

---

**Running & Usage**

Run local checks:

```bash
python test_setup.py
```

Start the API (development):

```bash
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

Start the dashboard (development):

```bash
python run_gui.py
```

CLI utilities

- `python setup_admin.py` — create initial admin user
- `python create_full_docx.py` — utility to export documentation

---

**Testing**

This repository uses `pytest`. To run the full test suite:

```bash
pytest -q
```

Notes:

- End-to-end tests use Playwright and may require a running UI server and environment variables (e.g., admin credentials).
- If Playwright tests fail locally, make sure the Streamlit server is running at `http://localhost:8501` and `AGENTIC_IAM_E2E_ADMIN_PASSWORD` is exported for the test run.

---

**Docker & Deployment**

Build and run locally with Docker:

```bash
docker build -t agentic-iam:local .
docker run -p 8501:8501 agentic-iam:local
```

For Azure deployment, see `AZURE_DEPLOYMENT_GUIDE.md` and `azure.yaml` for pipeline and infrastructure references.

---

**Security & Best Practices**

- Do not store secrets in source control; use environment variables or secret stores.
- Rotate keys and review `SECURITY_TESTING.md` and `security_report.json` before production releases.
- Run static analysis (`bandit`, `flake8`) and dependency checks before promoting code.

Suggested commands:

```bash
pip install bandit flake8
bandit -r .
flake8 .
```

---

**Contributing**

We welcome contributions. Please follow these steps:

1. Fork the repository and create a branch matching the change (e.g., `feat/describe-change`).
2. Add tests and update documentation if relevant.
3. Run the test suite locally.
4. Open a Pull Request with a clear description and link issues if applicable.

Commit message guidance: use Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`) for clear history.

---

**Repository layout (high level)**

- `app.py`, `run_gui.py` — UI entry points
- `api/` — API application and routers
- `config/` — configuration and settings
- `scripts/` — maintenance and utility scripts
- `infra/`, `azure.yaml` — deployment artifacts
- `tests/` — unit and integration tests

---

**License**

This project is licensed under the MIT License. See `LICENSE` for details.

---

**Contact & next steps**

- If you want me to: open a Pull Request from `replace-arabic-with-english` into `main`, merge it, or draft a release, tell me which action to take next.
- I can also search the repository for remaining non-English strings and propose translations as separate commits.

---

Thank you — ready for the next step.