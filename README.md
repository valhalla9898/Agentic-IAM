# Agentic-IAM

[![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)](#status)
[![CI](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/ci.yml)
[![E2E](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/playwright-e2e.yml/badge.svg?branch=main)](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/playwright-e2e.yml)
[![Security Scan](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/security.yml)
[![AI CLI Smoke](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/ai-cli-smoke.yml/badge.svg?branch=main)](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/ai-cli-smoke.yml)
[![Pre-commit](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/pre-commit.yml/badge.svg?branch=main)](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/pre-commit.yml)

Agentic-IAM is an enterprise-grade Identity and Access Management platform for AI agent ecosystems.

## Status
- Production-ready baseline
- Full test suite green (unit/integration/e2e)
- Unified quality gate available locally and in CI

## Quick Start
1. Create and activate a virtual environment.
2. Install dependencies:
   - `pip install -r requirements.txt`
3. Run the dashboard:
   - `python run_gui.py`
4. Open `http://localhost:8501`

## AI Quick Start
- Package CLI:
  - `agentic-iam-ai "How to enable mTLS?"`
- PowerShell:
  - `.\ask_ai.ps1 "How to enable mTLS?"`
- Command Prompt:
  - `ask_ai.bat "How to enable mTLS?"`
- Optional modes:
  - `--model knowledge`
  - `--model openai:gpt-3.5-turbo` (requires `OPENAI_API_KEY`)

## Quality Checks
- Full local gate:
  - `python scripts/check_all.py`
- Quick gate (no E2E):
  - `python scripts/check_all.py --quick`
- PowerShell wrapper:
  - `.\check_all.ps1`

## Reproducible Dependencies
- Install pinned environment:
  - `pip install -r requirements-lock.txt`
- Refresh lockfile after dependency changes:
  - `python scripts/update_lockfile.py`

## Pre-commit Setup
- Install hooks:
  - `pre-commit install`
- Run manually on all files:
  - `pre-commit run --all-files`

## Documentation
- Delivery runbook:
  - [RUNBOOK.md](RUNBOOK.md)
- Detailed project guide (full previous README):
  - [docs/README_DETAILED.md](docs/README_DETAILED.md)
- Development notes:
  - [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)

## API Docs
- Once running, open:
  - `http://localhost:8000/docs`

## License
MIT (see [LICENSE](LICENSE)).
