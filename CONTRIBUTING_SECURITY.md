# CONTRIBUTING — Security Requirements for PRs

All pull requests that affect security-sensitive code must include:

- A risk brief describing the change impact
- Tests covering the change (unit/integration)
- Bandit scan report (if relevant)
- No secrets in code (use detect-secrets pre-commit)
- At least one reviewer with security expertise

Run locally before PR:

```bash
pre-commit run --all-files
bandit -r .
pytest -q
```
