PR: feat/infra-ci-alembic-casbin-celery

Summary:
- Added Alembic migrations and `alembic.ini` (initial schema: 0001_initial).
- Added Casbin-based authorization wrapper (`authz.py`) and example policy CSV.
- Added Celery worker scaffold and a credential rotation task.
- Added `auth_oidc.py` and OIDC verification integration in `authentication.py`.
- Added observability scaffold (Prometheus + OpenTelemetry helpers).
- Added append-only audit exporter and integrated audit calls in `database.py`.
- Added Kubernetes/Helm skeletons and CI workflow scaffold (.github/workflows/ci.yml).
- Pinned critical dependencies for CI stability (`alembic==1.10.3`, `celery==5.3.0`, `casbin==1.10.1`, `redis==4.5.0`, `httpx` constrained).
- Fixed several lint issues (tabs -> spaces, trailing whitespace, small import/type fixes).

Tests:
- Local test run: `pytest -q` => 125 passed, 6 skipped.

Remaining manual work / notes:
- Many non-critical lint warnings remain across the codebase (unused imports, placeholder f-strings). Recommend staged follow-up to clean up project files.
- Secrets provider wiring requires cloud credentials (Azure Key Vault / Vault). See `secrets_manager.py` for placeholders.
- Celery requires Redis/RabbitMQ runtime and Docker/k8s wiring (compose/k8s manifests added as skeletons).
- CASBIN policies included as example; review and harden enforcement callsites.
- CI push: this branch needs to be pushed to remote and a PR opened; CI will run tests and migrations.

How to push and open PR:
1. `git push -u origin feat/infra-ci-alembic-casbin-celery`
2. Open PR with title: "feat(infra): add migrations, casbin, celery scaffolds; pin deps"

If you want, I can attempt to push and open the PR now (requires remote credentials).