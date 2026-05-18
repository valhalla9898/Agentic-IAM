# Deployment & Migration Notes

1. Configure production database via environment variable `DATABASE_URL` (e.g. `postgresql://user:pass@host:5432/dbname`).
2. Install requirements and Alembic:

```bash
python -m pip install -r requirements.txt
pip install alembic
```

3. Run migrations:

```bash
python scripts/setup_db.py
# or directly: alembic upgrade head
```

4. To run background rotation worker:

```bash
export CELERY_BROKER_URL=redis://localhost:6379/0
celery -A celery_worker.celery_app worker --loglevel=info -Q rotation
```

5. CI is configured in `.github/workflows/ci.yml` to run tests and linters on push/PR.
