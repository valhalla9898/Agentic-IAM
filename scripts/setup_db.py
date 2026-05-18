"""Helper script to run Alembic migrations programmatically.
Usage: python scripts/setup_db.py
Ensure `DATABASE_URL` env var is set for production DB (Postgres) or leave unset for SQLite.
"""
import os
import subprocess
import sys


def main():
    # prefer installed alembic
    try:
        # run alembic upgrade head
        cmd = [sys.executable, '-m', 'alembic', 'upgrade', 'head']
        env = os.environ.copy()
        print('Running:', ' '.join(cmd))
        subprocess.check_call(cmd, env=env)
        print('Migrations applied successfully')
    except subprocess.CalledProcessError as e:
        print('Migration failed:', e)


if __name__ == '__main__':
    main()
