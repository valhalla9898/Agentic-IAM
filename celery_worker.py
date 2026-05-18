"""Celery worker bootstrap for background tasks (credential rotation, audits)."""
from celery import Celery
import os

broker = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
backend = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/1')

celery_app = Celery('agentic_iam', broker=broker, backend=backend)

celery_app.conf.task_routes = {
    'tasks.rotate_credentials': {'queue': 'rotation'}
}

if __name__ == '__main__':
    celery_app.start()
