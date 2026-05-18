"""Lightweight SQLAlchemy helper for production DB support (Postgres) with fallback to SQLite."""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from secrets_manager import get_secret

# Resolve database URL from secrets manager or environment
DATABASE_URL = get_secret('DATABASE_URL') or os.getenv('DATABASE_URL') or os.getenv('DB_PATH') or 'sqlite:///agentic_iam.db'

engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_engine():
    return engine


def get_session():
    return SessionLocal()
