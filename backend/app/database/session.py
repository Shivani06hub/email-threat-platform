"""
Database connection setup using SQLAlchemy.

Uses SQLite for now (a single local file: app.db). Because we're going
through the ORM (not raw SQL), moving to PostgreSQL later just means
changing DATABASE_URL in .env -- the model code below doesn't change.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.core.config import settings

# connect_args is only needed for SQLite (allows use across threads,
# which FastAPI's request handling requires). Postgres won't need this.
connect_args = {"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    FastAPI dependency: gives each request its own DB session,
    and always closes it afterwards -- even if the request errors out.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()