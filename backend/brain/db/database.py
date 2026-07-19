"""
OwelSec AI Database — engine and session management.

Usage:
    from db.database import get_db, init_db

    # At app startup:
    init_db()

    # In request handlers:
    db = get_db()
    scan = db.query(Scan).get(scan_id)
    db.close()
"""

import logging
import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from db.models import Base

load_dotenv()
logger = logging.getLogger("owelsecai.db")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set. Please check your .env file.")

if DATABASE_URL.startswith("sqlite:///"):
    db_path = DATABASE_URL.replace("sqlite:///", "", 1)
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

# SQLite needs check_same_thread=False for Flask's threaded mode
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,
    pool_pre_ping=True,  # reconnect on stale connections (important for Azure)
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def init_db() -> None:
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized: %s", DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL)


def get_db() -> Session:
    """Get a new database session. Caller must close it."""
    return SessionLocal()
