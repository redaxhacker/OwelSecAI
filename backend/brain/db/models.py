"""
OwelSec AI Database — SQLAlchemy models.

Supports both SQLite (local dev) and PostgreSQL (Azure production).
Configure via DATABASE_URL in .env.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, DateTime, Float, Integer, String, Text, JSON, create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


def generate_uuid() -> str:
    return str(uuid.uuid4())


class Scan(Base):
    """Persisted scan record."""

    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target = Column(String(2048), nullable=False, index=True)
    state = Column(String(20), nullable=False, default="queued")  # queued/running/completed/failed
    progress = Column(Integer, nullable=False, default=1)
    stage = Column(String(200), nullable=False, default="Queued")
    strix_results = Column(JSON, nullable=True, default=list)
    analysis = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    output_file = Column(String(512), nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        """Serialize to JSON-safe dict for API responses."""
        return {
            "scan_id": self.id,
            "target": self.target,
            "state": self.state,
            "progress": self.progress,
            "stage": self.stage,
            "strix_results": self.strix_results or [],
            "analysis": self.analysis,
            "error": self.error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
