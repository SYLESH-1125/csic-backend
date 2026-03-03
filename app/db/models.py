import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Integer, Boolean, Float, Text
from app.db.base import Base


# ---------------------------------------------------------------------------
# Original audit ledger — NOT modified; backward-compatible additions only
# ---------------------------------------------------------------------------

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String, nullable=False)
    sha256_hash = Column(String, nullable=False)
    previous_hash = Column(String, nullable=True)
    merkle_root = Column(String, nullable=True)          # NEW: Merkle seal
    upload_time = Column(DateTime, default=datetime.utcnow)
    file_size = Column(Integer, nullable=False)
    uploader = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)             # NEW: origin IP
    ingestion_mode = Column(String, nullable=True)        # NEW: manual/cloud/agent
    status = Column(String, default="ingested")


# ---------------------------------------------------------------------------
# JIT Ephemeral Session Table
# ---------------------------------------------------------------------------

class IngestionSession(Base):
    """
    Short-lived session record created at ingestion entry.
    Enforces IP binding, TTL, and burn-on-use semantics.
    """
    __tablename__ = "ingestion_sessions"

    session_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    bound_ip = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    mode = Column(String, nullable=False)                 # manual | cloud | agent
    created_at = Column(DateTime, default=datetime.utcnow)
    audit_id = Column(String, nullable=True)              # linked after ledger commit


# ---------------------------------------------------------------------------
# Quarantine Log Table
# ---------------------------------------------------------------------------

class QuarantineLog(Base):
    """
    Records files that failed sandbox triage.
    Legally traceable quarantine chain-of-custody.
    """
    __tablename__ = "quarantine_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    original_filename = Column(String, nullable=False)
    quarantine_path = Column(String, nullable=False)
    sha256_hash = Column(String, nullable=True)
    reason = Column(String, nullable=False)               # ZIP_BOMB | MAGIC_MISMATCH | MALWARE | ENTROPY_HIGH
    risk_score = Column(Float, nullable=True)
    details = Column(Text, nullable=True)                 # JSON-encoded detail blob
    detected_at = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String, nullable=True)
    ingestion_mode = Column(String, nullable=True)
    session_id = Column(String, nullable=True)
