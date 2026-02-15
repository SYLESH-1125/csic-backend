import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Integer
from app.db.base import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String, nullable=False)
    sha256_hash = Column(String, nullable=False)
    previous_hash = Column(String, nullable=True)
    upload_time = Column(DateTime, default=datetime.utcnow)
    file_size = Column(Integer, nullable=False)
    uploader = Column(String, nullable=True)
    status = Column(String, default="ingested")
