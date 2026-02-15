import os
from datetime import datetime
from sqlalchemy.orm import Session
from app.db.models import AuditLog
from app.core.security import compute_sha256
from app.config import settings
from app.core.logging import logger


def get_last_hash(db: Session):
    last = db.query(AuditLog).order_by(AuditLog.upload_time.desc()).first()
    return last.sha256_hash if last else None


import stat


from pathlib import Path

RAW_PATH = Path("data/raw")


def save_raw_file(filename: str, content: bytes):
    RAW_PATH.mkdir(parents=True, exist_ok=True)

    file_path = RAW_PATH / filename

    with open(file_path, "wb") as f:
        f.write(content)

    return str(file_path)




def ingest_file(db: Session, filename: str, content: bytes, uploader: str | None = None):
    try:
        file_hash = compute_sha256(content)
        previous_hash = get_last_hash(db)

        save_raw_file(filename, content)

        audit_entry = AuditLog(
            filename=filename,
            sha256_hash=file_hash,
            previous_hash=previous_hash,
            upload_time=datetime.utcnow(),
            file_size=len(content),
            uploader=uploader,
            status="ingested"
        )

        db.add(audit_entry)
        db.commit()
        db.refresh(audit_entry)

        logger.info(f"Ledger entry created: {filename}")

        return audit_entry

    except Exception as e:
        db.rollback()
        logger.error(f"Ingestion failed: {str(e)}")
        raise
