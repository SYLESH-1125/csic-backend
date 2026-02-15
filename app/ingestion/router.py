from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.ingestion.service import ingest_file
from app.schemas.audit import AuditResponse

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/upload-log", response_model=AuditResponse)
async def upload_log(
    file: UploadFile = File(...),
    uploader: str | None = None,
    db: Session = Depends(get_db)
):
    try:
        content = await file.read()

        result = ingest_file(db, file.filename, content, uploader)

        from app.parsing.service import process_log_file
        process_log_file(file.filename, content, result.sha256_hash, result.id)

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

from app.ingestion.integrity import verify_file_integrity


from app.ingestion.integrity import (
    verify_file_integrity,
    verify_hash_chain
)

@router.get("/verify/{audit_id}")
def verify_log(audit_id: str, db: Session = Depends(get_db)):
    return verify_file_integrity(db, audit_id)


@router.get("/verify-chain")
def verify_chain(db: Session = Depends(get_db)):
    return verify_hash_chain(db)

