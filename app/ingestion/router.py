"""
app/ingestion/router.py
------------------------
Ingestion API router.

Existing endpoints (UNCHANGED — backward-compatible):
    POST /ingestion/upload-log          Legacy single-shot upload
    GET  /ingestion/verify/{audit_id}   Per-file integrity check
    GET  /ingestion/verify-chain        Full hash-chain verification

Phase-1 secure ingestion endpoints (NEW):
    POST /ingestion/manual              Create JIT session for UI upload
    POST /ingestion/cloud               Create JIT session for cloud pull
    POST /ingestion/generate-telemetry-link  Agentless telemetry link

WebSocket endpoint is registered separately in app/ingestion/ws_router.py,
mounted at the application root (not under /api) to avoid prefix conflicts.
"""

from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.ingestion.integrity import verify_file_integrity, verify_hash_chain
from app.ingestion.service import (
    create_cloud_session,
    create_manual_session,
    create_telemetry_link,
    ingest_file,
)
from app.schemas.audit import AuditResponse

router = APIRouter()


# ---------------------------------------------------------------------------
# DB dependency
# ---------------------------------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class CloudIngestRequest(BaseModel):
    oauth_token: str
    cloud_provider: str = "generic"


# ---------------------------------------------------------------------------
# ── LEGACY ENDPOINT (preserved, backward-compatible) ─────────────────────
# ---------------------------------------------------------------------------

@router.post("/upload-log", response_model=AuditResponse)
async def upload_log(
    request: Request,
    file: UploadFile = File(...),
    uploader: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Legacy single-shot log upload.
    Kept for backward compatibility with existing integrations.
    """
    try:
        content = await file.read()
        source_ip = request.client.host if request.client else None

        result = ingest_file(
            db,
            file.filename,
            content,
            uploader=uploader,
            source_ip=source_ip,
            ingestion_mode="legacy",
        )

        from app.parsing.service import process_log_file
        process_log_file(file.filename, content, result.sha256_hash, result.id)

        return result

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# ── PHASE-1 ENTRY ROUTES (NODE 1) ─────────────────────────────────────────
# ---------------------------------------------------------------------------

@router.post("/manual")
async def manual_ingestion_init(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    NODE 1 — MANUAL UPLOAD ENTRY POINT

    Creates a JIT-bound ephemeral session for UI-initiated uploads.

    Returns:
        session_id, websocket_url, expires_at
        The client connects to websocket_url and streams file chunks.
    """
    try:
        return create_manual_session(db, request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/cloud")
async def cloud_ingestion_init(
    request: Request,
    body: CloudIngestRequest,
    db: Session = Depends(get_db),
):
    """
    NODE 1 — CLOUD DRIVE / S3 / AZURE PULL ENTRY POINT

    Validates the OAuth2 token, then creates a JIT session for a
    server-to-server streaming proxy.

    Body:
        oauth_token:    Provider OAuth2 / STS token
        cloud_provider: 'gdrive' | 's3' | 'azure' | 'generic'

    Returns:
        session_id, websocket_url, expires_at, cloud_provider
    """
    try:
        return create_cloud_session(
            db, request,
            oauth_token=body.oauth_token,
            cloud_provider=body.cloud_provider,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/generate-telemetry-link")
async def generate_telemetry_link(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    NODE 1 — AGENTLESS TELEMETRY LINK GENERATOR

    Issues a time-limited, IP-bound, OTP WebSocket link for live
    victim / endpoint artefact extraction without installing an agent.

    Returns:
        ephemeral_token, websocket_url, expires_at, usage instructions
    """
    try:
        return create_telemetry_link(db, request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# ── INTEGRITY VERIFICATION (preserved) ────────────────────────────────────
# ---------------------------------------------------------------------------

@router.get("/verify/{audit_id}")
def verify_log(audit_id: str, db: Session = Depends(get_db)):
    """Verify SHA-256 integrity for a single audited file."""
    return verify_file_integrity(db, audit_id)


@router.get("/verify-chain")
def verify_chain(db: Session = Depends(get_db)):
    """Verify the complete cryptographic hash chain across all audit records."""
    return verify_hash_chain(db)


