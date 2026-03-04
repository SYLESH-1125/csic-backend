"""
app/ingestion/service.py
-------------------------
Core ingestion service layer.

Responsibilities:
  - Legacy direct-upload ingestion (backward-compatible)
  - JIT session creation for all three entry modes
  - Cloud OAuth2 ingest helper (server-to-server stream)
  - Telemetry link generation for agentless extraction
"""

import hashlib
import os
import stat
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from app.config import settings
from app.core.logging import logger
from app.core.security import compute_sha256
from app.db.models import AuditLog
from app.ingestion.auth_gateway import SessionStore, _extract_client_ip
from app.ingestion.secure_ledger import commit_to_ledger
from app.ingestion.sandbox import run_sync_triage, run_sync_deep_scan, async_malware_scan, collect_triage_info
from app.ingestion.audit_trail import build_trail_from_legacy_upload


# ---------------------------------------------------------------------------
# Legacy helpers (preserved for backward compatibility)
# ---------------------------------------------------------------------------

RAW_PATH = Path(settings.RAW_STORAGE_PATH)
WORM_PATH = Path(settings.WORM_STORAGE_PATH)


def get_last_hash(db: Session) -> Optional[str]:
    last = db.query(AuditLog).order_by(AuditLog.upload_time.desc()).first()
    return last.sha256_hash if last else None


def save_raw_file(filename: str, content: bytes) -> str:
    RAW_PATH.mkdir(parents=True, exist_ok=True)
    file_path = RAW_PATH / filename
    with open(file_path, "wb") as f:
        f.write(content)
    return str(file_path)


# ---------------------------------------------------------------------------
# Legacy direct-upload ingest  (original endpoint — UNCHANGED behaviour)
# ---------------------------------------------------------------------------

def ingest_file(
    db: Session,
    filename: str,
    content: bytes,
    uploader: Optional[str] = None,
    source_ip: Optional[str] = None,
    ingestion_mode: str = "legacy",
) -> AuditLog:
    """
    Original synchronous ingest path retained for backward compatibility.
    Called by POST /api/ingestion/upload-log.
    Now includes full sandbox triage before ledger commit.
    """
    import tempfile

    sandbox_passed = False
    triage_info: dict = {}
    quarantine_reason: str | None = None

    try:
        file_hash = compute_sha256(content)

        # Write to a temp file so sandbox can operate on it by path
        tmp_dir = Path(tempfile.mkdtemp(prefix="legacy_triage_"))
        tmp_file = tmp_dir / filename
        tmp_file.write_bytes(content)

        try:
            # ── Collect triage diagnostics for audit trail ────────────────
            triage_info = collect_triage_info(tmp_file)

            # ── Sandbox triage (synchronous ZIP bomb + magic byte) ────────
            quarantine_record = run_sync_triage(
                file_path=tmp_file,
                db=db,
                source_ip=source_ip,
                ingestion_mode=ingestion_mode,
                session_id=None,
            )

            if quarantine_record is not None:
                quarantine_reason = quarantine_record.reason
                logger.warning(
                    f"[IngestService] File quarantined during legacy upload: "
                    f"{filename} reason={quarantine_record.reason}"
                )
                raise ValueError(
                    f"File failed sandbox triage: {quarantine_record.reason} "
                    f"(risk_score={quarantine_record.risk_score})"
                )

            # ── Deep scan (synchronous — entropy + YARA + extension) ──────
            deep_record = run_sync_deep_scan(
                file_path=tmp_file,
                db=db,
                source_ip=source_ip,
                ingestion_mode=ingestion_mode,
                session_id=None,
            )

            if deep_record is not None:
                quarantine_reason = deep_record.reason
                logger.warning(
                    f"[IngestService] File quarantined by deep scan: "
                    f"{filename} reason={deep_record.reason}"
                )
                raise ValueError(
                    f"File failed deep scan: {deep_record.reason} "
                    f"(risk_score={deep_record.risk_score})"
                )

            # All sandbox checks passed
            sandbox_passed = True

            # ── Persist raw file ──────────────────────────────────────────
            raw_path = save_raw_file(filename, content)

            # ── Ledger commit ─────────────────────────────────────────────
            previous_hash = get_last_hash(db)

            audit_entry = AuditLog(
                filename=filename,
                sha256_hash=file_hash,
                previous_hash=previous_hash,
                upload_time=datetime.utcnow(),
                file_size=len(content),
                uploader=uploader,
                source_ip=source_ip,
                ingestion_mode=ingestion_mode,
                status="ingested",
            )
            db.add(audit_entry)
            db.commit()
            db.refresh(audit_entry)

            # ── Build audit trail JSON ────────────────────────────────────
            audit_entry._audit_trail = build_trail_from_legacy_upload(
                ingestion_mode=ingestion_mode,
                source_ip=source_ip or "unknown",
                file_name=filename,
                file_size_bytes=len(content),
                content=content,
                sandbox_passed=True,
                ledger_entry_id=audit_entry.id,
                sha256_hash=file_hash,
                previous_hash=previous_hash,
                worm_storage_path=raw_path,
                **triage_info,
            )

            logger.info(f"[IngestService] Legacy ledger entry created: {filename}")
            return audit_entry

        finally:
            # Always clean up the triage temp directory
            shutil.rmtree(tmp_dir, ignore_errors=True)

    except ValueError:
        raise
    except Exception as exc:
        db.rollback()
        logger.error(f"[IngestService] Legacy ingestion failed: {exc}")
        raise


# ---------------------------------------------------------------------------
# JIT Session creation helpers (NODE 1 — Entry Routes)
# ---------------------------------------------------------------------------

def create_manual_session(db: Session, request: Request) -> dict:
    """
    Create an ephemeral JIT session for manual (UI) uploads.

    Returns a dict with session_id, websocket_url, and expires_at so the
    UI client can initiate the WebSocket stream.
    """
    store = SessionStore(db)
    client_ip = _extract_client_ip(request)
    session = store.create(bound_ip=client_ip, mode="manual")

    ws_url = _build_ws_url(request, session.session_id)
    logger.info(
        f"[IngestService] Manual session created: {session.session_id} ip={client_ip}"
    )
    return {
        "session_id": session.session_id,
        "websocket_url": ws_url,
        "expires_at": session.expires_at.isoformat() + "Z",
        "mode": "manual",
        "bound_ip": client_ip,
    }


def create_cloud_session(
    db: Session,
    request: Request,
    oauth_token: Optional[str] = None,
    cloud_provider: str = "generic",
) -> dict:
    """
    Create an ephemeral session for cloud drive / S3 / Azure pull.

    Validates the OAuth2 token (placeholder — extend with provider SDK),
    then issues a JIT session so the server-to-server streaming proxy can
    open the WebSocket channel.
    """
    # OAuth2 token validation (extensible provider hook)
    _validate_oauth_token(oauth_token, cloud_provider)

    store = SessionStore(db)
    client_ip = _extract_client_ip(request)
    session = store.create(bound_ip=client_ip, mode="cloud")

    ws_url = _build_ws_url(request, session.session_id)
    logger.info(
        f"[IngestService] Cloud session created: {session.session_id} "
        f"provider={cloud_provider} ip={client_ip}"
    )
    return {
        "session_id": session.session_id,
        "websocket_url": ws_url,
        "expires_at": session.expires_at.isoformat() + "Z",
        "mode": "cloud",
        "cloud_provider": cloud_provider,
        "bound_ip": client_ip,
    }


def create_telemetry_link(db: Session, request: Request) -> dict:
    """
    Generate an agentless telemetry collection link.

    The returned ephemeral_token and websocket_url are sent to a victim
    endpoint.  The victim's extraction agent uses them to open a JIT-bound
    WebSocket and stream log artefacts to this server.
    """
    store = SessionStore(db)
    client_ip = _extract_client_ip(request)
    session = store.create(bound_ip=client_ip, mode="agent")

    ws_url = _build_ws_url(request, session.session_id)
    logger.info(
        f"[IngestService] Telemetry link generated: {session.session_id} ip={client_ip}"
    )
    return {
        "ephemeral_token": session.session_id,
        "websocket_url": ws_url,
        "expires_at": session.expires_at.isoformat() + "Z",
        "mode": "agent",
        "bound_ip": client_ip,
        "instructions": (
            "Connect to websocket_url using the ephemeral_token as session_id. "
            "Stream log chunks as JSON: {chunk_number, chunk_hash, data(b64), is_final}."
        ),
    }


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

def _build_ws_url(request: Request, session_id: str) -> str:
    """
    Construct the full WebSocket URL for the secure stream endpoint,
    using the same host/port as the incoming request.
    """
    scheme = "wss" if request.url.scheme == "https" else "ws"
    host = request.headers.get("host", request.url.netloc)
    return f"{scheme}://{host}/ws/secure-stream/{session_id}"


def _validate_oauth_token(token: Optional[str], provider: str) -> None:
    """
    OAuth2 token validation stub.
    Replace this with provider-specific SDK calls (Google Drive, AWS STS,
    Azure AD) based on the *provider* argument.

    Raises:
        ValueError: If the token is missing or invalid.
    """
    if not token:
        raise ValueError(
            f"OAuth2 token required for cloud ingestion (provider={provider})."
        )
    # TODO: Implement provider-specific token introspection
    # Example for Google: google.oauth2.id_token.verify_oauth2_token(...)
    logger.debug(
        f"[IngestService] OAuth2 token accepted for provider={provider} "
        f"(introspection stub — extend for production use)."
    )

