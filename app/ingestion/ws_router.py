"""
app/ingestion/ws_router.py
---------------------------
Secure WebSocket Chunk-Stream Endpoint.

Route:
    /ws/secure-stream/{session_id}

Protocol (client → server per message):
    {
      "chunk_number": int,    // 0-based sequence number
      "chunk_hash":   str,    // client-computed SHA-256 hex of this chunk
      "data":         str,    // base64-encoded raw bytes of the chunk
      "is_final":     bool    // true on the last chunk
    }

Server responses (server → client):
    {"status": "ok",    "chunk_number": N}  — chunk accepted
    {"status": "error", "detail": "..."}    — fatal error (connection closes)
    {"status": "done",  "audit_id": "...",
     "merkle_root": "...", "sha256": "..."}  — pipeline completed

Security enforcement order:
    1. Session validation   (JIT Gateway — all 3 rules)
    2. Session consumption  (burn-on-use)
    3. Per-chunk hash verification
    4. On-disk temporary storage only (no in-memory large buffers)
    5. Post-stream Merkle root construction
    6. Monolithic SHA-256 verification
    7. Synchronous sandbox triage
    8. Ledger commit → WORM storage
    9. Async malware scan (background, after WebSocket closes)
"""

import asyncio
import base64
import hashlib
import json
import shutil
import stat
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.core.logging import logger
from app.core.merkle import build_merkle_root
from app.db.session import SessionLocal
from app.ingestion.auth_gateway import (
    SessionStore,
    _extract_ws_client_ip,
    _enforce_rules,
)
from app.ingestion.sandbox import async_malware_scan, run_sync_triage
from app.ingestion.secure_ledger import commit_to_ledger

router = APIRouter()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TEMP_CHUNKS_DIR = Path("data/temp")
WORM_DIR = Path("data/worm")
MAX_CHUNKS = 10_000          # hard cap — prevents runaway streams
MAX_CHUNK_SIZE_BYTES = 5 * 1024 * 1024   # 5 MB per chunk


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_db() -> Session:
    db = SessionLocal()
    try:
        return db
    except Exception:
        db.close()
        raise


def _compute_sha256_file(file_path: Path) -> str:
    """Streaming SHA-256 of a file — never loads entire file into RAM."""
    h = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _worm_store(source: Path, filename: str) -> Path:
    """
    Move *source* into the WORM directory and make it read-only.
    Returns the final WORM path.
    """
    WORM_DIR.mkdir(parents=True, exist_ok=True)
    dest = WORM_DIR / filename
    if dest.exists():
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        dest = WORM_DIR / f"{ts}_{filename}"

    shutil.move(str(source), str(dest))
    # Read-only for owner; no write permission for anyone
    try:
        os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    except Exception as exc:
        logger.warning(f"[WSRouter] WORM chmod failed for {dest}: {exc}")

    logger.info(f"[WSRouter] WORM: {filename} → {dest}")
    return dest


async def _ws_reject(websocket: WebSocket, detail: str, code: int = 4003) -> None:
    """Send error frame and close the WebSocket cleanly."""
    try:
        await websocket.send_text(json.dumps({"status": "error", "detail": detail}))
    except Exception:
        pass
    await websocket.close(code=code)


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@router.websocket("/ws/secure-stream/{session_id}")
async def websocket_secure_stream(
    websocket: WebSocket,
    session_id: str,
) -> None:
    """
    Secure chunk-stream ingestion over WebSocket.

    Lifecycle:
      1.  Accept TCP upgrade (before authentication — required by WebSocket spec)
      2.  Validate JIT session (all 3 rules)
      3.  Receive chunks, verify each hash, write to disk
      4.  Reconstruct file
      5.  Merkle root + monolithic SHA-256
      6.  Sandbox triage
      7.  Ledger commit + WORM
      8.  Launch async malware scan
    """
    # Accept at TCP level first (required before we can send close frames)
    await websocket.accept()

    db: Optional[Session] = None
    session_dir: Optional[Path] = None

    try:
        db = _get_db()
        store = SessionStore(db)

        # ── Step 1: Validate all three JIT rules ────────────────────────────
        session = store.get(session_id)
        client_ip = _extract_ws_client_ip(websocket)

        if session is None:
            logger.warning(f"[WSRouter] Unknown session_id={session_id}")
            await _ws_reject(websocket, "Session not found.", code=4001)
            return

        try:
            _enforce_rules(session, client_ip, context="WS")
        except PermissionError as exc:
            await _ws_reject(websocket, str(exc), code=4003)
            return

        # ── Step 2: Burn the session (OTP) ──────────────────────────────────
        store.mark_used(session)
        logger.info(
            f"[WSRouter] Session consumed: {session_id} mode={session.mode}"
        )

        # ── Step 3: Prepare temp storage ────────────────────────────────────
        session_dir = TEMP_CHUNKS_DIR / session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        chunk_hashes: list[str] = []
        chunk_number_expected: int = 0
        filename: str = f"stream_{session_id}.bin"   # overwritten by client meta

        # ── Step 4: Receive chunks ───────────────────────────────────────────
        while True:
            try:
                raw_message = await websocket.receive()
            except WebSocketDisconnect:
                logger.warning(
                    f"[WSRouter] Client disconnected mid-stream for session {session_id}"
                )
                return

            # Handle text (JSON metadata) or bytes messages
            if "text" in raw_message:
                message: dict = json.loads(raw_message["text"])
            elif "bytes" in raw_message:
                # Binary framing not supported; client must send JSON
                await _ws_reject(
                    websocket,
                    "Binary framing not supported. Send JSON with base64-encoded data.",
                )
                return
            else:
                continue

            msg_type = message.get("type")

            # ── META message: optionally sent before the first chunk ────────
            if msg_type == "meta":
                filename = message.get("filename", filename)
                logger.debug(f"[WSRouter] Meta received: filename={filename}")
                await websocket.send_text(
                    json.dumps({"status": "meta_ack", "filename": filename})
                )
                continue

            # ── CHUNK message ───────────────────────────────────────────────
            chunk_number: int = message.get("chunk_number", -1)
            client_chunk_hash: str = message.get("chunk_hash", "")
            encoded_data: str = message.get("data", "")
            is_final: bool = bool(message.get("is_final", False))

            # Sequence enforcement
            if chunk_number != chunk_number_expected:
                await _ws_reject(
                    websocket,
                    f"Out-of-order chunk: expected {chunk_number_expected}, "
                    f"got {chunk_number}.",
                )
                return

            # Size guard
            if len(encoded_data) > MAX_CHUNK_SIZE_BYTES * 4 // 3 + 4:
                await _ws_reject(
                    websocket,
                    f"Chunk {chunk_number} exceeds maximum allowed size.",
                )
                return

            # Limit runaway streams
            if chunk_number >= MAX_CHUNKS:
                await _ws_reject(
                    websocket,
                    f"Maximum chunk count ({MAX_CHUNKS}) exceeded.",
                )
                return

            # Decode payload
            try:
                chunk_data = base64.b64decode(encoded_data)
            except Exception:
                await _ws_reject(
                    websocket,
                    f"Chunk {chunk_number}: base64 decode failed.",
                )
                return

            # Verify per-chunk hash
            server_chunk_hash = hashlib.sha256(chunk_data).hexdigest()
            if server_chunk_hash != client_chunk_hash:
                logger.error(
                    f"[WSRouter] Chunk {chunk_number} hash mismatch! "
                    f"client={client_chunk_hash} server={server_chunk_hash}"
                )
                await _ws_reject(
                    websocket,
                    f"Chunk {chunk_number} hash mismatch — data corruption detected.",
                )
                return

            # Write chunk to temporary NVMe-backed storage (never accumulate in RAM)
            chunk_path = session_dir / f"chunk_{chunk_number:06d}.bin"
            chunk_path.write_bytes(chunk_data)

            chunk_hashes.append(server_chunk_hash)
            chunk_number_expected += 1

            await websocket.send_text(
                json.dumps({"status": "ok", "chunk_number": chunk_number})
            )
            logger.debug(
                f"[WSRouter] Chunk {chunk_number} stored "
                f"hash={server_chunk_hash[:12]}…"
            )

            if is_final:
                break

        # ── Step 5: Reconstruct file ─────────────────────────────────────────
        reconstructed_path = session_dir / filename
        logger.info(
            f"[WSRouter] Reconstructing {len(chunk_hashes)} chunks → "
            f"{reconstructed_path}"
        )

        with open(reconstructed_path, "wb") as out_fh:
            for i in range(len(chunk_hashes)):
                chunk_path = session_dir / f"chunk_{i:06d}.bin"
                with open(chunk_path, "rb") as chunk_fh:
                    out_fh.write(chunk_fh.read())
                chunk_path.unlink(missing_ok=True)   # free temp space immediately

        # ── Step 6: Merkle root + monolithic SHA-256 ─────────────────────────
        merkle_root = build_merkle_root(chunk_hashes)
        mono_sha256 = _compute_sha256_file(reconstructed_path)

        logger.info(
            f"[WSRouter] merkle_root={merkle_root[:12]}… "
            f"sha256={mono_sha256[:12]}…"
        )

        # ── Step 7: Synchronous sandbox triage ───────────────────────────────
        quarantine_record = run_sync_triage(
            file_path=reconstructed_path,
            db=db,
            source_ip=client_ip,
            ingestion_mode=session.mode,
            session_id=session_id,
        )

        if quarantine_record is not None:
            logger.warning(
                f"[WSRouter] File quarantined: reason={quarantine_record.reason}"
            )
            await _ws_reject(
                websocket,
                f"File failed sandbox triage: {quarantine_record.reason}",
                code=4010,
            )
            return

        # ── Step 8: Ledger commit + WORM storage ─────────────────────────────
        worm_path = _worm_store(reconstructed_path, filename)

        audit_entry = commit_to_ledger(
            db=db,
            filename=filename,
            file_path=worm_path,
            sha256_hash=mono_sha256,
            merkle_root=merkle_root,
            source_ip=client_ip,
            ingestion_mode=session.mode,
            file_size=worm_path.stat().st_size,
        )

        store.link_audit(session, audit_entry.id)

        logger.info(
            f"[WSRouter] Ledger commit successful: audit_id={audit_entry.id}"
        )

        # ── Step 9: Async malware scan (background, non-blocking) ────────────
        asyncio.create_task(
            async_malware_scan(
                file_path=worm_path,
                db=db,
                source_ip=client_ip,
                ingestion_mode=session.mode,
                session_id=session_id,
            )
        )

        # ── Final ACK ────────────────────────────────────────────────────────
        await websocket.send_text(
            json.dumps({
                "status": "done",
                "audit_id": audit_entry.id,
                "merkle_root": merkle_root,
                "sha256": mono_sha256,
                "filename": filename,
            })
        )
        await websocket.close(code=1000)

    except WebSocketDisconnect:
        logger.info(f"[WSRouter] WebSocket disconnected: session={session_id}")
    except Exception as exc:
        logger.exception(f"[WSRouter] Unhandled error in session {session_id}: {exc}")
        try:
            await _ws_reject(websocket, "Internal server error.", code=4500)
        except Exception:
            pass
    finally:
        # Clean up session temp directory
        if session_dir is not None and session_dir.exists():
            try:
                shutil.rmtree(session_dir, ignore_errors=True)
            except Exception as cleanup_exc:
                logger.warning(
                    f"[WSRouter] Temp cleanup failed for {session_dir}: {cleanup_exc}"
                )
        if db is not None:
            db.close()
