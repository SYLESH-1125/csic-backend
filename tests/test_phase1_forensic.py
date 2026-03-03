"""
tests/test_phase1_forensic.py
------------------------------
Phase-1 Forensic Ingestion Pipeline — Complete Security Validation Suite

Covers:
  A) JIT Authentication Gateway (IP binding, TTL, burn-on-use, replay)
  B) WebSocket Secure Chunk Stream (hash verify, order, size, abort)
  C) Merkle Tree Integrity (root, proof, tamper detection)
  D) SHA-256 Monolithic Integrity (reconstruction, tamper detection)
  E) Sandbox Security (ZIP bomb, magic bytes, exec renamed, quarantine)
  F) WORM Behavior (read-only, write rejection)
  G) Hash Chain Integrity (chain links, tamper detection)
  H) Concurrency & Session Isolation (unique sessions, no race conditions)
"""

import base64
import hashlib
import io
import json
import os
import stat
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy.orm import Session

from app.core.merkle import (
    build_merkle_root,
    build_merkle_proof,
    verify_merkle_proof,
    verify_merkle_integrity,
)
from app.db.models import AuditLog, IngestionSession, QuarantineLog
from app.ingestion.auth_gateway import SessionStore, _enforce_rules
from app.ingestion.sandbox import (
    check_magic_bytes,
    check_zip_bomb,
    run_sync_triage,
)
from app.ingestion.integrity import verify_hash_chain
from app.ingestion.secure_ledger import commit_to_ledger


# ===========================================================================
# Helpers
# ===========================================================================

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _build_chunk_msg(number: int, data: bytes, is_final: bool = False) -> dict:
    return {
        "chunk_number": number,
        "chunk_hash": _sha256(data),
        "data": _b64(data),
        "is_final": is_final,
    }


def _create_clean_session(db: Session, bound_ip: str = "testclient") -> IngestionSession:
    """Directly insert a valid session into the test DB."""
    store = SessionStore(db)
    return store.create(bound_ip=bound_ip, mode="manual")


def _create_expired_session(db: Session, bound_ip: str = "testclient") -> IngestionSession:
    """Insert an already-expired session."""
    sess = IngestionSession(
        bound_ip=bound_ip,
        expires_at=datetime.utcnow() - timedelta(hours=1),  # expired 1 hour ago
        used=False,
        mode="manual",
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)
    return sess


def _create_used_session(db: Session, bound_ip: str = "testclient") -> IngestionSession:
    """Insert an already-burned session."""
    store = SessionStore(db)
    sess = store.create(bound_ip=bound_ip, mode="manual")
    store.mark_used(sess)
    return sess


def _make_zip_bomb_bytes(expansion_factor: int = 150) -> bytes:
    """
    Create a ZIP file whose uncompressed/compressed ratio exceeds threshold.
    A large slab of zeros compresses to near nothing.
    """
    raw = b"\x00" * (1024 * 1024)  # 1 MB of zeros → compresses to ~1 KB
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Add multiple entries to push ratio over 100
        for i in range(expansion_factor):
            zf.writestr(f"entry_{i:03d}.txt", raw)
    buf.seek(0)
    return buf.read()


def _make_mz_txt_bytes() -> bytes:
    """MZ (Windows PE) header disguised as text content."""
    return b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 200


def _make_clean_log_bytes() -> bytes:
    """Normal forensic log content — should pass all sandbox checks."""
    lines = [
        "2026-03-02T10:00:00Z INFO  System boot detected",
        "2026-03-02T10:00:01Z INFO  User login: analyst@forensics.lab",
        "2026-03-02T10:00:02Z WARN  Unexpected network connection to 10.0.0.5",
        "2026-03-02T10:00:03Z INFO  File access: /var/log/auth.log",
        "2026-03-02T10:00:04Z INFO  Shutdown initiated",
    ]
    return "\n".join(lines).encode()


CHUNK_SIZE = 32 * 1024  # 32 KB per chunk for tests


def _ws_upload_clean(
    client,
    session_id: str,
    content: bytes,
    filename: str = "test.log",
) -> dict:
    """
    Perform a clean WebSocket upload.  Returns the final server message.
    Raises AssertionError if any chunk ACK is not 'ok'.
    """
    chunks = [content[i:i + CHUNK_SIZE] for i in range(0, len(content), CHUNK_SIZE)]
    if not chunks:
        chunks = [b"empty"]

    with client.websocket_connect(f"/ws/secure-stream/{session_id}") as ws:
        ws.send_json({"type": "meta", "filename": filename})
        meta_ack = ws.receive_json()
        assert meta_ack["status"] == "meta_ack", f"Unexpected meta ack: {meta_ack}"

        for i, chunk in enumerate(chunks):
            is_final = i == len(chunks) - 1
            ws.send_json(_build_chunk_msg(i, chunk, is_final))
            ack = ws.receive_json()
            assert ack["status"] == "ok", f"Chunk {i} rejected: {ack}"

        final = ws.receive_json()
    return final


# ===========================================================================
# A) JIT Authentication Gateway
# ===========================================================================

class TestJITGateway:

    def test_manual_session_creation_returns_ws_url(self, client):
        """POST /ingestion/manual must return a websocket_url and session_id."""
        resp = client.post("/api/ingestion/manual")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "session_id" in body
        assert "websocket_url" in body
        assert "expires_at" in body
        assert body["mode"] == "manual"
        assert "/ws/secure-stream/" in body["websocket_url"]

    def test_telemetry_link_returns_ephemeral_token(self, client):
        """POST /ingestion/generate-telemetry-link returns ephemeral_token."""
        resp = client.post("/api/ingestion/generate-telemetry-link")
        assert resp.status_code == 200
        body = resp.json()
        assert "ephemeral_token" in body
        assert "websocket_url" in body
        assert body["mode"] == "agent"

    def test_cloud_session_rejects_missing_token(self, client):
        """POST /ingestion/cloud without OAuth2 token → 401."""
        resp = client.post(
            "/api/ingestion/cloud",
            json={"oauth_token": "", "cloud_provider": "gdrive"},
        )
        assert resp.status_code == 401, resp.text

    def test_cloud_session_accepts_token(self, client):
        """POST /ingestion/cloud with a token → returns session."""
        resp = client.post(
            "/api/ingestion/cloud",
            json={"oauth_token": "fake-valid-token", "cloud_provider": "s3"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["mode"] == "cloud"

    # ── RULE 1: IP Binding ────────────────────────────────────────────────

    def test_ip_binding_same_ip_allowed(self, client, db_session):
        """
        Session bound to 'testclient'. WS connection from TestClient
        appears as 'testclient'. Must succeed.
        """
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()
        content = _make_clean_log_bytes()
        result = _ws_upload_clean(client, sess.session_id, content)
        assert result["status"] == "done", f"Expected done, got: {result}"

    def test_ip_binding_wrong_ip_rejected(self, client, db_session):
        """
        Session bound to '192.168.99.9'. WS connection from TestClient
        appears as 'testclient'. Must fail with error message.
        """
        sess = _create_clean_session(db_session, bound_ip="192.168.99.9")
        db_session.commit()

        with client.websocket_connect(f"/ws/secure-stream/{sess.session_id}") as ws:
            msg = ws.receive_json()

        assert msg["status"] == "error"
        assert "IP binding" in msg["detail"] or "binding" in msg["detail"].lower()

    # ── RULE 2: TTL ───────────────────────────────────────────────────────

    def test_expired_session_rejected(self, client, db_session):
        """Expired session (1 hour ago) must be rejected by TTL rule."""
        sess = _create_expired_session(db_session, bound_ip="testclient")
        db_session.commit()

        with client.websocket_connect(f"/ws/secure-stream/{sess.session_id}") as ws:
            msg = ws.receive_json()

        assert msg["status"] == "error"
        assert "expired" in msg["detail"].lower()

    def test_valid_session_not_rejected_by_ttl(self, client, db_session):
        """Fresh session (just created) must not be rejected by TTL."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()
        # Just verify we don't get an expiry error on first message
        content = b"short test log content"
        result = _ws_upload_clean(client, sess.session_id, content)
        assert result["status"] != "error" or "expired" not in result.get("detail", "")

    # ── RULE 3: Burn-on-Use ───────────────────────────────────────────────

    def test_burn_on_use_second_connection_rejected(self, client, db_session):
        """
        After a successful upload, the session is marked used=True.
        A replay attempt with the same session_id must be rejected.
        """
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        # First upload — must succeed
        content = _make_clean_log_bytes()
        result = _ws_upload_clean(client, sess.session_id, content)
        assert result["status"] == "done", f"First upload failed: {result}"

        # Second attempt with same session_id — must be rejected
        with client.websocket_connect(f"/ws/secure-stream/{sess.session_id}") as ws:
            msg = ws.receive_json()

        assert msg["status"] == "error"
        assert "consumed" in msg["detail"].lower() or "already" in msg["detail"].lower()

    def test_already_used_session_rejected_immediately(self, client, db_session):
        """Pre-burned session must be rejected before sending any data."""
        sess = _create_used_session(db_session, bound_ip="testclient")
        db_session.commit()

        with client.websocket_connect(f"/ws/secure-stream/{sess.session_id}") as ws:
            msg = ws.receive_json()

        assert msg["status"] == "error"
        assert "consumed" in msg["detail"].lower() or "already" in msg["detail"].lower()

    def test_unknown_session_rejected(self, client):
        """Connection with a non-existent session_id must be rejected."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        with client.websocket_connect(f"/ws/secure-stream/{fake_id}") as ws:
            msg = ws.receive_json()

        assert msg["status"] == "error"
        assert "not found" in msg["detail"].lower()


# ===========================================================================
# B) WebSocket Secure Chunk Stream
# ===========================================================================

class TestWebSocketStream:

    def test_single_chunk_upload_creates_ledger_entry(self, client, db_session):
        """Single-chunk upload must produce an AuditLog record."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        content = _make_clean_log_bytes()
        result = _ws_upload_clean(client, sess.session_id, content)

        assert result["status"] == "done"
        assert "audit_id" in result
        assert "merkle_root" in result
        assert "sha256" in result

        # Verify audit record exists in DB
        record = db_session.query(AuditLog).filter(
            AuditLog.id == result["audit_id"]
        ).first()
        assert record is not None
        assert record.sha256_hash == result["sha256"]
        assert record.merkle_root == result["merkle_root"]

    def test_multi_chunk_upload_reconstructs_correctly(self, client, db_session):
        """Multi-chunk upload must produce correct SHA-256 in ledger."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        # Build content larger than one chunk
        content = b"FORENSIC_LOG_ENTRY\n" * 5000  # ~90KB > CHUNK_SIZE
        expected_sha256 = _sha256(content)

        result = _ws_upload_clean(
            client, sess.session_id, content, filename="multi.log"
        )
        assert result["status"] == "done"
        assert result["sha256"] == expected_sha256, (
            f"SHA-256 mismatch: expected {expected_sha256}, got {result['sha256']}"
        )

    def test_invalid_chunk_hash_aborts_connection(self, client, db_session):
        """Server must close connection when chunk_hash mismatches actual data."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        chunk_data = b"legitimate chunk content"
        wrong_hash = _sha256(b"completely different data")  # deliberately wrong

        with client.websocket_connect(f"/ws/secure-stream/{sess.session_id}") as ws:
            ws.send_json({"type": "meta", "filename": "test.log"})
            ws.receive_json()  # meta_ack

            ws.send_json({
                "chunk_number": 0,
                "chunk_hash": wrong_hash,
                "data": _b64(chunk_data),
                "is_final": True,
            })
            resp = ws.receive_json()

        assert resp["status"] == "error"
        assert "hash mismatch" in resp["detail"].lower()

    def test_hash_mismatch_no_ledger_entry(self, client, db_session):
        """No AuditLog record must be created when chunk hash fails."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        count_before = db_session.query(AuditLog).count()

        with client.websocket_connect(f"/ws/secure-stream/{sess.session_id}") as ws:
            ws.send_json({"type": "meta", "filename": "test.log"})
            ws.receive_json()
            ws.send_json({
                "chunk_number": 0,
                "chunk_hash": "a" * 64,  # obviously wrong hash
                "data": _b64(b"some data"),
                "is_final": True,
            })
            ws.receive_json()

        count_after = db_session.query(AuditLog).count()
        assert count_after == count_before, (
            f"Ledger entry was created despite hash mismatch! "
            f"Before={count_before}, After={count_after}"
        )

    def test_out_of_order_chunk_rejected(self, client, db_session):
        """Server must reject chunk_number=1 when expecting chunk_number=0."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        data = b"chunk content"
        with client.websocket_connect(f"/ws/secure-stream/{sess.session_id}") as ws:
            ws.send_json({"type": "meta", "filename": "test.log"})
            ws.receive_json()

            # Send chunk 1 first (skipping 0)
            ws.send_json(_build_chunk_msg(1, data, is_final=False))
            resp = ws.receive_json()

        assert resp["status"] == "error"
        assert "out-of-order" in resp["detail"].lower() or "order" in resp["detail"].lower()

    def test_oversized_chunk_rejected(self, client, db_session):
        """Chunk > 5MB (as base64) must be rejected immediately."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        # 6MB of data
        oversized = b"X" * (6 * 1024 * 1024)
        with client.websocket_connect(f"/ws/secure-stream/{sess.session_id}") as ws:
            ws.send_json({"type": "meta", "filename": "test.log"})
            ws.receive_json()

            ws.send_json(_build_chunk_msg(0, oversized, is_final=True))
            resp = ws.receive_json()

        assert resp["status"] == "error"
        assert "size" in resp["detail"].lower() or "maximum" in resp["detail"].lower()

    def test_binary_framing_rejected(self, client, db_session):
        """Server must reject raw binary websocket messages."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        with client.websocket_connect(f"/ws/secure-stream/{sess.session_id}") as ws:
            # Skip meta, send raw bytes directly
            ws.send_bytes(b"\x00\x01\x02BINARY_PAYLOAD")
            resp = ws.receive_json()

        assert resp["status"] == "error"
        assert "binary" in resp["detail"].lower()

    def test_worm_file_created_after_upload(self, client, db_session):
        """After successful upload, file must exist in WORM directory."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        content = _make_clean_log_bytes()
        result = _ws_upload_clean(
            client, sess.session_id, content, filename="worm_test.log"
        )
        assert result["status"] == "done"

        worm_dir = client._worm_dir
        worm_files = list(worm_dir.glob("*.log"))
        assert len(worm_files) >= 1, (
            f"No .log file found in WORM dir: {list(worm_dir.iterdir())}"
        )

    def test_temp_dir_cleaned_after_successful_upload(self, client, db_session):
        """Temporary chunk directory must be removed after upload completes."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        content = _make_clean_log_bytes()
        _ws_upload_clean(client, sess.session_id, content)

        temp_dir = client._temp_dir
        session_tmp = temp_dir / sess.session_id
        assert not session_tmp.exists(), (
            f"Temp dir not cleaned up: {session_tmp} still exists"
        )


# ===========================================================================
# C) Merkle Tree Integrity
# ===========================================================================

class TestMerkleTree:

    def test_single_chunk_merkle_root_equals_chunk_hash(self):
        """For a single chunk, root IS the leaf hash itself (loop never runs)."""
        chunk_hash = _sha256(b"single chunk")
        root = build_merkle_root([chunk_hash])
        # Single leaf: while len > 1 is False, so root == leaf hash directly
        assert root == chunk_hash

    def test_two_chunk_merkle_root(self):
        """Two chunks → root = sha256(hash0 + hash1)."""
        h0 = _sha256(b"chunk 0")
        h1 = _sha256(b"chunk 1")
        root = build_merkle_root([h0, h1])
        expected = hashlib.sha256(bytes.fromhex(h0) + bytes.fromhex(h1)).hexdigest()
        assert root == expected

    def test_four_chunk_merkle_root(self):
        """Four chunks → correct 2-level tree root."""
        hashes = [_sha256(f"chunk {i}".encode()) for i in range(4)]
        root = build_merkle_root(hashes)
        # Level 1
        p0 = hashlib.sha256(bytes.fromhex(hashes[0]) + bytes.fromhex(hashes[1])).hexdigest()
        p1 = hashlib.sha256(bytes.fromhex(hashes[2]) + bytes.fromhex(hashes[3])).hexdigest()
        # Root
        expected = hashlib.sha256(bytes.fromhex(p0) + bytes.fromhex(p1)).hexdigest()
        assert root == expected

    def test_tampered_chunk_changes_root(self):
        """Modifying one chunk hash must produce a different root."""
        hashes = [_sha256(f"chunk {i}".encode()) for i in range(4)]
        original_root = build_merkle_root(hashes)

        # Tamper chunk index 2
        tampered = list(hashes)
        tampered[2] = _sha256(b"TAMPERED_DATA")
        tampered_root = build_merkle_root(tampered)

        assert original_root != tampered_root, (
            "CRITICAL: Tampered chunk produced identical Merkle root — "
            "integrity guarantee broken!"
        )

    def test_merkle_verify_integrity_pass(self):
        """verify_merkle_integrity must return True for matching root."""
        hashes = [_sha256(f"block {i}".encode()) for i in range(8)]
        root = build_merkle_root(hashes)
        assert verify_merkle_integrity(hashes, root) is True

    def test_merkle_verify_integrity_fail_on_tamper(self):
        """verify_merkle_integrity must return False when root mismatches."""
        hashes = [_sha256(f"block {i}".encode()) for i in range(8)]
        correct_root = build_merkle_root(hashes)

        # Pass wrong root
        bad_root = "a" * 64
        assert verify_merkle_integrity(hashes, bad_root) is False

    def test_merkle_proof_verify_all_leaves(self):
        """Merkle proof must verify correctly for every leaf in an 8-chunk tree."""
        hashes = [_sha256(f"leaf {i}".encode()) for i in range(8)]
        root = build_merkle_root(hashes)

        for i, leaf_hash in enumerate(hashes):
            proof = build_merkle_proof(hashes, i)
            assert verify_merkle_proof(leaf_hash, proof, root) is True, (
                f"Proof verification failed for leaf index {i}"
            )

    def test_merkle_proof_fails_on_tampered_leaf(self):
        """Merkle proof with a tampered leaf must fail verification."""
        hashes = [_sha256(f"leaf {i}".encode()) for i in range(4)]
        root = build_merkle_root(hashes)
        proof = build_merkle_proof(hashes, 0)

        tampered_leaf = _sha256(b"TAMPERED")
        assert verify_merkle_proof(tampered_leaf, proof, root) is False

    def test_empty_chunk_list_raises_valueerror(self):
        """build_merkle_root must raise ValueError on empty input."""
        with pytest.raises(ValueError):
            build_merkle_root([])

    def test_ws_upload_ledger_merkle_matches_recomputed(self, client, db_session):
        """
        After upload, recompute Merkle root from chunk hashes and verify
        it matches the stored value in the ledger.
        """
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        content = b"forensic data line\n" * 100
        chunks = [content[i:i + CHUNK_SIZE] for i in range(0, len(content), CHUNK_SIZE)]
        chunk_hashes = [_sha256(c) for c in chunks]
        expected_root = build_merkle_root(chunk_hashes)

        result = _ws_upload_clean(client, sess.session_id, content, "merkle_check.log")
        assert result["status"] == "done"
        assert result["merkle_root"] == expected_root, (
            f"Server Merkle root differs from client-recomputed root!\n"
            f"  Server:   {result['merkle_root']}\n"
            f"  Recomputed: {expected_root}"
        )


# ===========================================================================
# D) SHA-256 Monolithic Integrity
# ===========================================================================

class TestSHA256Integrity:

    def test_sha256_matches_full_file_content(self, client, db_session):
        """SHA-256 stored in ledger must match hash of original content."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        content = b"SHA256 integrity test content\n" * 200
        expected = _sha256(content)

        result = _ws_upload_clean(client, sess.session_id, content, "sha_test.log")
        assert result["status"] == "done"
        assert result["sha256"] == expected, (
            f"SHA-256 mismatch: expected {expected}, stored {result['sha256']}"
        )

    def test_sha256_different_files_produce_different_hashes(self, client, db_session):
        """Two different files must produce different SHA-256 hashes."""
        content_a = b"File A content - unique identifier AAA"
        content_b = b"File B content - unique identifier BBB"

        for content, mode in [(content_a, "manual"), (content_b, "manual")]:
            sess = _create_clean_session(db_session)
            db_session.commit()
            result = _ws_upload_clean(client, sess.session_id, content, "file.log")
            assert result["status"] == "done"

        records = db_session.query(AuditLog).all()
        hashes = [r.sha256_hash for r in records]
        assert len(set(hashes)) == len(hashes), "Duplicate SHA-256 hashes found!"

    def test_streaming_sha256_matches_in_memory_sha256(self, tmp_path):
        """Streaming SHA-256 (used by WS route) must match in-memory SHA-256."""
        from app.ingestion.ws_router import _compute_sha256_file

        content = os.urandom(512 * 1024)  # 512 KB random data
        file_path = tmp_path / "test_sha.bin"
        file_path.write_bytes(content)

        expected = _sha256(content)
        computed = _compute_sha256_file(file_path)
        assert computed == expected


# ===========================================================================
# E) Sandbox Security
# ===========================================================================

class TestSandboxSecurity:

    # ── ZIP Bomb Detection ────────────────────────────────────────────────

    def test_zip_bomb_detected_by_check_zip_bomb(self, tmp_path):
        """ZIP bomb check must flag file with ratio > 100."""
        bomb_bytes = _make_zip_bomb_bytes(expansion_factor=150)
        bomb_path = tmp_path / "bomb.zip"
        bomb_path.write_bytes(bomb_bytes)

        result = check_zip_bomb(bomb_path)
        assert result is not None, (
            "SECURITY FAILURE: ZIP bomb not detected by check_zip_bomb()"
        )
        assert result["ratio"] > 100

    def test_normal_zip_passes_bomb_check(self, tmp_path):
        """A small normal ZIP must not be flagged as a ZIP bomb."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("readme.txt", "This is a normal, safe ZIP file.")
        zip_path = tmp_path / "normal.zip"
        zip_path.write_bytes(buf.getvalue())

        result = check_zip_bomb(zip_path)
        assert result is None, f"Normal ZIP falsely flagged: {result}"

    def test_non_archive_file_skips_bomb_check(self, tmp_path):
        """Non-archive files must return None from check_zip_bomb (not checked)."""
        log_path = tmp_path / "test.log"
        log_path.write_bytes(_make_clean_log_bytes())
        result = check_zip_bomb(log_path)
        assert result is None

    def test_zip_bomb_quarantined_via_run_sync_triage(self, tmp_path, db_session):
        """run_sync_triage must quarantine ZIP bomb and return QuarantineLog."""
        quarantine_dir = tmp_path / "quarantine"
        quarantine_dir.mkdir()

        bomb_bytes = _make_zip_bomb_bytes(expansion_factor=150)
        bomb_path = tmp_path / "bomb.zip"
        bomb_path.write_bytes(bomb_bytes)

        with patch("app.ingestion.sandbox.QUARANTINE_DIR", quarantine_dir):
            log = run_sync_triage(
                file_path=bomb_path,
                db=db_session,
                source_ip="10.0.0.1",
                ingestion_mode="manual",
            )

        assert log is not None, "ZIP bomb was NOT quarantined!"
        assert log.reason == "ZIP_BOMB"
        quarantine_count = db_session.query(QuarantineLog).filter(
            QuarantineLog.reason == "ZIP_BOMB"
        ).count()
        assert quarantine_count >= 1

    # ── Magic Byte Mismatch Detection ─────────────────────────────────────

    def test_mz_bytes_in_txt_file_flagged(self, tmp_path):
        """MZ header in .txt file must be flagged by magic byte check."""
        malware_as_txt = tmp_path / "disguised.txt"
        malware_as_txt.write_bytes(_make_mz_txt_bytes())

        result = check_magic_bytes(malware_as_txt)
        assert result is not None, (
            "SECURITY FAILURE: MZ header in .txt file NOT detected!"
        )
        assert result["mismatch"] is True
        assert "MZ" in result.get("detected_header", "")

    def test_elf_bytes_in_txt_file_flagged(self, tmp_path):
        """ELF header in .txt file must be flagged."""
        elf_path = tmp_path / "linux_bin.txt"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        result = check_magic_bytes(elf_path)
        assert result is not None, "ELF header in .txt file NOT detected!"
        assert result["mismatch"] is True

    def test_clean_log_file_passes_magic_check(self, tmp_path):
        """Plain text log file must pass magic byte check."""
        log_path = tmp_path / "clean.log"
        log_path.write_bytes(_make_clean_log_bytes())

        result = check_magic_bytes(log_path)
        assert result is None, f"Clean log falsely flagged: {result}"

    def test_mz_in_txt_quarantined_via_run_sync_triage(self, tmp_path, db_session):
        """run_sync_triage must quarantine MZ-in-txt and record MAGIC_MISMATCH."""
        quarantine_dir = tmp_path / "quarantine"
        quarantine_dir.mkdir()

        malware_path = tmp_path / "totally_normal.txt"
        malware_path.write_bytes(_make_mz_txt_bytes())

        with patch("app.ingestion.sandbox.QUARANTINE_DIR", quarantine_dir):
            log = run_sync_triage(
                file_path=malware_path,
                db=db_session,
                source_ip="10.0.0.1",
                ingestion_mode="manual",
            )

        assert log is not None, "Magic byte mismatch was NOT quarantined!"
        assert log.reason == "MAGIC_MISMATCH"

    def test_quarantine_creates_db_record(self, tmp_path, db_session):
        """Quarantine must persist a QuarantineLog record in the database."""
        quarantine_dir = tmp_path / "quarantine"
        quarantine_dir.mkdir()

        malware_path = tmp_path / "malware.txt"
        malware_path.write_bytes(_make_mz_txt_bytes())

        with patch("app.ingestion.sandbox.QUARANTINE_DIR", quarantine_dir):
            log = run_sync_triage(
                file_path=malware_path,
                db=db_session,
                source_ip="1.2.3.4",
            )

        assert log is not None
        db_record = db_session.query(QuarantineLog).filter(
            QuarantineLog.id == log.id
        ).first()
        assert db_record is not None
        assert db_record.original_filename == "malware.txt"
        assert db_record.reason == "MAGIC_MISMATCH"

    def test_quarantine_moves_file_out_of_original_location(self, tmp_path, db_session):
        """After quarantine, original file path must no longer exist."""
        quarantine_dir = tmp_path / "quarantine"
        quarantine_dir.mkdir()

        malware_path = tmp_path / "payload.txt"
        malware_path.write_bytes(_make_mz_txt_bytes())

        assert malware_path.exists()
        with patch("app.ingestion.sandbox.QUARANTINE_DIR", quarantine_dir):
            run_sync_triage(file_path=malware_path, db=db_session)

        assert not malware_path.exists(), (
            "Quarantined file still at original path — not moved!"
        )

    def test_sandbox_does_not_create_ledger_entry_for_quarantined(self, client, db_session):
        """
        Uploading a file with MZ header as .txt must NOT produce an AuditLog entry.
        """
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        count_before = db_session.query(AuditLog).count()

        with client.websocket_connect(f"/ws/secure-stream/{sess.session_id}") as ws:
            ws.send_json({"type": "meta", "filename": "exploit.txt"})
            ws.receive_json()  # meta_ack

            mz_data = _make_mz_txt_bytes()
            ws.send_json(_build_chunk_msg(0, mz_data, is_final=True))
            ws.receive_json()  # chunk ack

            final = ws.receive_json()  # should be error

        assert final["status"] == "error", (
            f"Malware file not blocked by sandbox: {final}"
        )
        count_after = db_session.query(AuditLog).count()
        assert count_after == count_before, (
            f"CRITICAL: Ledger entry created for quarantined file! "
            f"Before={count_before}, After={count_after}"
        )


# ===========================================================================
# F) WORM Behavior
# ===========================================================================

class TestWORMBehavior:

    def test_worm_file_has_readonly_permissions(self, client, db_session):
        """After upload, WORM file must have no write permission."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        content = _make_clean_log_bytes()
        result = _ws_upload_clean(client, sess.session_id, content, "worm.log")
        assert result["status"] == "done"

        worm_dir = client._worm_dir
        worm_files = list(worm_dir.iterdir())
        assert len(worm_files) >= 1, "No WORM file found after upload"

        worm_file = worm_files[0]
        mode = worm_file.stat().st_mode

        # On POSIX: no write bits. On Windows: read-only attribute set.
        # Check that os.access reports no write permission
        has_write = os.access(worm_file, os.W_OK)
        assert not has_write, (
            f"WORM file is WRITABLE: {worm_file} mode={oct(mode)}"
        )

    def test_worm_file_write_raises_permission_error(self, client, db_session):
        """Attempting to write to a WORM file must raise PermissionError or OSError."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        content = _make_clean_log_bytes()
        result = _ws_upload_clean(client, sess.session_id, content, "worm_write.log")
        assert result["status"] == "done"

        worm_dir = client._worm_dir
        worm_file = list(worm_dir.iterdir())[0]

        with pytest.raises((PermissionError, OSError)):
            with open(worm_file, "wb") as f:
                f.write(b"TAMPER ATTEMPT")

    def test_worm_file_readable(self, client, db_session):
        """WORM file must remain readable after being made read-only."""
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        content = _make_clean_log_bytes()
        result = _ws_upload_clean(client, sess.session_id, content, "readable.log")
        assert result["status"] == "done"

        worm_dir = client._worm_dir
        worm_file = list(worm_dir.iterdir())[0]

        data = worm_file.read_bytes()
        assert len(data) > 0, "WORM file is empty or unreadable"
        assert data == content


# ===========================================================================
# G) Hash Chain Integrity
# ===========================================================================

class TestHashChainIntegrity:

    def test_first_entry_has_null_previous_hash(self, db_session, tmp_path):
        """The very first ledger entry must have previous_hash=None."""
        fake_path = tmp_path / "file.log"
        fake_path.write_bytes(b"test")
        entry = commit_to_ledger(
            db=db_session,
            filename="first.log",
            file_path=fake_path,
            sha256_hash=_sha256(b"test"),
            merkle_root=build_merkle_root([_sha256(b"test")]),
            source_ip="10.0.0.1",
            ingestion_mode="manual",
            file_size=4,
        )
        assert entry.previous_hash is None

    def test_sequential_entries_chain_correctly(self, db_session, tmp_path):
        """Each entry's previous_hash must equal the prior entry's sha256_hash."""
        hashes = []
        for i in range(3):
            content = f"log entry #{i}".encode()
            fake_path = tmp_path / f"file_{i}.log"
            fake_path.write_bytes(content)
            entry = commit_to_ledger(
                db=db_session,
                filename=f"entry_{i}.log",
                file_path=fake_path,
                sha256_hash=_sha256(content),
                merkle_root=build_merkle_root([_sha256(content)]),
                source_ip="10.0.0.1",
                ingestion_mode="manual",
                file_size=len(content),
            )
            hashes.append((entry.sha256_hash, entry.previous_hash))

        # entry[0].previous_hash == None
        assert hashes[0][1] is None
        # entry[1].previous_hash == entry[0].sha256_hash
        assert hashes[1][1] == hashes[0][0], (
            f"Chain link broken between entry 0 and 1!\n"
            f"  entry[1].previous_hash = {hashes[1][1]}\n"
            f"  entry[0].sha256_hash   = {hashes[0][0]}"
        )
        # entry[2].previous_hash == entry[1].sha256_hash
        assert hashes[2][1] == hashes[1][0]

    def test_verify_chain_passes_for_valid_chain(self, db_session, tmp_path):
        """verify_hash_chain must return chain_valid for an intact chain."""
        for i in range(3):
            content = f"valid log #{i}".encode()
            fake_path = tmp_path / f"v{i}.log"
            fake_path.write_bytes(content)
            commit_to_ledger(
                db=db_session,
                filename=f"valid_{i}.log",
                file_path=fake_path,
                sha256_hash=_sha256(content),
                merkle_root=build_merkle_root([_sha256(content)]),
                source_ip="10.0.0.1",
                ingestion_mode="manual",
                file_size=len(content),
            )

        result = verify_hash_chain(db_session)
        assert result["status"] == "chain_valid", (
            f"Valid chain reported broken: {result}"
        )

    def test_verify_chain_detects_tampered_previous_hash(self, db_session, tmp_path):
        """Tampering with previous_hash in DB must cause verify_hash_chain to fail."""
        entries = []
        for i in range(3):
            content = f"tamper test #{i}".encode()
            fake_path = tmp_path / f"t{i}.log"
            fake_path.write_bytes(content)
            entry = commit_to_ledger(
                db=db_session,
                filename=f"tamper_{i}.log",
                file_path=fake_path,
                sha256_hash=_sha256(content),
                merkle_root=build_merkle_root([_sha256(content)]),
                source_ip="10.0.0.1",
                ingestion_mode="manual",
                file_size=len(content),
            )
            entries.append(entry)

        # Directly tamper with entry[1]'s previous_hash
        entries[1].previous_hash = "deadbeef" * 8
        db_session.commit()

        result = verify_hash_chain(db_session)
        assert result["status"] == "chain_broken", (
            "CRITICAL: Chain tampering NOT detected by verify_hash_chain! "
            f"Got: {result}"
        )

    def test_ws_upload_chains_with_existing_entries(self, client, db_session, tmp_path):
        """
        Upload via WS must reference the previous AuditLog entry's hash
        as its own previous_hash.
        """
        # Seed one entry directly
        content_seed = b"seed log entry"
        fake_path = tmp_path / "seed.log"
        fake_path.write_bytes(content_seed)
        seed_entry = commit_to_ledger(
            db=db_session,
            filename="seed.log",
            file_path=fake_path,
            sha256_hash=_sha256(content_seed),
            merkle_root=build_merkle_root([_sha256(content_seed)]),
            source_ip="10.0.0.1",
            ingestion_mode="manual",
            file_size=len(content_seed),
        )

        # Upload via WS
        sess = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        content = _make_clean_log_bytes()
        result = _ws_upload_clean(client, sess.session_id, content, "chain_ws.log")
        assert result["status"] == "done"

        ws_entry = db_session.query(AuditLog).filter(
            AuditLog.id == result["audit_id"]
        ).first()
        assert ws_entry.previous_hash == seed_entry.sha256_hash, (
            f"WS entry did not chain to seed!\n"
            f"  ws.previous_hash = {ws_entry.previous_hash}\n"
            f"  seed.sha256_hash = {seed_entry.sha256_hash}"
        )


# ===========================================================================
# H) Concurrency & Session Isolation
# ===========================================================================

class TestConcurrencyAndIsolation:

    def test_multiple_sessions_are_unique(self, client):
        """Creating N sessions must produce N unique session_ids."""
        N = 20
        session_ids = set()
        for _ in range(N):
            resp = client.post("/api/ingestion/generate-telemetry-link")
            assert resp.status_code == 200
            sid = resp.json()["ephemeral_token"]
            session_ids.add(sid)

        assert len(session_ids) == N, (
            f"Session ID collision detected! Created {N}, got {len(session_ids)} unique"
        )

    def test_two_sessions_do_not_share_state(self, client, db_session):
        """
        Burning session A must not affect session B.
        """
        sess_a = _create_clean_session(db_session, bound_ip="testclient")
        sess_b = _create_clean_session(db_session, bound_ip="testclient")
        db_session.commit()

        # Use session A
        content = _make_clean_log_bytes()
        result_a = _ws_upload_clean(client, sess_a.session_id, content)
        assert result_a["status"] == "done"

        # Session B must still be usable
        result_b = _ws_upload_clean(client, sess_b.session_id, content)
        assert result_b["status"] == "done", (
            f"Session B was affected by burning Session A: {result_b}"
        )

    def test_two_uploads_produce_separate_ledger_entries(self, client, db_session):
        """Two separate uploads must produce two distinct AuditLog records."""
        for i in range(2):
            sess = _create_clean_session(db_session, bound_ip="testclient")
            db_session.commit()
            content = f"log file {i} content".encode() * 50
            result = _ws_upload_clean(client, sess.session_id, content, f"file{i}.log")
            assert result["status"] == "done"

        count = db_session.query(AuditLog).count()
        assert count >= 2

    def test_sequential_uploads_form_valid_chain(self, client, db_session):
        """Multiple sequential WS uploads must maintain a valid hash chain."""
        for i in range(4):
            sess = _create_clean_session(db_session, bound_ip="testclient")
            db_session.commit()
            content = f"sequential log #{i}".encode() * 20
            result = _ws_upload_clean(client, sess.session_id, content, f"seq{i}.log")
            assert result["status"] == "done"

        result = verify_hash_chain(db_session)
        assert result["status"] == "chain_valid", (
            f"Hash chain broken after sequential uploads: {result}"
        )

    def test_temp_dirs_do_not_leak_across_sessions(self, client, db_session):
        """After N uploads, temp directory must hold 0 session subdirs."""
        temp_dir = client._temp_dir

        for i in range(3):
            sess = _create_clean_session(db_session, bound_ip="testclient")
            db_session.commit()
            content = f"session {i} data".encode() * 10
            _ws_upload_clean(client, sess.session_id, content, f"s{i}.log")

        leftover = [d for d in temp_dir.iterdir() if d.is_dir()]
        assert len(leftover) == 0, (
            f"Temp directories leaked after upload: {leftover}"
        )
