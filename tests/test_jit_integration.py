"""Full JIT + WebSocket log-stream integration tests (temp DB + module reload)."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from unittest.mock import AsyncMock

import pytest


def _chunk(chunk_num: int, data: bytes, is_final: bool) -> dict:
    return {
        "chunk_number": chunk_num,
        "chunk_hash": hashlib.sha256(data).hexdigest(),
        "data": base64.b64encode(data).decode("ascii"),
        "is_final": is_final,
    }


def _patch_phase2(monkeypatch):
    import app.ingestion.ws_router as ws_r

    monkeypatch.setattr(ws_r, "trigger_phase2_processing", AsyncMock())


def test_ws_ingest_single_chunk_ok(jit_client, monkeypatch):
    _patch_phase2(monkeypatch)

    r = jit_client.post("/api/ingestion/manual")
    assert r.status_code == 200, r.text
    sid = r.json()["session_id"]

    payload = b"JIT ingestion test payload\n"
    msg = _chunk(0, payload, True)

    with jit_client.websocket_connect(f"/ws/secure-stream/{sid}") as ws:
        ws.send_text(json.dumps(msg))
        assert json.loads(ws.receive_text()).get("status") == "ok"
        done = json.loads(ws.receive_text())
        assert done.get("status") == "done", done
        assert done["result"].get("audit_id")


def test_jit_manual_log_pull_multi_chunk_with_meta(jit_client, monkeypatch):
    """Simulates pulling a log file: meta filename + multiple chunks, then done."""
    _patch_phase2(monkeypatch)

    r = jit_client.post("/api/ingestion/manual")
    assert r.status_code == 200, r.text
    sid = r.json()["session_id"]

    part0 = b"2025-01-01T00:00:00Z INFO boot\n"
    part1 = b"2025-01-01T00:00:01Z INFO ready\n"

    with jit_client.websocket_connect(f"/ws/secure-stream/{sid}") as ws:
        ws.send_text(
            json.dumps({"type": "meta", "filename": "simulated_pull.log"})
        )
        meta_ack = json.loads(ws.receive_text())
        assert meta_ack.get("status") == "meta_ack"
        assert meta_ack.get("filename") == "simulated_pull.log"

        ws.send_text(json.dumps(_chunk(0, part0, False)))
        assert json.loads(ws.receive_text()).get("status") == "ok"

        ws.send_text(json.dumps(_chunk(1, part1, True)))
        assert json.loads(ws.receive_text()).get("status") == "ok"

        done = json.loads(ws.receive_text())
        assert done.get("status") == "done"
        res = done["result"]
        assert res.get("audit_id")
        assert "simulated_pull.log" in (res.get("file_path") or "")


def test_jit_cloud_session_ws_log_pull(jit_client, monkeypatch):
    """Cloud JIT entry issues the same WebSocket pipeline after OAuth stub passes."""
    _patch_phase2(monkeypatch)

    r = jit_client.post(
        "/api/ingestion/cloud",
        json={"oauth_token": "stub-token-for-test", "cloud_provider": "generic"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("mode") == "cloud"
    sid = body["session_id"]

    line = b"cloud-pull log line\n"
    with jit_client.websocket_connect(f"/ws/secure-stream/{sid}") as ws:
        ws.send_text(json.dumps(_chunk(0, line, True)))
        assert json.loads(ws.receive_text()).get("status") == "ok"
        done = json.loads(ws.receive_text())
        assert done.get("status") == "done"
        assert done["result"].get("audit_id")


def test_jit_telemetry_link_ws_log_pull(jit_client, monkeypatch):
    """Agent/telemetry link uses ephemeral_token as session_id on the same WS route."""
    _patch_phase2(monkeypatch)

    r = jit_client.post("/api/ingestion/generate-telemetry-link")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("mode") == "agent"
    sid = body["ephemeral_token"]

    blob = b"telemetry artefact\n"
    with jit_client.websocket_connect(f"/ws/secure-stream/{sid}") as ws:
        ws.send_text(json.dumps(_chunk(0, blob, True)))
        assert json.loads(ws.receive_text()).get("status") == "ok"
        done = json.loads(ws.receive_text())
        assert done.get("status") == "done"
        assert done["result"].get("audit_id")


def test_jit_second_websocket_rejected_burn_on_use(jit_client, monkeypatch):
    """After a successful stream, the same session_id must not be reusable."""
    _patch_phase2(monkeypatch)

    r = jit_client.post("/api/ingestion/manual")
    sid = r.json()["session_id"]
    payload = b"one-shot\n"

    with jit_client.websocket_connect(f"/ws/secure-stream/{sid}") as ws:
        ws.send_text(json.dumps(_chunk(0, payload, True)))
        assert json.loads(ws.receive_text()).get("status") == "ok"
        assert json.loads(ws.receive_text()).get("status") == "done"

    with jit_client.websocket_connect(f"/ws/secure-stream/{sid}") as ws2:
        err = json.loads(ws2.receive_text())
        assert err.get("status") == "error"
        assert "consumed" in (err.get("detail") or "").lower() or "burn" in (
            err.get("detail") or ""
        ).lower()


def test_jit_unknown_session_rejected(jit_client, monkeypatch):
    _patch_phase2(monkeypatch)
    bad = str(uuid.uuid4())
    with jit_client.websocket_connect(f"/ws/secure-stream/{bad}") as ws:
        err = json.loads(ws.receive_text())
        assert err.get("status") == "error"
        assert "not found" in (err.get("detail") or "").lower()


def test_duckdb_mirror_updated_after_ws_done(jit_client, monkeypatch):
    """DuckDB ingestion_sessions row reflects used + audit_id after ingest."""
    _patch_phase2(monkeypatch)

    from app.db import duckdb_sessions

    r = jit_client.post("/api/ingestion/manual")
    sid = r.json()["session_id"]

    row_before = duckdb_sessions.get_session(sid)
    assert row_before is not None
    assert row_before["used"] is False

    with jit_client.websocket_connect(f"/ws/secure-stream/{sid}") as ws:
        ws.send_text(json.dumps(_chunk(0, b"duckdb check\n", True)))
        assert json.loads(ws.receive_text()).get("status") == "ok"
        done = json.loads(ws.receive_text())
        assert done.get("status") == "done"
        audit_id = done["result"]["audit_id"]

    row_after = duckdb_sessions.get_session(sid)
    assert row_after is not None
    assert row_after["used"] is True
    assert row_after.get("audit_id") == audit_id
