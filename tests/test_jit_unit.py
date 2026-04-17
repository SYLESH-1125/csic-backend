"""Unit tests for JIT IP canonicalization, SessionStore, and DuckDB mirror (no app reload)."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.ingestion.auth_gateway import (
    SessionStore,
    canonical_ip_for_jit,
    _enforce_rules,
)


@pytest.fixture()
def memory_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        yield db
    finally:
        db.close()


def test_canonical_ip_loopback_aliases_match():
    a = canonical_ip_for_jit("127.0.0.1")
    b = canonical_ip_for_jit("::1")
    c = canonical_ip_for_jit("testclient")
    assert a == b == c
    assert canonical_ip_for_jit("203.0.113.10") == "203.0.113.10"


def test_enforce_rules_accepts_ipv4_vs_ipv6_loopback(memory_db):
    store = SessionStore(memory_db)
    session = store.create(bound_ip="127.0.0.1", mode="manual")
    _enforce_rules(session, "::1", context="WS")


def test_duckdb_session_mirror(tmp_path, monkeypatch, memory_db):
    monkeypatch.setattr("app.db.duckdb_sessions.DUCKDB_PATH", str(tmp_path / "mirror.duckdb"))
    from app.db import duckdb_sessions

    store = SessionStore(memory_db)
    row = store.create(bound_ip="127.0.0.1", mode="manual")
    mirrored = duckdb_sessions.get_session(row.session_id)
    assert mirrored is not None
    assert mirrored["session_id"] == row.session_id
    assert mirrored["used"] is False
    assert mirrored["mode"] == "manual"

    store.mark_used(row)
    mirrored2 = duckdb_sessions.get_session(row.session_id)
    assert mirrored2["used"] is True
