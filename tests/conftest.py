"""
tests/conftest.py
------------------
Shared pytest fixtures for Phase-1 forensic ingestion validation tests.

Design decisions:
  - StaticPool ensures all SQLAlchemy sessions in a test share the SAME
    in-memory SQLite connection (critical because WS route creates its own
    DB session independently of FastAPI dependency injection).
  - All filesystem paths (WORM, quarantine, temp) are redirected to
    unique tmp_path directories per test to prevent cross-test pollution.
  - Patches are applied at module level so both REST and WS code paths
    see the same in-memory DB and temp directories.
"""

import pytest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.ingestion.router import get_db


# ---------------------------------------------------------------------------
# In-memory SQLite engine shared across all sessions in a test via StaticPool
# ---------------------------------------------------------------------------

@pytest.fixture()
def test_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def TestSessionLocal(test_engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture()
def db_session(TestSessionLocal):
    """Single DB session for direct DB manipulation in tests."""
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()


# ---------------------------------------------------------------------------
# TestClient with all patches applied
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(TestSessionLocal, db_session, tmp_path):
    """
    Full FastAPI TestClient with:
      - In-memory SQLite for all DB operations
      - Temp dirs for WORM, quarantine, and chunk storage
    """
    from app.main import new_app

    worm_dir = tmp_path / "worm"
    quarantine_dir = tmp_path / "quarantine"
    temp_dir = tmp_path / "temp"
    worm_dir.mkdir()
    quarantine_dir.mkdir()
    temp_dir.mkdir()

    def override_get_db():
        session = TestSessionLocal()
        try:
            yield session
        finally:
            session.close()

    new_app.dependency_overrides[get_db] = override_get_db

    with patch("app.ingestion.ws_router.SessionLocal", TestSessionLocal), \
         patch("app.ingestion.ws_router.WORM_DIR", worm_dir), \
         patch("app.ingestion.ws_router.TEMP_CHUNKS_DIR", temp_dir), \
         patch("app.ingestion.sandbox.QUARANTINE_DIR", quarantine_dir):

        with TestClient(new_app, raise_server_exceptions=False) as c:
            c._worm_dir = worm_dir
            c._quarantine_dir = quarantine_dir
            c._temp_dir = temp_dir
            yield c

    new_app.dependency_overrides.clear()
