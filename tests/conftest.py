"""Pytest configuration and helpers for JIT / ingestion tests."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient


def _reload_app_with_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """
    Point SQLAlchemy + DuckDB at temp files and reload modules so SessionLocal
    matches (avoids stale engine bound to the developer's ledger.db).
    """
    db_path = tmp_path / "jit_test.db"
    duck_path = tmp_path / "jit_analytics.duckdb"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("AUTO_TRIGGER_PHASE2", "false")
    monkeypatch.setattr("app.db.duckdb_sessions.DUCKDB_PATH", str(duck_path))

    import app.config as app_config
    import app.db.session as db_session
    import app.ingestion.auth_gateway as auth_gateway
    import app.ingestion.service as ingestion_service
    import app.ingestion.router as ingestion_router
    import app.ingestion.ws_router as ws_router
    import app.main as main_app

    importlib.reload(app_config)
    importlib.reload(db_session)
    importlib.reload(auth_gateway)
    importlib.reload(ingestion_service)
    importlib.reload(ws_router)
    importlib.reload(ingestion_router)
    importlib.reload(main_app)
    # main_app startup runs Base.metadata.create_all(bind=engine) on import
    return TestClient(main_app.new_app)


@pytest.fixture
def jit_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[TestClient, None, None]:
    client = _reload_app_with_db(tmp_path, monkeypatch)
    try:
        yield client
    finally:
        client.close()
