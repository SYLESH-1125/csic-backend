"""
JIT ingestion session mirror in DuckDB (analytics DB).

SQLite remains the source of truth for ORM and FKs; DuckDB stores a copy for
analytics and cross-query with logs. Failures here are logged and never block
ingestion.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import duckdb

from app.core.logging import logger

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DUCKDB_PATH = str(BASE_DIR / "data" / "analytics.duckdb")


def _ensure_schema(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ingestion_sessions (
            session_id VARCHAR PRIMARY KEY,
            bound_ip VARCHAR NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN NOT NULL,
            mode VARCHAR NOT NULL,
            created_at TIMESTAMP,
            audit_id VARCHAR
        )
        """
    )


def _connect() -> duckdb.DuckDBPyConnection:
    Path(DUCKDB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(DUCKDB_PATH)
    _ensure_schema(conn)
    return conn


def upsert_session_row(
    session_id: str,
    bound_ip: str,
    expires_at: datetime,
    used: bool,
    mode: str,
    created_at: Optional[datetime],
    audit_id: Optional[str] = None,
) -> None:
    try:
        conn = _connect()
        try:
            conn.execute(
                "DELETE FROM ingestion_sessions WHERE session_id = ?",
                [session_id],
            )
            conn.execute(
                """
                INSERT INTO ingestion_sessions (
                    session_id, bound_ip, expires_at, used, mode, created_at, audit_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    session_id,
                    bound_ip,
                    expires_at,
                    used,
                    mode,
                    created_at,
                    audit_id,
                ],
            )
        finally:
            conn.close()
    except Exception as exc:
        logger.warning(f"[DuckDBSessions] upsert failed session_id={session_id}: {exc}")


def mark_used(session_id: str) -> None:
    try:
        conn = _connect()
        try:
            conn.execute(
                "UPDATE ingestion_sessions SET used = TRUE WHERE session_id = ?",
                [session_id],
            )
        finally:
            conn.close()
    except Exception as exc:
        logger.warning(f"[DuckDBSessions] mark_used failed session_id={session_id}: {exc}")


def link_audit(session_id: str, audit_id: str) -> None:
    try:
        conn = _connect()
        try:
            conn.execute(
                "UPDATE ingestion_sessions SET audit_id = ? WHERE session_id = ?",
                [audit_id, session_id],
            )
        finally:
            conn.close()
    except Exception as exc:
        logger.warning(
            f"[DuckDBSessions] link_audit failed session_id={session_id}: {exc}"
        )


def get_session(session_id: str) -> Optional[dict[str, Any]]:
    """Read-through for diagnostics / tests (optional)."""
    try:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT session_id, bound_ip, expires_at, used, mode, created_at, audit_id
                FROM ingestion_sessions WHERE session_id = ?
                """,
                [session_id],
            ).fetchall()
            if not rows:
                return None
            r = rows[0]
            return {
                "session_id": r[0],
                "bound_ip": r[1],
                "expires_at": r[2],
                "used": r[3],
                "mode": r[4],
                "created_at": r[5],
                "audit_id": r[6],
            }
        finally:
            conn.close()
    except Exception as exc:
        logger.warning(f"[DuckDBSessions] get_session failed: {exc}")
        return None
