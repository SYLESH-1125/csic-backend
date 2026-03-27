from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import duckdb


@dataclass(frozen=True)
class StorageConfig:
    hot_db_path: str
    cold_dir: str
    ttl_seconds: int = 30


def _now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def ensure_dirs(cfg: StorageConfig) -> None:
    Path(cfg.cold_dir).mkdir(parents=True, exist_ok=True)


def connect_hot(cfg: StorageConfig) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(cfg.hot_db_path)
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS live_events (
          lineage VARCHAR PRIMARY KEY,
          target_user VARCHAR,
          notes VARCHAR,
          notes_redacted VARCHAR,
          vector DOUBLE[],
          created_at TIMESTAMPTZ,
          ttl_seconds INTEGER,
          is_locked BOOLEAN,
          is_tombstoned BOOLEAN,
          pii_redactions INTEGER,
          privacy_confidence DOUBLE
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS ingest_audit (
          event_id VARCHAR,
          lineage VARCHAR,
          created_at TIMESTAMPTZ,
          status VARCHAR,
          detail VARCHAR
        )
        """
    )
    return con


def _cold_paths(cfg: StorageConfig, lineage: str) -> Tuple[Path, Path]:
    date = _now_utc().date().isoformat()
    stage_dir = Path(cfg.cold_dir) / "_staging" / date
    final_dir = Path(cfg.cold_dir) / "events" / date
    stage_dir.mkdir(parents=True, exist_ok=True)
    final_dir.mkdir(parents=True, exist_ok=True)
    stage = stage_dir / f"{lineage}.parquet"
    final = final_dir / f"{lineage}.parquet"
    return stage, final


def stage_to_cold(cfg: StorageConfig, event: Dict[str, Any]) -> Path:
    """
    Writes a single-event parquet to staging using DuckDB COPY.
    """
    lineage = str(event.get("Lineage") or event.get("lineage") or "")
    stage_path, _ = _cold_paths(cfg, lineage)
    tmp_con = duckdb.connect(":memory:")
    tmp_con.execute(
        """
        CREATE TABLE e (
          Target_User VARCHAR,
          Notes VARCHAR,
          Notes_Redacted VARCHAR,
          Lineage VARCHAR,
          created_at TIMESTAMPTZ
        )
        """
    )
    tmp_con.execute(
        "INSERT INTO e VALUES (?, ?, ?, ?, ?)",
        (
            str(event.get("Target_User") or ""),
            str(event.get("Notes") or ""),
            str(event.get("Notes_Redacted") or ""),
            lineage,
            event.get("created_at"),
        ),
    )
    tmp_con.execute(f"COPY e TO '{stage_path.as_posix()}' (FORMAT 'parquet')")
    tmp_con.close()
    return stage_path


def commit_cold(cfg: StorageConfig, lineage: str) -> Optional[Path]:
    stage_path, final_path = _cold_paths(cfg, lineage)
    if not stage_path.exists():
        return None
    final_path.parent.mkdir(parents=True, exist_ok=True)
    stage_path.replace(final_path)
    return final_path


def rollback_cold(cfg: StorageConfig, lineage: str) -> None:
    stage_path, _ = _cold_paths(cfg, lineage)
    try:
        if stage_path.exists():
            stage_path.unlink()
    except Exception:
        pass


def insert_hot_event(
    con: duckdb.DuckDBPyConnection,
    *,
    lineage: str,
    target_user: str,
    notes: str,
    notes_redacted: str,
    vector: List[float],
    created_at: dt.datetime,
    ttl_seconds: int,
    pii_redactions: int,
    privacy_confidence: float,
) -> None:
    con.execute(
        """
        INSERT OR REPLACE INTO live_events
        (lineage, target_user, notes, notes_redacted, vector, created_at, ttl_seconds,
         is_locked, is_tombstoned, pii_redactions, privacy_confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?, FALSE, FALSE, ?, ?)
        """,
        (
            lineage,
            target_user,
            notes,
            notes_redacted,
            vector,
            created_at,
            ttl_seconds,
            pii_redactions,
            privacy_confidence,
        ),
    )


def lock_lineage(con: duckdb.DuckDBPyConnection, lineage: str) -> None:
    con.execute("UPDATE live_events SET is_locked = TRUE WHERE lineage = ?", (lineage,))


def extend_lineage(con: duckdb.DuckDBPyConnection, lineage: str, seconds: int) -> None:
    con.execute("UPDATE live_events SET ttl_seconds = ttl_seconds + ? WHERE lineage = ?", (int(seconds), lineage))


def remove_lineage(con: duckdb.DuckDBPyConnection, lineage: str) -> None:
    con.execute("DELETE FROM live_events WHERE lineage = ?", (lineage,))
    con.execute("VACUUM")


def tombstone_lineage(con: duckdb.DuckDBPyConnection, lineage: str) -> None:
    con.execute("UPDATE live_events SET is_tombstoned = TRUE WHERE lineage = ?", (lineage,))


def select_live_rows(con: duckdb.DuckDBPyConnection) -> List[tuple]:
    return con.execute("SELECT lineage, created_at, ttl_seconds, is_locked FROM live_events").fetchall()


def query_cold(
    cfg: StorageConfig,
    *,
    target_user: str,
    limit: int,
    offset: int,
) -> List[Dict[str, Any]]:
    events_root = Path(cfg.cold_dir) / "events"
    if not events_root.is_dir():
        return []
    if not any(events_root.glob("*/*.parquet")):
        return []

    # Use in-memory DuckDB: this query only scans Parquet under cold_dir. Opening cfg.hot_db_path
    # here would contend with the Phase 3 app's long-lived connection to the same file (lock error).
    con = duckdb.connect(":memory:")
    glob_path = str(Path(cfg.cold_dir) / "events" / "*" / "*.parquet")
    sql = (
        "SELECT Target_User, Notes_Redacted AS Notes, Lineage, created_at "
        f"FROM read_parquet('{glob_path}', union_by_name=True) "
        "WHERE Target_User = ? "
        "ORDER BY created_at DESC "
        "LIMIT ? OFFSET ?"
    )
    rows = con.execute(sql, (target_user, int(limit), int(offset))).fetchall()
    con.close()
    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append({"Target_User": r[0], "Notes": r[1], "Lineage": r[2], "created_at": str(r[3]) if r[3] is not None else None})
    return out

