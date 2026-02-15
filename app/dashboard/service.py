from __future__ import annotations

from datetime import datetime
from pathlib import Path
import duckdb
from sqlalchemy.orm import Session

from app.db.models import AuditLog
from app.detection.service import load_cold_into_hot


HOT_DB_PATH = Path("data/hot/analytics.duckdb")


def _iso(dt_val):
    if dt_val is None:
        return None
    if isinstance(dt_val, str):
        return dt_val
    try:
        return dt_val.isoformat()
    except Exception:
        return str(dt_val)


def _connect_hot():
    if not HOT_DB_PATH.exists():
        return None
    return duckdb.connect(str(HOT_DB_PATH))


def get_summary():
    ok = load_cold_into_hot()
    if not ok:
        return {
            "status": "no_data",
            "total_events": 0,
            "earliest_log": None,
            "latest_log": None,
            "critical_threats": 0,
            "source": "cold_empty"
        }

    conn = _connect_hot()
    if conn is None:
        return {
            "status": "no_data",
            "total_events": 0,
            "earliest_log": None,
            "latest_log": None,
            "critical_threats": 0,
            "source": "hot_missing"
        }

    total, earliest, latest = conn.execute("""
        SELECT
          COUNT(*)::BIGINT AS total_events,
          MIN(timestamp) AS earliest_log,
          MAX(timestamp) AS latest_log
        FROM logs
        WHERE timestamp IS NOT NULL
    """).fetchone()

    # critical threats comes from detection_results if it exists
    has_det = conn.execute("""
        SELECT COUNT(*)::INT
        FROM information_schema.tables
        WHERE table_name='detection_results'
    """).fetchone()[0] > 0

    critical = 0
    if has_det:
        # risk_score is 0..100; treat >=80 as "critical"
        critical = conn.execute("""
            SELECT COUNT(*)::BIGINT
            FROM detection_results
            WHERE is_anomaly = 1 AND risk_score >= 80
        """).fetchone()[0]

    conn.close()

    return {
        "status": "ok",
        "total_events": int(total),
        "earliest_log": _iso(earliest),
        "latest_log": _iso(latest),
        "critical_threats": int(critical),
        "source": "detection_results" if has_det else "logs_only"
    }


def get_timeline():
    ok = load_cold_into_hot()
    if not ok:
        return {"status": "no_data", "series": [0] * 24}

    conn = _connect_hot()
    if conn is None:
        return {"status": "no_data", "series": [0] * 24}

    rows = conn.execute("""
        SELECT EXTRACT('hour' FROM timestamp)::INT AS h, COUNT(*)::BIGINT AS c
        FROM logs
        WHERE timestamp IS NOT NULL
        GROUP BY h
        ORDER BY h
    """).fetchall()
    conn.close()

    series = [0] * 24
    for h, c in rows:
        if h is not None and 0 <= int(h) <= 23:
            series[int(h)] = int(c)

    return {"status": "ok", "series": series}


def get_severity():
    ok = load_cold_into_hot()
    if not ok:
        return {"status": "no_data", "source": "none", "critical": 0, "warning": 0, "info": 0}

    conn = _connect_hot()
    if conn is None:
        return {"status": "no_data", "source": "none", "critical": 0, "warning": 0, "info": 0}

    has_det = conn.execute("""
        SELECT COUNT(*)::INT
        FROM information_schema.tables
        WHERE table_name='detection_results'
    """).fetchone()[0] > 0

    if has_det:
        # critical: anomaly + risk>=80
        # warning: anomaly + 60<=risk<80
        # info: everything else
        critical = conn.execute("""
            SELECT COUNT(*)::BIGINT
            FROM detection_results
            WHERE is_anomaly=1 AND risk_score >= 80
        """).fetchone()[0]

        warning = conn.execute("""
            SELECT COUNT(*)::BIGINT
            FROM detection_results
            WHERE is_anomaly=1 AND risk_score >= 60 AND risk_score < 80
        """).fetchone()[0]

        total = conn.execute("SELECT COUNT(*)::BIGINT FROM detection_results").fetchone()[0]
        info = int(total) - int(critical) - int(warning)

        conn.close()
        return {
            "status": "ok",
            "source": "detection_results",
            "critical": int(critical),
            "warning": int(warning),
            "info": int(info),
        }

    # fallback before running detection: map from logs.status (failed => warning)
    warning = conn.execute("""
        SELECT COUNT(*)::BIGINT
        FROM logs
        WHERE LOWER(COALESCE(status,''))='failed'
    """).fetchone()[0]

    total = conn.execute("SELECT COUNT(*)::BIGINT FROM logs").fetchone()[0]
    conn.close()

    return {
        "status": "ok",
        "source": "logs_status",
        "critical": 0,
        "warning": int(warning),
        "info": int(total) - int(warning),
    }


def get_recent_uploads(db: Session, limit: int = 20):
    items = (
        db.query(AuditLog)
        .order_by(AuditLog.upload_time.desc())
        .limit(limit)
        .all()
    )

    out = []
    for r in items:
        out.append({
            "audit_id": r.id,
            "filename": r.filename,
            "upload_time": r.upload_time.isoformat() if r.upload_time else None,
            "uploader": r.uploader,
            "file_size": r.file_size,
            "status": r.status,
        })
    return {"status": "ok", "items": out}
