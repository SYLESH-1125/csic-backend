import duckdb
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DUCKDB_PATH = str(BASE_DIR / "data" / "analytics.duckdb")

def get_duckdb_connection():
    conn = duckdb.connect(DUCKDB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
             audit_id VARCHAR,
            timestamp TIMESTAMP,
            user VARCHAR,
            source_ip VARCHAR,
            action VARCHAR,
            status VARCHAR,
            raw_hash VARCHAR
        )
    """)

    return conn
