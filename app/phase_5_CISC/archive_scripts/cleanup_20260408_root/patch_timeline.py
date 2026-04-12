import os

filepath = r"c:\CISC\operation-room\backend\app\services\timeline_service.py"
with open(filepath, "a", encoding="utf-8") as f:
    f.write("""

# ── Advanced Search & Stats ──────────────────────────────────────────────

def get_timeline_search(case_id: str, search_query: dict, limit: int = 500, offset: int = 0) -> list[dict]:
    \"\"\"Fetch timeline events using the advanced JSON Filter DSL.\"\"\"
    conn = open_vault(case_id)
    try:
        where_clause, params = build_where_clause(search_query)
        base_where = "case_id = ?"
        all_params = [case_id]

        if where_clause:
            full_where = f"{base_where} AND {where_clause}"
            all_params.extend(params)
        else:
            full_where = base_where

        query = f\"\"\"
            SELECT tl_event_id, case_id, original_event_id, normalised_ts,
                   utc_offset, source_type, source_system, actor, action,
                   target, severity, detail, cluster_id, is_time_stomped
            FROM unified_timeline
            WHERE {full_where}
            ORDER BY normalised_ts ASC
            LIMIT {limit} OFFSET {offset}
        \"\"\"

        rows = conn.execute(query, all_params).fetchall()
        cols = [
            "tl_event_id", "case_id", "original_event_id", "normalised_ts",
            "utc_offset", "source_type", "source_system", "actor", "action",
            "target", "severity", "detail", "cluster_id", "is_time_stomped",
        ]
        results = []
        for row in rows:
            d = dict(zip(cols, row))
            # parse date
            if d.get("normalised_ts") and not isinstance(d["normalised_ts"], str):
                d["normalised_ts"] = str(d["normalised_ts"])
            results.append(d)
        return results
    finally:
        conn.close()

def get_timeline_stats_search(case_id: str, search_query: dict) -> dict:
    \"\"\"Fetch aggregated stats using the advanced JSON Filter DSL.\"\"\"
    conn = open_vault(case_id)
    try:
        where_clause, params = build_where_clause(search_query)
        base_where = "case_id = ?"
        all_params = [case_id]

        if where_clause:
            full_where = f"{base_where} AND {where_clause}"
            all_params.extend(params)
        else:
            full_where = base_where

        total = conn.execute(f"SELECT COUNT(*) FROM unified_timeline WHERE {full_where}", all_params).fetchone()[0]
        clusters = conn.execute(f"SELECT COUNT(DISTINCT cluster_id) FROM unified_timeline WHERE cluster_id IS NOT NULL AND {full_where}", all_params).fetchone()[0]

        source_rows = conn.execute(f"SELECT source_type, COUNT(*) FROM unified_timeline WHERE {full_where} GROUP BY source_type ORDER BY COUNT(*) DESC", all_params).fetchall()
        sources = {r[0]: r[1] for r in source_rows}

        action_rows = conn.execute(f"SELECT action, COUNT(*) FROM unified_timeline WHERE {full_where} GROUP BY action ORDER BY COUNT(*) DESC", all_params).fetchall()
        actions = {r[0]: r[1] for r in action_rows}

        return {
            "total_events": total,
            "clusters": clusters,
            "sources": sources,
            "actions": actions
        }
    finally:
        conn.close()
""")
