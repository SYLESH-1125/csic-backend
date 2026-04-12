import sys

code = """

# ── Advanced Search & Stats ──────────────────────────────────────────────

def get_timeline_search(case_id: str, search_query: dict, limit: int = 500, offset: int = 0, anchors_only: bool = False) -> list[dict]:
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
        
        if anchors_only:
            full_where += " AND is_anchor = TRUE"

        query = f'''
            SELECT tl_event_id, case_id, original_event_id, normalised_ts,
                   utc_offset, source_type, source_system, actor, action,
                   target, severity, detail, cluster_id, is_time_stomped, is_anchor, anchor_label
            FROM unified_timeline
            WHERE {full_where}
            ORDER BY normalised_ts ASC
            LIMIT {limit} OFFSET {offset}
        '''

        rows = conn.execute(query, all_params).fetchall()
        cols = [
            "tl_event_id", "case_id", "original_event_id", "normalised_ts",
            "utc_offset", "source_type", "source_system", "actor", "action",
            "target", "severity", "detail", "cluster_id", "is_time_stomped", "is_anchor", "anchor_label"
        ]
        results = []
        for row in rows:
            d = dict(zip(cols, row))
            if d.get("normalised_ts") and not isinstance(d["normalised_ts"], str):
                d["normalised_ts"] = str(d["normalised_ts"])
            results.append(d)
        return results
    finally:
        conn.close()

def get_timeline_stats_search(case_id: str, search_query: dict, anchors_only: bool = False) -> dict:
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

        if anchors_only:
            full_where += " AND is_anchor = TRUE"

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

def toggle_anchor(case_id: str, data: dict) -> dict:
    conn = open_vault(case_id)
    try:
        tl_id = data['tl_event_id']
        label = data.get('label', '')
        is_anchor = data.get('is_anchor', True)
        
        if is_anchor:
            conn.execute('UPDATE unified_timeline SET is_anchor = TRUE, anchor_label = ? WHERE tl_event_id = ?', [label, tl_id])
        else:
            conn.execute('UPDATE unified_timeline SET is_anchor = FALSE, anchor_label = NULL WHERE tl_event_id = ?', [tl_id])
            
        from operation_room.services.audit_service import record_coc_event
        record_coc_event(case_id=case_id, actor='analyst', action='ANCHOR_TOGGLED', target_artefact=f'timeline_event:{tl_id}', justification=f'Anchor toggled to {is_anchor}')
        return {"status": "ok"}
    finally:
        conn.close()

def get_anchors(case_id: str) -> list[dict]:
    conn = open_vault(case_id)
    try:
        rows = conn.execute("SELECT tl_event_id, normalised_ts, action, actor, target, source_type, severity, detail, anchor_label FROM unified_timeline WHERE case_id = ? AND is_anchor = TRUE ORDER BY normalised_ts ASC", [case_id]).fetchall()
        cols = ["tl_event_id", "normalised_ts", "action", "actor", "target", "source_type", "severity", "detail", "anchor_label"]
        results = []
        for row in rows:
            d = dict(zip(cols, row))
            if d.get("normalised_ts") and not isinstance(d["normalised_ts"], str):
                d["normalised_ts"] = str(d["normalised_ts"])
            results.append(d)
        return results
    finally:
        conn.close()
"""

with open(r'c:\CISC\operation-room\backend\app\services\timeline_service.py', 'a', encoding='utf-8') as f:
    f.write(code)

print("Appended!")
