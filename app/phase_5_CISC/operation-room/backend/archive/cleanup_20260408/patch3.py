import sys

# Update routes
with open('C:/CISC/operation-room/backend/app/routes/timeline.py', 'r', encoding='utf-8') as f:
    rcontent = f.read()

rcontent = rcontent.replace(
    '''@router.post("/search")
def search_timeline(case_id: str, payload: dict = Body(...), limit: int = Query(default=500, le=5000), offset: int = Query(default=0)):
    \"\"\"Search timeline using advanced Filter DSL.\"\"\"
    try:
        return timeline_service.get_timeline_search(case_id, payload, limit, offset)''',
    '''@router.post("/search")
def search_timeline(case_id: str, payload: dict = Body(...), limit: int = Query(default=500, le=5000), offset: int = Query(default=0), anchors_only: bool = Query(default=False)):
    \"\"\"Search timeline using advanced Filter DSL.\"\"\"
    try:
        return timeline_service.get_timeline_search(case_id, payload, limit, offset, anchors_only)'''
)

rcontent = rcontent.replace(
    '''@router.post("/stats/search")
def search_timeline_stats(case_id: str, payload: dict = Body(...)):
    \"\"\"Get aggregated stats using advanced Filter DSL.\"\"\"
    try:
        return timeline_service.get_timeline_stats_search(case_id, payload)''',
    '''@router.post("/stats/search")
def search_timeline_stats(case_id: str, payload: dict = Body(...), anchors_only: bool = Query(default=False)):
    \"\"\"Get aggregated stats using advanced Filter DSL.\"\"\"
    try:
        return timeline_service.get_timeline_stats_search(case_id, payload, anchors_only)'''
)

with open('C:/CISC/operation-room/backend/app/routes/timeline.py', 'w', encoding='utf-8') as f:
    f.write(rcontent)

# Update services
with open('C:/CISC/operation-room/backend/app/services/timeline_service.py', 'r', encoding='utf-8') as f:
    scontent = f.read()

scontent = scontent.replace(
    '''def get_timeline_search(case_id: str, search_query: dict, limit: int = 500, offset: int = 0) -> list[dict]:''',
    '''def get_timeline_search(case_id: str, search_query: dict, limit: int = 500, offset: int = 0, anchors_only: bool = False) -> list[dict]:'''
)

scontent = scontent.replace(
    '''def get_timeline_stats_search(case_id: str, search_query: dict) -> dict:''',
    '''def get_timeline_stats_search(case_id: str, search_query: dict, anchors_only: bool = False) -> dict:'''
)

# Insert the condition inside get_timeline_search
scontent = scontent.replace(
    '''        if where_clause:
            full_where = f"{base_where} AND {where_clause}"
            all_params.extend(params)
        else:
            full_where = base_where

        query = f"""
            SELECT''',
    '''        if where_clause:
            full_where = f"{base_where} AND {where_clause}"
            all_params.extend(params)
        else:
            full_where = base_where
        
        if anchors_only:
            full_where += " AND is_anchor = TRUE"

        query = f"""
            SELECT'''
)

with open('C:/CISC/operation-room/backend/app/services/timeline_service.py', 'w', encoding='utf-8') as f:
    f.write(scontent)
