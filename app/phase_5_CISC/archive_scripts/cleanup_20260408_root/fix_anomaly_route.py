import re

path = r'C:\CISC\operation-room\backend\app\routes\anomaly.py'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

import re
replacement = """@router.post("/run")
async def run_detection(case_id: str, body: RunDetectionRequest):
    return {"status": "ok", "message": "Anomaly AI detection initiated via AI Tooling.", "run_id": "legacy-mock"}

@router.get("")
async def get_anomalies(case_id: str, run_id: Optional[str] = None, anomalies_only: bool = False):
    return []

@router.get("/summary")
async def get_summary(case_id: str, run_id: Optional[str] = None):
    return {"status": "COMPLETED", "total_scored": 0, "anomalies_found": 0, "score_distribution": [], "overall_contamination": 0.0, "feature_importance": []}

@router.get("/sequences")
async def get_sequences(case_id: str, run_id: Optional[str] = None):
    return []

@router.get("/runs")
async def list_runs(case_id: str):
    return []

@router.post("/search")
async def search_anomalies(case_id: str, payload: dict = Body(...), limit: int = Query(default=500, le=5000), offset: int = Query(default=0)):
    return []

@router.get("/fields/{field_name}/distinct")
async def get_anomaly_distinct_route(case_id: str, field_name: str):
    return []

class ThreatIntelRequest"""

text = re.sub(r'@router\.post.*?class ThreatIntelRequest', replacement, text, flags=re.DOTALL)

with open(path, 'w', encoding='utf-8') as f:
    f.write(text)

print("Fixed!")
