import duckdb
import os
from datetime import datetime, timedelta

os.makedirs('cases/test-case', exist_ok=True)
db_path = 'cases/test-case/vault.db'
if os.path.exists(db_path):
    os.remove(db_path)

con = duckdb.connect(db_path)
con.execute('CREATE TABLE timeline (id VARCHAR, timestamp TIMESTAMP, tool VARCHAR, action VARCHAR)')

start_time = datetime.now()
data = []
for i in range(5005):
    ts = (start_time + timedelta(seconds=i//100)).strftime('%Y-%m-%d %H:%M:%S')
    data.append(f"('{i}', '{ts}', 'CRUD', 'UPDATE')")

query = 'INSERT INTO timeline VALUES ' + ','.join(data)
con.execute(query)

query = """
    WITH bucketed AS (
        SELECT 
            time_bucket(INTERVAL '5 MINUTE', try_cast(timestamp AS TIMESTAMP)) as time_window,
            action,
            COUNT(*) as event_count
        FROM timeline
        WHERE tool = 'CRUD' AND action IN ('UPDATE', 'DELETE')
        GROUP BY 1, 2
    )
    SELECT * FROM bucketed WHERE event_count > 5000 ORDER BY time_window ASC
"""
try:
    res = con.execute(query).fetchall()
    print(f'Detected bursts: {len(res)}')
    for r in res:
        print(f"Window: {r[0]}, Action: {r[1]}, Count: {r[2]}")
except Exception as e:
    print("DuckDB Query Error:", e)
finally:
    con.close()
