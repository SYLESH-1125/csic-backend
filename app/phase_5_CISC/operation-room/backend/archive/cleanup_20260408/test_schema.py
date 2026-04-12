import duckdb
import os
try:
    c = duckdb.connect('C:/CISC/operation-room/backend/data/cases/CASE-FORENSIC-001/vault.duckdb')
    print([x[0] for x in c.execute('DESCRIBE unified_timeline;').fetchall()])
    c.close()
except Exception as e:
    print(e)
