import os, re
for rt, ds, fs in os.walk('C:/CISC/operation-room/backend/app'):
    for f in fs:
        if f.endswith('.py'):
            path = os.path.join(rt, f)
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read()
            if 'duckdb.connect(str(vault_db)' in content or 'duckdb.connect(str(vault_db), read_only=True)' in content:
                print('Fixing', path)
                content = content.replace('con = duckdb.connect(str(vault_db), read_only=True)', 'from operation_room.database import open_vault\n    con = open_vault(case_id)')
                content = content.replace('con = duckdb.connect(str(vault_db))', 'from operation_room.database import open_vault\n    con = open_vault(case_id)')
                with open(path, 'w', encoding='utf-8') as file:
                    file.write(content)

