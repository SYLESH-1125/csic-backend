
import os, re

def replace_duck(path):
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    changed = False
    for i, line in enumerate(lines):
        match1 = re.search(r'^(\s*)con = duckdb\.connect\(str\(vault_db\)\)', line)
        match2 = re.search(r'^(\s*)con = duckdb\.connect\(str\(vault_db\), read_only=True\)', line)
        
        if match1 or match2:
            indent = (match1.group(1) if match1 else match2.group(1))
            
            # replace this line with two lines: import and assignment
            new_lines = [
                indent + 'from operation_room.database import open_vault\n',
                indent + 'con = open_vault(case_id)\n'
            ]
            lines[i] = ''.join(new_lines)
            changed = True
            
    if changed:
        print('Fixing', path)
        with open(path, 'w', encoding='utf-8') as f:
            f.writelines(lines)

for rt, ds, fs in os.walk('C:/CISC/operation-room/backend/app'):
    for f in fs:
        if f.endswith('.py'):
            replace_duck(os.path.join(rt, f))

