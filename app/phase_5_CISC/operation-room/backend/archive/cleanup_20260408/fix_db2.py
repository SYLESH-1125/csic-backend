import os, re
import pprint

for rt, ds, fs in os.walk('C:/CISC/operation-room/backend/app'):
    for f in fs:
        if f.endswith('.py'):
            path = os.path.join(rt, f)
            with open(path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
            
            changed = False
            for i, line in enumerate(lines):
                if 'from operation_room.database import open_vault' in line:
                    continue
                match = re.search(r'^(\s*)con = open_vault\(case_id\)', line)
                if match and lines[i-1].strip() == 'from operation_room.database import open_vault':
                    # Fix indentation 
                    indent = len(lines[i-2]) - len(lines[i-2].lstrip())
                    if not lines[i-2].strip():
                        indent = len(lines[i-3]) - len(lines[i-3].lstrip())
                    lines[i-1] = (' ' * indent) + lines[i-1].strip() + '\n'
                    lines[i] = (' ' * indent) + lines[i].strip() + '\n'
                    changed = True
            if changed:
                print('Fixed indent in', path)
                with open(path, 'w', encoding='utf-8') as file:
                    file.writelines(lines)

