
import os, re

for rt, ds, fs in os.walk('C:/CISC/operation-room/backend/app'):
    for f in fs:
        if f.endswith('.py'):
            path = os.path.join(rt, f)
            with open(path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
            changed = False
            for i, line in enumerate(lines):
                if 'from operation_room.database import open_vault' in line:
                    base_indent = len(line) - len(line.lstrip())
                    lines[i] = (' ' * 4) + line.lstrip() if base_indent > 8 else line
                    changed = True
                if 'con = open_vault(case_id)' in line:
                    base_indent = len(line) - len(line.lstrip())
                    lines[i] = (' ' * 4) + line.lstrip() if base_indent > 8 else line
                    changed = True
            if changed:
                print('Reformatting', path)
                with open(path, 'w', encoding='utf-8') as f:
                    f.writelines(lines)

