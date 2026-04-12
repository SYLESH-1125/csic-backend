import os

path = r'C:\CISC\operation-room\backend\app\services\snapshot_service.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('`n', '\n')

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
