import re
path = r'c:\CISC\operation-room\frontend\src\components\studio-v4\panels\AnomalyPanel.tsx'
with open(path, 'r', encoding='utf-8') as f: content = f.read()
new_content = content.replace('cn("flex flex-col h-full", className)', 'cn("flex flex-col h-full min-h-0", className)')

with open(path, 'w', encoding='utf-8') as f: f.write(new_content)
print('Done')
