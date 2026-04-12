import re
f = r'c:\CISC\operation-room\frontend\src\components\studio-v4\dialogs\GhostWriterWizard.tsx'

with open(f, 'r', encoding='utf-8') as file:
    txt = file.read()

# Replace any word starting with new_ inside map parameters
txt = re.sub(r'\(\s*(new_[a-zA-Z0-9_]+)\s*\)\s*=>', r'(\1: any) =>', txt)

with open(f, 'w', encoding='utf-8') as file:
    file.write(txt)
