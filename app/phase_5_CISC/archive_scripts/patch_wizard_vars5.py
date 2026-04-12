import re
f = r'c:\CISC\operation-room\frontend\src\components\studio-v4\dialogs\GhostWriterWizard.tsx'

with open(f, 'r', encoding='utf-8') as file:
    txt = file.read()

txt = re.sub(r'\(new_g\) =>', '(new_g: any) =>', txt)

with open(f, 'w', encoding='utf-8') as file:
    file.write(txt)
