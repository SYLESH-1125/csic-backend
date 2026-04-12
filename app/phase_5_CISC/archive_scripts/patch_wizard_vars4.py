f = r'c:\CISC\operation-room\frontend\src\components\studio-v4\dialogs\GhostWriterWizard.tsx'

with open(f, 'r', encoding='utf-8') as file:
    txt = file.read()

txt = txt.replace('{ bg: "#FFFFFF", grid: "#E2E8F0", c1: "#0284C7", c2: "#38BDF8", text: "#334155" }', 
                  '{ bg: "#FFFFFF", grid: "#E2E8F0", c1: "#0284C7", c2: "#38BDF8", c3: "#0EA5E9", c4: "#7DD3FC", text: "#334155" }')

txt = txt.replace('{ bg: "#F8FAFC", grid: "#CBD5E1", c1: "#4F46E5", c2: "#818CF8", text: "#1E293B" }', 
                  '{ bg: "#F8FAFC", grid: "#CBD5E1", c1: "#4F46E5", c2: "#818CF8", c3: "#6366F1", c4: "#A5B4FC", text: "#1E293B" }')

txt = txt.replace('{ bg: "#0F172A", grid: "#334155", c1: "#38BDF8", c2: "#BAE6FD", text: "#F8FAFC" }', 
                  '{ bg: "#0F172A", grid: "#334155", c1: "#38BDF8", c2: "#BAE6FD", c3: "#0EA5E9", c4: "#7DD3FC", text: "#F8FAFC" }')

with open(f, 'w', encoding='utf-8') as file:
    file.write(txt)
print("Updated palettes.")
