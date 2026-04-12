import sys
f = r'c:\CISC\operation-room\frontend\src\components\studio-v4\dialogs\GhostWriterWizard.tsx'

with open(f, 'r', encoding='utf-8') as file:
    txt = file.read()

vars_to_add = """
  const new_font_family = new_font_style === "times" ? "'Times New Roman', serif" : new_font_style === "georgia" ? "'Georgia', serif" : "'Inter', sans-serif";
  const new_primary_color = new_selected_cover === "1" ? "#0F172A" : new_selected_cover === "2" ? "#312e81" : "#4c0519";
  const new_mock_palette = new_graph_style === "classic" ? { bg: "#FFFFFF", grid: "#E2E8F0", c1: "#0284C7", c2: "#38BDF8" } : new_graph_style === "modern" ? { bg: "#F8FAFC", grid: "#CBD5E1", c1: "#4F46E5", c2: "#818CF8" } : { bg: "#0F172A", grid: "#334155", c1: "#38BDF8", c2: "#BAE6FD" };
"""

if 'return (' in txt:
    # Just find the first `return (` which is inside the component.
    idx = txt.find('return (')
    
    # We want to insert exactly before the final return statement, so let's find `return (` that belongs to the main component.
    # Actually `runExport` has a return inside it. Let's find `  return (` (with spaces)
    idx = txt.rfind('  return (')
    if idx == -1:
        idx = txt.find('return (')

    txt = txt[:idx] + vars_to_add + "\n" + txt[idx:]
    with open(f, 'w', encoding='utf-8') as file:
        file.write(txt)
    print("Injected vars_to_add!")
else:
    print("Could not find 'return ('")
