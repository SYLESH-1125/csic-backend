import sys
import re

f = r'c:\CISC\operation-room\frontend\src\components\studio-v4\dialogs\GhostWriterWizard.tsx'

with open(f, 'r', encoding='utf-8') as file:
    txt = file.read()

# remove old injected ones
txt = re.sub(r'  const new_font_family =.*?\n', '', txt)
txt = re.sub(r'  const new_primary_color =.*?\n', '', txt)
txt = re.sub(r'  const new_mock_palette =.*?\n', '', txt)

vars_to_add = """
  const new_font_family = new_font_style === "times" ? "'Times New Roman', serif" : new_font_style === "georgia" ? "'Georgia', serif" : "'Inter', sans-serif";
  const new_primary_color = new_selected_cover === "1" ? "#0F172A" : new_selected_cover === "2" ? "#312e81" : "#4c0519";
  const new_mock_palette = new_graph_style === "classic" ? { bg: "#FFFFFF", grid: "#E2E8F0", c1: "#0284C7", c2: "#38BDF8" } : new_graph_style === "modern" ? { bg: "#F8FAFC", grid: "#CBD5E1", c1: "#4F46E5", c2: "#818CF8" } : { bg: "#0F172A", grid: "#334155", c1: "#38BDF8", c2: "#BAE6FD" };
"""

hook_str = "const [new_custom_tab, setNewCustomTab] = useState<'fonts' | 'graphs' | 'tables'>('fonts');"

if hook_str in txt:
    txt = txt.replace(hook_str, hook_str + '\n' + vars_to_add)
    with open(f, 'w', encoding='utf-8') as file:
        file.write(txt)
    print("Vars placed correctly.")
else:
    print("Could not find the hook to inject after.")
