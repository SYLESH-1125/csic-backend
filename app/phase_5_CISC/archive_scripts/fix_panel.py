import re

path = r'c:\CISC\operation-room\frontend\src\components\studio-v4\ExpandablePanel.tsx'
with open(path, 'r', encoding='utf-8') as f: 
    content = f.read()

# Fix PanelHeader layout to prevent overlap on narrow squeeze
content = content.replace(
    '<div className="flex items-center justify-between px-4 py-3">',
    '<div className="flex items-center justify-between px-4 py-3 min-w-0">'
)
content = content.replace(
    '<div className="flex items-center gap-2">',
    '<div className="flex items-center gap-2 min-w-0 flex-1 pr-2">'
)
content = content.replace(
    '<span style={{ color: iconColor }}>{icon}</span>',
    '<span className="flex-shrink-0" style={{ color: iconColor }}>{icon}</span>'
)
content = content.replace(
    'tracking-tight">{title}</h2>',
    'tracking-tight truncate">{title}</h2>'
)
content = content.replace(
    '<div className="flex items-center gap-1">',
    '<div className="flex items-center gap-1 flex-shrink-0">'
)

# Fix motion.div classes for Sidebar Overlap Fix (Phase 1)
content = content.replace(
    '"flex-shrink-0 overflow-hidden bg-background relative border-r max-h-[calc(100vh-64px)]"',
    '"absolute left-0 top-0 bottom-0 z-40 overflow-hidden bg-background/95 backdrop-blur shadow-2xl border-r"'
)

with open(path, 'w', encoding='utf-8') as f: 
    f.write(content)
print("Done")
