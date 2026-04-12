import re

file_path = "C:/CISC/operation-room/frontend/src/app/(studio)/cases/[id]/studio-v4/print/page.tsx"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# Make the setTimeout dynamic based on the length of pages (up to 100+ pages)
dynamic_timeout = """        // Automatically scale rendering time for 100+ page datasets
        const astPages = typeof window !== 'undefined' ? JSON.parse(window.localStorage.getItem('dynamite_engine_ast') || '{}')?.pages : undefined;
        const pageCount = Array.isArray(astPages) ? astPages.length : 20;
        const dynamicDelay = Math.max(3000, pageCount * 300); // e.g., 100 pages = 30 seconds
        setTimeout(() => setLoading(false), dynamicDelay);"""

content = re.sub(
    r"setTimeout\(\(\) => setLoading\(false\), 2000\)",
    dynamic_timeout,
    content
)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Dynamic timeout array scaled")
