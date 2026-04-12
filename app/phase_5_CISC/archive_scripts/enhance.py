import re

file_path = "C:/CISC/operation-room/backend/app/services/export_service.py"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update Playwright wait_until network idle timeout
content = content.replace(
    "page.goto(target_url, wait_until='networkidle')",
    "page.goto(target_url, wait_until='networkidle', timeout=180000)"
)

# 2. Update Playwright wait_for_timeout to be dynamic or simply longer
content = content.replace(
    "page.wait_for_timeout(3000)",
    "page.wait_for_timeout(6000)  # Extended for 100+ page datasets"
)

# 3. Update Dynamite requests.post timeout for deep NLP processing
content = content.replace(
    "timeout=30)",
    "timeout=300) # 5 Minutes for 100+ pages of JSON generation"
)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Export capacities enhanced for 100+ pages")
