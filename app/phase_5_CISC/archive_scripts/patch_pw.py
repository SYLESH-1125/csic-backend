import re

with open(r'c:\CISC\operation-room\backend\app\services\export_service.py', 'r', encoding='utf-8') as f:
    text = f.read()

new_text = re.sub(
    r"page\.goto\(target_url, wait_until='networkidle', timeout=180000\)\s*# Extra wait foRecharts animations to settle\s*page\.wait_for_timeout\(6000\)\s*# Extended for 100\+ page datasets\s*page\.pdf\(",
    \"\"\"page.goto(target_url, wait_until='networkidle', timeout=180000)

                  try:
                      page.wait_for_selector('.canvas-render-complete', state='attached', timeout=65000)
                  except Exception as e:
                      pass

                  page.wait_for_timeout(2000)

                  page.pdf(\"\"\",
    text
)

with open(r'c:\CISC\operation-room\backend\app\services\export_service.py', 'w', encoding='utf-8') as f:
    f.write(new_text)
