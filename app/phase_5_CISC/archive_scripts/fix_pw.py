import re
with open(r'c:\CISC\operation-room\backend\app\services\export_service.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = "page.goto(target_url, wait_until='networkidle', timeout=180000)\n\n                  # Extra wait foRecharts animations to settle\n                  page.wait_for_timeout(6000)  # Extended for 100+ page datasets\n\n                  page.pdf("

replacement = """page.goto(target_url, wait_until='networkidle', timeout=180000)

                  try:
                      page.wait_for_selector('.canvas-render-complete', state='attached', timeout=60000)
                  except Exception as e:
                      pass
                  
                  # Extra wait to ensure Recharts animations are physically drawn
                  page.wait_for_timeout(2000)

                  page.pdf("""

new_text = text.replace(target, replacement)
with open(r'c:\CISC\operation-room\backend\app\services\export_service.py', 'w', encoding='utf-8') as f:
    f.write(new_text)