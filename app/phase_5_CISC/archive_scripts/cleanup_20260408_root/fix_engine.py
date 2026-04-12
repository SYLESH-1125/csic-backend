import os

content = """import os
import json
from typing import Any, Dict, List, Optional
    
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    pass

def build_report_preview(raw: Dict[str, Any], new_gstyle: str = 'classic', selected_graphs: List[str] = None) -> Dict[str, Any]:
    return {'message': 'Preview not available in Exact-Match rendering mode'}

def generate_forensic_report(
    raw_data_object: dict,
    output_path: str,
    custom_color: str = '#1e3a8a',
    cover_path: str = None,
    new_gstyle: str = 'classic',
    selected_graphs: list = None
):
    import playwright
    from playwright.sync_api import sync_playwright

    ast = raw_data_object.get('sheet_ast', {})
    source = raw_data_object.get('source', '')
    
    frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
    print(f'[Dynamite Engine] Exact-match to {frontend_url} for PDF Conversion')
    
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-web-security']
        )
        context = browser.new_context(
            viewport={'width': 1200, 'height': 800},
            device_scale_factor=2
        )
        page = context.new_page()
        
        # Navigate to a generic route to set localStorage
        page.goto(f"{frontend_url}/favicon.ico", wait_until="domcontentloaded")
        
        ast_json_str = json.dumps(ast)
        # Inject AST as string mapped inside localStorage
        js_eval = f"window.localStorage.setItem('dynamite_engine_ast', {json.dumps(ast_json_str)});"
        page.evaluate(js_eval)
        
        # Navigate to print
        page.goto(f"{frontend_url}/print?engine=dynamite", wait_until="networkidle")
        page.wait_for_timeout(3000)
        
        page.pdf(
            path=output_path,
            format="A4",
            print_background=True,
            margin={"top": "0in", "right": "0in", "bottom": "0in", "left": "0in"}
        )
        browser.close()
        
    print(f'[Dynamite Engine] Successfully rendered exact-match PDF to {output_path}')
"""

# Now write it to the engine_backend 
with open(r"C:\CISC\operation-room\dynamite_report_engine (2)\dynamite_report_engine\engine_backend\forensic_engine.py", "w") as f:
    f.write(content)
print("Updated forensic_engine.py")
