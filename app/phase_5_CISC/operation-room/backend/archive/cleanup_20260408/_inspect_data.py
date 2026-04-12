import json, sys, os
sys.path.insert(0, os.path.dirname(__file__))

import duckdb
from pathlib import Path

vault_path = Path("data/cases/CASE-FORENSIC-001/vault.duckdb")
if not vault_path.exists():
    print("Vault not found at", vault_path)
    sys.exit(1)

conn = duckdb.connect(str(vault_path), read_only=True)
try:
    row = conn.execute("SELECT doc_id, ast_json FROM studio_documents LIMIT 1").fetchone()
    if not row:
        print("No documents found")
        sys.exit(1)
    
    ast = json.loads(row[1]) if isinstance(row[1], str) else row[1]
    print("AST type:", ast.get('type'))
    
    if ast.get('type') == 'v4-canvas':
        for pi, page in enumerate(ast.get('pages', [])):
            for el in page.get('elements', []):
                etype = el.get('type')
                data = el.get('data', {})
                print(f"\n=== Page {pi} | type={etype} ===")
                print(f"  top-level data keys: {list(data.keys())}")
                
                # Check nested 'data' key
                if 'data' in data:
                    nested = data['data']
                    nt = type(nested).__name__
                    if isinstance(nested, dict):
                        print(f"  data.data = dict with keys: {list(nested.keys())[:15]}")
                        # Check for deeper nesting
                        for k, v in nested.items():
                            vt = type(v).__name__
                            if isinstance(v, list) and v:
                                print(f"    data.data.{k} = list[{len(v)}], first={type(v[0]).__name__}")
                            elif isinstance(v, dict):
                                print(f"    data.data.{k} = dict with {len(v)} keys")
                            else:
                                print(f"    data.data.{k} = {vt}: {str(v)[:80]}")
                    elif isinstance(nested, list):
                        print(f"  data.data = list[{len(nested)}]")
                        if nested and isinstance(nested[0], dict):
                            print(f"    first item keys: {list(nested[0].keys())[:10]}")
                    else:
                        print(f"  data.data = {nt}: {str(nested)[:100]}")
finally:
    conn.close()
