import urllib.request, json, urllib.error
req = urllib.request.Request('http://127.0.0.1:8000/api/cases/CASE-FORENSIC-001/correlation/chat', data=b'{"query":"hello","llm_provider":"Qwen3","run_id":"test"}', headers={'Content-Type': 'application/json'}, method='POST')
try:
    urllib.request.urlopen(req)
except Exception as e:
    print(e.read().decode() if hasattr(e, 'read') else str(e))
