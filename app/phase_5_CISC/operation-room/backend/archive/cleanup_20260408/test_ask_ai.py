import httpx, asyncio

async def h():
    try:
        async with httpx.AsyncClient(timeout=300) as c:
            print("Sending request...")
            r = await c.post('http://127.0.0.1:8000/api/cases/CASE-FORENSIC-001/correlation/chat', json={'query': 'What is the most likely entry point?', 'llm_provider': 'Qwen3 (Local)'})
            print(r.status_code, r.text)
    except Exception as e:
        print("ERROR:", e)

asyncio.run(h())