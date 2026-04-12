import asyncio
import concurrent.futures
from playwright.sync_api import sync_playwright
import sys

def f():
    # Simulate what anyio might do
    loop = asyncio.SelectorEventLoop()
    asyncio.set_event_loop(loop)
    
    # My old fix:
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
    try:
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            b.close()
        print('Policy change worked')
    except Exception as e:
        print('Policy change failed:', e)
        
    # Proposed new fix:
    if sys.platform == 'win32':
        asyncio.set_event_loop(asyncio.ProactorEventLoop())
        
    try:
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            b.close()
        print('Explicit loop setting worked')
    except Exception as e:
        print('Explicit loop setting failed:', e)

with concurrent.futures.ThreadPoolExecutor() as e:
    e.submit(f).result()
