
import sys, asyncio, threading
from playwright.sync_api import sync_playwright

def run():
    print('Thread starting')
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)
    
    with sync_playwright() as p:
        browser = p.chromium.launch()
        print('Success:', browser)
        browser.close()

t = threading.Thread(target=run)
t.start()
t.join()

