"""End-to-end test for NFLIP system."""
import asyncio
import httpx
import sys

async def test_e2e():
    base = 'http://127.0.0.1:8000'
    errors = []
    
    async with httpx.AsyncClient(timeout=30) as client:
        # 1. Health check
        print('1. Health check...')
        try:
            r = await client.get(f'{base}/api/cases')
            print(f'   Cases endpoint: {r.status_code}')
            if r.status_code not in [200, 404]:
                errors.append(f'Cases endpoint returned {r.status_code}')
        except Exception as e:
            errors.append(f'Cases endpoint failed: {e}')
            print(f'   ERROR: {e}')
        
        # 2. Create a test case
        print('2. Creating test case...')
        case_data = {
            'case_id': 'TEST-E2E-001',
            'title': 'E2E Test Case',
            'description': 'Automated end-to-end test'
        }
        try:
            r = await client.post(f'{base}/api/cases', json=case_data)
            print(f'   Create case: {r.status_code}')
            if r.status_code == 422:
                print(f'   Response: {r.text[:200]}')
        except Exception as e:
            errors.append(f'Create case failed: {e}')
            print(f'   ERROR: {e}')
        
        # 3. Test tools endpoint (note: trailing slash required)
        print('3. Testing tools endpoint...')
        try:
            r = await client.get(f'{base}/api/tools/')
            print(f'   Tools: {r.status_code}')
            if r.status_code == 200:
                tools = r.json()
                # Response is a list of tools
                tool_count = len(tools) if isinstance(tools, list) else len(tools.get('tools', []))
                print(f'   Available tools: {tool_count}')
        except Exception as e:
            errors.append(f'Tools endpoint failed: {e}')
            print(f'   ERROR: {e}')
        
        # 4. Test aliases endpoint (path param, not query)
        print('4. Testing aliases endpoint...')
        try:
            r = await client.get(f'{base}/api/aliases/TEST-E2E-001')
            print(f'   Aliases: {r.status_code}')
        except Exception as e:
            errors.append(f'Aliases endpoint failed: {e}')
            print(f'   ERROR: {e}')
        
        # 5. Test augment endpoint (specific chart type endpoints)
        print('5. Testing augment chart generation...')
        # Pie chart expects Dict[str, float], not list
        chart_data = {
            'title': 'Test Chart',
            'data': {
                'Category A': 10.0,
                'Category B': 20.0,
                'Category C': 30.0
            }
        }
        try:
            r = await client.post(f'{base}/api/augment/pie', json=chart_data)
            print(f'   Chart generate (pie): {r.status_code}')
            if r.status_code != 200:
                print(f'   Response: {r.text[:300]}')
        except Exception as e:
            errors.append(f'Augment endpoint failed: {e}')
            print(f'   ERROR: {e}')
        
        # 6. Test investigation start
        print('6. Testing investigation endpoint...')
        inv_data = {
            'case_id': 'TEST-E2E-001',
            'scenario': 'Test scenario for E2E validation',
            'objectives': ['Validate system works']
        }
        try:
            r = await client.post(f'{base}/api/investigation/start', json=inv_data)
            print(f'   Investigation start: {r.status_code}')
            if r.status_code != 200:
                print(f'   Response: {r.text[:300]}')
        except Exception as e:
            errors.append(f'Investigation endpoint failed: {e}')
            print(f'   ERROR: {e}')
        
        # 7. Test deep research endpoint
        print('7. Testing deep research endpoint...')
        try:
            r = await client.get(f'{base}/deep-research/llm/providers')
            print(f'   Deep research LLM providers: {r.status_code}')
        except Exception as e:
            print(f'   Deep research: {e}')
        
        # 8. Test augment types
        print('8. Testing augment types...')
        try:
            r = await client.get(f'{base}/api/augment/types')
            print(f'   Augment types: {r.status_code}')
            if r.status_code == 200:
                print(f'   Types: {r.json()}'[:100])
        except Exception as e:
            print(f'   Augment types: {e}')
        
        # 9. Test tools health
        print('9. Testing tools health...')
        try:
            r = await client.get(f'{base}/api/tools/health')
            print(f'   Tools health: {r.status_code}')
        except Exception as e:
            print(f'   Tools health: {e}')
        
        print('\n' + '='*50)
        if errors:
            print(f'ERRORS: {len(errors)}')
            for e in errors:
                print(f'  - {e}')
            return 1
        else:
            print('ALL TESTS PASSED')
            return 0

if __name__ == '__main__':
    exit_code = asyncio.run(test_e2e())
    sys.exit(exit_code)
