"""
Full investigation flow test with sample scenario.
Tests the complete pipeline from scenario input to findings.
"""
import asyncio
import httpx
import json
import sys

SAMPLE_SCENARIO = """
INCIDENT REPORT: Suspected Data Exfiltration

Timeline:
- January 5, 2024 03:15 AM: Security alert triggered on server DB-PROD-01 (192.168.1.100)
- January 5, 2024 03:18 AM: Unusual outbound traffic detected to IP 45.33.32.156
- January 5, 2024 03:22 AM: Large file transfer (2.3GB) to external endpoint
- January 5, 2024 03:30 AM: Incident response team notified

Affected Systems:
- DB-PROD-01 (192.168.1.100) - Primary production database
- APP-WEB-01 (192.168.1.50) - Web application server
- User account: admin.backup@company.com

Investigation Objectives:
1. Determine how the attacker gained initial access
2. Identify all systems compromised
3. Assess what data was exfiltrated
4. Establish timeline of attack
5. Identify indicators of compromise (IOCs)
"""

async def test_full_investigation():
    base = 'http://127.0.0.1:8000'
    
    print('='*60)
    print('NFLIP E2E INVESTIGATION TEST')
    print('='*60)
    
    async with httpx.AsyncClient(timeout=60) as client:
        # 1. Create case
        print('\n[1] Creating investigation case...')
        case_data = {
            'case_id': 'CASE-EXFIL-2024-001',
            'title': 'Data Exfiltration Investigation',
            'description': 'Suspected data exfiltration from production database'
        }
        r = await client.post(f'{base}/api/cases', json=case_data)
        print(f'    Case creation: {r.status_code}')
        
        # 2. Start investigation
        print('\n[2] Starting AI investigation...')
        inv_request = {
            'case_id': 'CASE-EXFIL-2024-001',
            'scenario': SAMPLE_SCENARIO,
            'objectives': [
                'Determine initial access vector',
                'Identify compromised systems',
                'Assess data exfiltration scope'
            ],
            'time_range': {
                'start': '2024-01-01T00:00:00Z',
                'end': '2024-01-06T00:00:00Z'
            }
        }
        
        r = await client.post(
            f'{base}/api/investigation/start',
            json=inv_request,
            headers={'Accept': 'text/event-stream'}
        )
        print(f'    Investigation start: {r.status_code}')
        
        if r.status_code == 200:
            # Process SSE stream
            events = []
            findings = []
            phases = []
            
            content = r.text
            for line in content.split('\n'):
                if line.startswith('data:'):
                    try:
                        data = json.loads(line[5:].strip())
                        events.append(data)
                        
                        event_type = data.get('type') or data.get('event_type')
                        
                        if event_type == 'phase_start':
                            phase = data.get('phase', data.get('data', {}).get('phase', 'unknown'))
                            phases.append(phase)
                            print(f'    → Phase: {phase}')
                        
                        if event_type == 'finding':
                            findings.append(data)
                            
                    except json.JSONDecodeError:
                        pass
            
            print(f'\n    Phases completed: {len(phases)}')
            print(f'    Findings received: {len(findings)}')
            print(f'    Total events: {len(events)}')
        
        # 3. Test entity aliasing
        print('\n[3] Testing entity aliasing...')
        alias_request = {
            'entity_value': '192.168.1.100',
            'alias': 'db_prod_server',
            'entity_type': 'ip'
        }
        r = await client.post(
            f'{base}/api/aliases/CASE-EXFIL-2024-001/set',
            json=alias_request
        )
        print(f'    Set alias: {r.status_code}')
        if r.status_code != 200:
            print(f'    Response: {r.text[:200]}')
        
        # Resolve alias
        r = await client.get(
            f'{base}/api/aliases/CASE-EXFIL-2024-001/resolve/192.168.1.100'
        )
        print(f'    Resolve alias: {r.status_code}')
        if r.status_code == 200:
            print(f'    Result: {r.json()}')
        
        # 4. Test auto-aliasing (single entity)
        print('\n[4] Testing auto entity aliasing...')
        auto_alias_req = {
            'entity_value': '45.33.32.156'
        }
        r = await client.post(
            f'{base}/api/aliases/CASE-EXFIL-2024-001/auto',
            json=auto_alias_req
        )
        print(f'    Auto alias: {r.status_code}')
        if r.status_code == 200:
            result = r.json()
            print(f'    Generated alias: {result.get("alias", "N/A")}')
        
        # 5. Test tool execution
        print('\n[5] Testing individual tool execution...')
        tool_request = {
            'case_id': 'CASE-EXFIL-2024-001',
            'tool_id': 'timeline',
            'capability': 'build_timeline',
            'parameters': {}
        }
        r = await client.post(f'{base}/api/tools/timeline/execute', json=tool_request)
        print(f'    Timeline tool: {r.status_code}')
        
        # 6. Test augment charts
        print('\n[6] Testing chart generation...')
        
        # Pie chart
        pie_data = {
            'title': 'Event Distribution',
            'data': {
                'Login Events': 45.0,
                'File Access': 30.0,
                'Network Activity': 25.0
            }
        }
        r = await client.post(f'{base}/api/augment/pie', json=pie_data)
        print(f'    Pie chart: {r.status_code}')
        
        # Bar chart
        bar_data = {
            'title': 'Hourly Activity',
            'data': {
                '00:00': 10.0,
                '01:00': 5.0,
                '02:00': 3.0,
                '03:00': 45.0,
                '04:00': 8.0
            }
        }
        r = await client.post(f'{base}/api/augment/bar', json=bar_data)
        print(f'    Bar chart: {r.status_code}')
        
        # Radar (confidence) chart
        confidence_data = {
            'factors': {
                'Evidence Coverage': 0.85,
                'Module Agreement': 0.90,
                'Temporal Consistency': 0.75,
                'Cross Validation': 0.80,
                'Pattern Match': 0.70,
                'Research Alignment': 0.65
            },
            'overall': 0.78
        }
        r = await client.post(f'{base}/api/augment/confidence', json=confidence_data)
        print(f'    Confidence radar: {r.status_code}')
        
        # 7. List all aliases
        print('\n[7] Final alias check...')
        r = await client.get(f'{base}/api/aliases/CASE-EXFIL-2024-001')
        print(f'    Get aliases: {r.status_code}')
        if r.status_code == 200:
            aliases = r.json()
            # Handle both list and dict response formats
            if isinstance(aliases, list):
                print(f'    Total aliases: {len(aliases)}')
            else:
                print(f'    Total aliases: {len(aliases.get("aliases", []))}')
        
        print('\n' + '='*60)
        print('E2E INVESTIGATION TEST COMPLETE')
        print('='*60)
        return 0


if __name__ == '__main__':
    exit_code = asyncio.run(test_full_investigation())
    sys.exit(exit_code)
