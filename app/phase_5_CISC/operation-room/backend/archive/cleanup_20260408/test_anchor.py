import requests
c=requests.get('http://localhost:8000/api/cases').json()[0]['case_id']
events = requests.post(f'http://localhost:8000/api/cases/{c}/timeline/search', json={'operator': 'AND', 'conditions': []}).json()
eid = events[0]['tl_event_id']
print(f"Targeting {eid}")
print("Toggle:", requests.post(f'http://localhost:8000/api/cases/{c}/timeline/anchors', json={'tl_event_id': eid, 'is_anchor': True}).text)
print("Event check:", [e for e in requests.post(f'http://localhost:8000/api/cases/{c}/timeline/search', json={'operator': 'AND', 'conditions': []}).json() if e['tl_event_id'] == eid][0])
