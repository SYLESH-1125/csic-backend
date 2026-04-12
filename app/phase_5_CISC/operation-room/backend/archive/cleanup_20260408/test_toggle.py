import sys
sys.path.append('C:/CISC/operation-room/backend')
from operation_room.services.timeline_service import toggle_anchor

try:
    toggle_anchor('CASE-FORENSIC-001', {'tl_event_id': 'f7d54baf-0bed-4fa4-8af4-cbe46618e4da', 'is_anchor': True, 'label': 'Manual anchor'})
    print('Success!')
except Exception as e:
    import traceback
    traceback.print_exc()
