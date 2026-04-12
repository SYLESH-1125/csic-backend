content = open('C:/CISC/operation-room/backend/app/services/timeline_service.py', 'r', encoding='utf-8').read()
content = content.replace('is_anchor, anchor_label, is_anchor, anchor_label', 'is_anchor, anchor_label')
content = content.replace('\"is_anchor\", \"anchor_label\", \"is_anchor\", \"anchor_label\"]', '\"is_anchor\", \"anchor_label\"]')
open('C:/CISC/operation-room/backend/app/services/timeline_service.py', 'w', encoding='utf-8').write(content)
