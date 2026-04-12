content = open('c:/CISC/operation-room/frontend/src/components/tiptap/EvidenceBlockNode.tsx', 'r', encoding='utf-8').read()
content = content.replace('actor: Count: ,', 'actor: "Count: " + (c.event_count || 0),')
open('c:/CISC/operation-room/frontend/src/components/tiptap/EvidenceBlockNode.tsx', 'w', encoding='utf-8').write(content)
