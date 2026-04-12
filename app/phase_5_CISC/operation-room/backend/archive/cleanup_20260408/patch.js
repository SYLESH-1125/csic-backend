const fs = require('fs');
let content = fs.readFileSync('c:/CISC/operation-room/frontend/src/components/tiptap/EvidenceBlockNode.tsx', 'utf8');
content = content.replace(/actor:.*?,/g, 'actor: Count: ,');
fs.writeFileSync('c:/CISC/operation-room/frontend/src/components/tiptap/EvidenceBlockNode.tsx', content);
