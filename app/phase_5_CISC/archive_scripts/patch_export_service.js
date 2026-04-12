const fs=require('fs'); 
let p='C:/CISC/operation-room/backend/app/services/export_service.py'; 
let c=fs.readFileSync(p,'utf8'); 

c=c.replace(/'cover_selection': cover_id/g, "'cover_selection': cover_id,\n            'case_id': case_id"); 
fs.writeFileSync(p,c); 
console.log('Patched');
