const fs = require('fs');

const path = 'C:/CISC/operation-room/backend/app/routes/studio_v4.py';
let fileContent = fs.readFileSync(path, 'utf8');

const targetBlock = `def api_export_pdf(case_id: str, req: ExportRequest):
    from app.services.export_service import export_pdf

    try:
        result = export_pdf(case_id=case_id, doc_id=req.doc_id, actor=req.actor, frontend_url=req.frontend_url, cover_id=req.cover_id, focus_mode=req.focus_mode)
        print("EXPORT_PDF RAW RESULT:", result)  # DEBUG`;

const replacementBlock = `def api_export_pdf(case_id: str, req: ExportRequest):
    from app.services.export_service import export_pdf, export_dynamite_pdf

    try:
        if req.engine == "dynamite":
            result = export_dynamite_pdf(case_id=case_id, doc_id=req.doc_id, actor=req.actor, frontend_url=req.frontend_url, cover_id=req.cover_id, focus_mode=req.focus_mode)
        else:
            result = export_pdf(case_id=case_id, doc_id=req.doc_id, actor=req.actor, frontend_url=req.frontend_url, cover_id=req.cover_id, focus_mode=req.focus_mode)
        print("EXPORT_PDF RAW RESULT:", result)  # DEBUG`;

fileContent = fileContent.replace(targetBlock, replacementBlock);
fs.writeFileSync(path, fileContent);
console.log("Patched API PDF Route");
