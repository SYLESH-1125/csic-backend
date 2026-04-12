import sys

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    text = f.read()

# Replace ExportRequest in studio_v4
old_request = '''class ExportRequest(BaseModel):
    doc_id: str
    actor: str = "investigator"
    frontend_url: Optional[str] = None'''

new_request = '''class ExportRequest(BaseModel):
    doc_id: str
    actor: str = "investigator"
    frontend_url: Optional[str] = None
    cover_id: Optional[str] = None'''

if old_request in text:
    text = text.replace(old_request, new_request)
    
old_export_pdf = '''@router.post("/exports/pdf")
def api_export_pdf(case_id: str, req: ExportRequest):
    from app.services.export_service import export_pdf

    result = export_pdf(case_id=case_id, doc_id=req.doc_id, actor=req.actor, frontend_url=req.frontend_url)'''

new_export_pdf = '''@router.post("/exports/pdf")
def api_export_pdf(case_id: str, req: ExportRequest):
    from app.services.export_service import export_pdf

    result = export_pdf(case_id=case_id, doc_id=req.doc_id, actor=req.actor, frontend_url=req.frontend_url, cover_id=req.cover_id)'''

if old_export_pdf in text:
    text = text.replace(old_export_pdf, new_export_pdf)

with open(sys.argv[1], 'w', encoding='utf-8') as f:
    f.write(text)
print("Updated studio_v4.py")
