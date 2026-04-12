import sys

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    text = f.read()

old_sig = '''def export_pdf(case_id: str, doc_id: str, actor: str = "investigator", frontend_url: str = None) -> dict:'''
new_sig = '''def export_pdf(case_id: str, doc_id: str, actor: str = "investigator", frontend_url: str = None, cover_id: str = None) -> dict:'''

old_url = '''target_url = f"{frontend_url}/cases/{case_id}/studio-v4/print?docId={doc_id}"'''
new_url = '''target_url = f"{frontend_url}/cases/{case_id}/studio-v4/print?docId={doc_id}"
                if cover_id:
                    target_url += f"&coverId={cover_id}"'''

if old_sig in text:
    text = text.replace(old_sig, new_sig)
if old_url in text:
    text = text.replace(old_url, new_url)

with open(sys.argv[1], 'w', encoding='utf-8') as f:
    f.write(text)
print("Updated export_service.py")
