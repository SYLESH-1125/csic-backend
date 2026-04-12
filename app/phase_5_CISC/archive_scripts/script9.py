import sys

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('''target_url = f"{frontend_url}/cases/{case_id}/studio-v4/print?docId={doc_id}"
                if cover_id:
                    target_url += f"&coverId={cover_id}"
                if cover_id:
                    target_url += f"&coverId={cover_id}"''', '''target_url = f"{frontend_url}/cases/{case_id}/studio-v4/print?docId={doc_id}"
                if cover_id:
                    target_url += f"&coverId={cover_id}"''')

with open(sys.argv[1], 'w', encoding='utf-8') as f:
    f.write(text)
print("Fixed duplicate")
