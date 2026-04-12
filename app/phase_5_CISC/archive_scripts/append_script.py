def export_dynamite_pdf(case_id: str, doc_id: str, actor: str = 'investigator', frontend_url: str = None, cover_id: str = None, focus_mode: str = 'Review') -> dict:
    import json, os, uuid, requests
    from pathlib import Path
    from app.config import settings
    from app.database import open_vault

    export_dir = Path(settings.CASES_DIR) / case_id / 'exports'
    export_dir.mkdir(parents=True, exist_ok=True)
    export_id = str(uuid.uuid4())[:8]

    conn = open_vault(case_id)
    try:
        row = conn.execute('SELECT title, data FROM studio_documents WHERE doc_id=?', [doc_id]).fetchone()
        if not row:
            return {'error': 'Doc not found'}
        title = row[0]
        doc_data = json.loads(row[1]) if isinstance(row[1], str) else row[1]
    except Exception as e:
        return {'error': str(e)}
    finally:
        conn.close()

    ast = doc_data.get('ast', {})

    dynamite_payload = {
        'case_id': case_id,
        'payload': {
            'source': 'canvas_sheet',
            'sheet_ast': ast,
            'title': title,
            'actor': actor,
            'cover_selection': cover_id
        }
    }

    try:
        resp = requests.post('http://localhost:8001/api/report/generate', json=dynamite_payload, timeout=30)
        resp.raise_for_status()
    except Exception as e:
        return {'error': 'Dynamite Engine failed: ' + str(e)}

    safe_title = title.replace(' ', '_').lower()
    filename = f'{safe_title}_{export_id}_dynamite.pdf'
    filepath = export_dir / filename
    with open(filepath, 'wb') as f:
        f.write(resp.content)

    return {
        'filename': filename,
        'filepath': str(filepath),
        'format': 'pdf',
        'engine': 'dynamite'
    }
