
import re
with open(r'C:\CISC\operation-room\backend\app\services\export_service.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('SELECT title, data FROM studio_documents', 'SELECT title, ast_json FROM studio_documents')
text = text.replace('doc_data = json.loads(row[1]) if isinstance(row[1], str) else row[1]\n    except Exception as e:\n        return {''error'': str(e)}\n    finally:\n        conn.close()\n\n    ast = doc_data.get(''ast'', {})\n\n    # Map frontend AST to formal backend schema\n    dynamite_schema = _ast_to_dynamite_schema(ast, case_id)', 'ast = json.loads(row[1]) if isinstance(row[1], str) else row[1]\n    except Exception as e:\n        return {''error'': str(e)}\n    finally:\n        conn.close()\n\n    # Map frontend AST to formal backend schema\n    dynamite_schema = _ast_to_dynamite_schema(ast, case_id)')

with open(r'C:\CISC\operation-room\backend\app\services\export_service.py', 'w', encoding='utf-8') as f:
    f.write(text)

