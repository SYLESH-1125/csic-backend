import re
file_path = "C:/CISC/operation-room/backend/app/services/export_service.py"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# Replace the memory-heavy resp.content write with a buffered streaming writer for heavy 100+ page PDFs
streaming_write = """      resp = requests.post('http://localhost:8001/api/report/generate', json=dynamite_payload, stream=True, timeout=300)
      resp.raise_for_status()
  except Exception as e:
      return {'error': 'Dynamite Engine failed: ' + str(e)}

  safe_title = title.replace(' ', '_').lower()
  filename = f'{safe_title}_{export_id}_dynamite.pdf'
  filepath = export_dir / filename
  
  # Stream the PDF to disk in chunks to handle 100+ page reports without RAM bottlenecks
  with open(filepath, 'wb') as f:
      for chunk in resp.iter_content(chunk_size=65536): 
          if chunk:
              f.write(chunk)"""

content = re.sub(
    r"resp = requests\.post\('http://localhost:8001/api/report/generate', json=dynamite_payload, timeout=300\)\n *resp\.raise_for_status\(\)\n *except Exception as e:\n *return \{'error': 'Dynamite Engine failed: ' \+ str\(e\)\}\n\n *safe_title = title\.replace\(' ', '_'\)\.lower\(\)\n *filename = f'\{safe_title\}_\{export_id\}_dynamite\.pdf'\n *filepath = export_dir / filename\n *with open\(filepath, 'wb'\) as f:\n *f\.write\(resp\.content\)",
    streaming_write,
    content,
    flags=re.MULTILINE
)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)
print("Memory-efficient streaming patched")
