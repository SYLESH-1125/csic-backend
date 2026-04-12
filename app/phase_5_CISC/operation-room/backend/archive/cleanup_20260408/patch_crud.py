import re

path = r'C:\CISC\operation-room\backend\app\services\crud_agent.py'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Imports
if 'import polars as pl' not in text:
    text = text.replace('import numpy as np\n', 'import numpy as np\nimport polars as pl\nfrom sentence_transformers import SentenceTransformer\n')

# 2. Sensitivity rules
new_rules = '''# Semantic Sensitivity (Vector Embedded)
ANCHOR_CONCEPTS = {
    "CRITICAL": ["payroll", "compensation", "password", "credential", "audit trail", "financial", "secret"],
    "HIGH": ["customer", "pii", "user personal", "account", "admin", "executive"],
    "MEDIUM": ["order", "business transaction", "config", "system log"]
}

_embedding_model = None
_anchor_embeddings = {}

def get_embedding_model():
    global _embedding_model, _anchor_embeddings
    if _embedding_model is None:
        try:
            _embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
            for level, phrases in ANCHOR_CONCEPTS.items():
                _anchor_embeddings[level] = _embedding_model.encode(phrases)
        except Exception as e:
            print(f"Failed to load sentence_transformers: {e}. Using fallback.")
            _embedding_model = "fallback"
    return _embedding_model
'''
if 'ANCHOR_CONCEPTS =' not in text:
    text = re.sub(r'# Sensitivity classification by target pattern\nSENSITIVITY_RULES = \[.*?\n\]', new_rules, text, flags=re.DOTALL)

# 3. Classify method
new_classify = '''def _classify_sensitivity(target):
    """Classify target's data sensitivity using vectors."""
    if not target:
        return "LOW", ""
        
    model = get_embedding_model()
    if model == "fallback":
        target_lower = target.lower()
        if any(x in target_lower for x in ANCHOR_CONCEPTS["CRITICAL"]): return "CRITICAL", "Fallback match"
        if any(x in target_lower for x in ANCHOR_CONCEPTS["HIGH"]): return "HIGH", "Fallback match"
        return "LOW", "Fallback match"
        
    target_emb = model.encode([target])[0]
    best_level = "LOW"
    best_score = 0.0
    
    for level, phrases_emb in _anchor_embeddings.items():
        norms = np.linalg.norm(phrases_emb, axis=1) * np.linalg.norm(target_emb)
        norms[norms == 0] = 1e-9
        sims = np.dot(phrases_emb, target_emb) / norms
        max_sim = float(np.max(sims))
        if max_sim > best_score:
            best_score = max_sim
            best_level = level
            
    if best_score < 0.35:
        return "LOW", f"Semantic score low ({best_score:.2f})"
        
    return best_level, f"Semantic match ({best_score:.2f})"'''
if 'def _classify_sensitivity(target):' in text and 'model.encode' not in text:
    text = re.sub(r'def _classify_sensitivity\(target\):\n.*?return "LOW", ""', new_classify, text, flags=re.DOTALL)

with open(path, 'w', encoding='utf-8') as f:
    f.write(text)
print("Patch 1 done")
