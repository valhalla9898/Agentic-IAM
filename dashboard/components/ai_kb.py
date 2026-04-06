import os
import json
import hashlib
import re
import html
from typing import List, Dict, Optional, Tuple

INDEX_FILE = ".ai_index.json"

STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "can",
    "do",
    "does",
    "for",
    "from",
    "get",
    "guide",
    "help",
    "how",
    "i",
    "is",
    "it",
    "me",
    "of",
    "or",
    "please",
    "show",
    "the",
    "to",
    "use",
    "what",
    "why",
    "with",
    "you",
}


SENSITIVE_PATTERNS = [
    r"\.env$",
    r"secret",
    r"password",
    r"key$",
    r"\.pem$",
    r"\.pfx$",
    r"credentials",
    r"data/agent_registry",
    r"secrets/",
]


def _is_sensitive_path(path: str) -> bool:
    low = path.replace('\\\\', '/').lower()
    for p in SENSITIVE_PATTERNS:
        if re.search(p, low):
            return True
    return False


def _iter_text_files(root: str = "."):
    skip = {".git", "venv", "env", ".venv", "node_modules", ".mypy_cache", ".pytest_cache", "__pycache__", ".ruff_cache"}
    for dirpath, dirnames, filenames in os.walk(root):
        parts = set(dirpath.split(os.sep))
        if parts & skip:
            continue
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if _is_sensitive_path(path):
                continue
            if fn.endswith(('.md', '.py', '.txt', '.rst', '.cfg', '.toml', '.json')):
                yield path


def _chunk_text(text: str, max_size: int = 1200, overlap: int = 200) -> List[str]:
    # Split on sentence boundaries for better snippets
    sents = re.split(r'(?<=[.!?])\\s+', text)
    chunks = []
    cur = ""
    for s in sents:
        if len(cur) + len(s) + 1 <= max_size:
            cur = (cur + " " + s).strip()
        else:
            if cur:
                chunks.append(cur)
            # start new chunk
            cur = s
    if cur:
        chunks.append(cur)
    out = []
    for c in chunks:
        out.append(c)
    return out


def _highlight(snippet: str, query: str) -> str:
    # Naive term highlighting, return HTML-safe string
    safe = html.escape(snippet)
    terms = [t for t in re.split(r"\\s+", query) if t]
    for t in sorted(terms, key=len, reverse=True):
        try:
            pattern = re.compile(re.escape(t), re.IGNORECASE)
            safe = pattern.sub(r"<mark>\\g<0></mark>", safe)
        except Exception:
            continue
    return safe


def build_index(root: str = ".", force: bool = False) -> Tuple[bool, str]:
    """Build a simple file-index. If OPENAI_API_KEY is set, attempt to store embeddings.

    Returns (ok, message).
    """
    files = list(_iter_text_files(root))
    index = []
    for path in files:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        except Exception:
            continue
        chunks = _chunk_text(text)
        for j, c in enumerate(chunks):
            item = {
                'id': hashlib.sha256(f"{path}:{j}".encode()).hexdigest(),
                'path': path.replace('\\', '/'),
                'chunk': c[:4000]
            }
            index.append(item)

    # Try to add embeddings if OpenAI key present
    try:
        import openai
        api_key = os.getenv('OPENAI_API_KEY')
        if api_key:
            openai.api_key = api_key
            # batch embeddings in small groups
            for i in range(0, len(index), 50):
                batch = [it['chunk'] for it in index[i:i+50]]
                resp = openai.Embedding.create(model='text-embedding-3-small', input=batch)
                for k, r in enumerate(resp.data):
                    index[i+k]['embedding'] = r['embedding']
    except Exception:
        # embedding unavailable — proceed without embeddings
        pass

    with open(INDEX_FILE, 'w', encoding='utf-8') as f:
        json.dump(index, f)

    return True, f"Indexed {len(index)} chunks from {len(files)} files"


def _load_index() -> List[Dict]:
    if not os.path.exists(INDEX_FILE):
        return []
    try:
        with open(INDEX_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def _cosine(a: List[float], b: List[float]) -> float:
    sa = sum(x*x for x in a)
    sb = sum(x*x for x in b)
    if sa == 0 or sb == 0:
        return 0.0
    dot = sum(x*y for x, y in zip(a, b))
    return dot / ((sa**0.5) * (sb**0.5))


def query_kb(query: str, top_k: int = 3) -> List[Dict]:
    """Query the KB. If embeddings exist, use semantic similarity; otherwise keyword search."""
    index = _load_index()
    if not index:
        return []

    # Semantic path
    if 'embedding' in index[0]:
        try:
            import openai
            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key:
                raise Exception("OPENAI_API_KEY not set")
            openai.api_key = api_key
            q_emb = openai.Embedding.create(model='text-embedding-3-small', input=[query]).data[0]['embedding']
            scored = []
            for item in index:
                if 'embedding' not in item:
                    continue
                score = _cosine(q_emb, item['embedding'])
                scored.append((score, item))
            scored.sort(key=lambda x: x[0], reverse=True)
            return [{'score': s, 'path': it['path'], 'snippet': it['chunk'], 'html': _highlight(it['chunk'], query)} for s, it in scored[:top_k]]
        except Exception:
            # fall through to keyword
            pass

    # Keyword fallback
    q = [token for token in re.findall(r"[a-z0-9_]+", query.lower()) if len(token) >= 4 and token not in STOPWORDS]
    if not q:
        q = [token for token in re.findall(r"[a-z0-9_]+", query.lower()) if token not in STOPWORDS]
    scored = []
    for item in index:
        text = item['chunk'].lower()
        cnt = sum(text.count(w) for w in q)
        if cnt > 0:
            scored.append((cnt, item))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [{'score': s, 'path': it['path'], 'snippet': it['chunk'], 'html': _highlight(it['chunk'], query)} for s, it in scored[:top_k]]
