from pathlib import Path
import re
pattern = re.compile(r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]+')
skip_ext = {
    '.png',
    '.jpg',
    '.jpeg',
    '.gif',
    '.ico',
    '.exe',
    '.dll',
    '.so',
    '.pyc',
    '.zip',
    '.tar',
    '.gz',
    '.docx',
    '.pdf',
    '.pptx',
    '.xlsx'}
skip_dirs = {'venv', '.git'}
updated = []
for p in Path('.').rglob('*'):
    if not p.is_file():
        continue
    if any(part in skip_dirs for part in p.parts):
        continue
    if p.suffix.lower() in skip_ext:
        continue
    try:
        s = p.read_text(encoding='utf-8')
    except Exception:
        try:
            s = p.read_text(encoding='latin-1')
        except Exception:
            continue
    if pattern.search(s):
        new = pattern.sub('', s)
        # cleanup common leftover patterns
        new = re.sub(r"\s+-\s+", ' - ', new)
        new = re.sub(r"\n{3,}", '\n\n', new)
        if new != s:
            p.write_text(new, encoding='utf-8')
            updated.append(str(p))
print('Updated', len(updated), 'files')
for u in updated:
    print(u)
