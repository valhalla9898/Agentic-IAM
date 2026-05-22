import re
from pathlib import Path

pattern = re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]+")
skip_ext = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".exe",
    ".dll",
    ".so",
    ".pyc",
    ".zip",
    ".tar",
    ".gz",
    ".docx",
    ".pdf",
    ".pptx",
    ".xlsx",
}
files_with_arabic = []
for p in Path(".").rglob("*"):
    if not p.is_file():
        continue
    if p.suffix.lower() in skip_ext:
        continue
    try:
        s = p.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        try:
            s = p.read_text(encoding="latin-1")
        except (UnicodeDecodeError, OSError):
            continue
    if pattern.search(s):
        files_with_arabic.append(str(p))

print("FOUND", len(files_with_arabic), "files with Arabic characters")

count = 0
for fp in files_with_arabic:
    p = Path(fp)
    s = p.read_text(encoding="utf-8")
    # remove Arabic blocks but keep surrounding English
    new = pattern.sub("", s)
    # clean repeated spaces
    new = re.sub(r"[ \t]{2,}", " ", new)
    new = re.sub(r"\n{3,}", "\n\n", new)
    # if file mostly empty after removal, add English placeholder
    if len(re.sub(r"\s", "", new)) < 30:
        placeholder = f"# {p.name} — Placeholder (converted to English)\n\nThis file previously contained Arabic-only content and was converted to an English placeholder by an automated script. Please review and replace with the appropriate English content.\n"
        new = placeholder
    if new != s:
        p.write_text(new, encoding="utf-8")
        print("updated", p)
        count += 1
print("DONE files updated:", count)
