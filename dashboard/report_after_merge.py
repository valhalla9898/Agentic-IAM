import streamlit as st
from pathlib import Path

st.set_page_config(page_title="Report After Merge", layout="wide")

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

content = ""
if README.exists():
    text = README.read_text(encoding="utf-8")
    marker = "## Report After Merge"
    if marker in text:
        idx = text.index(marker)
        # take from marker to next top-level header (## ) or end
        rest = text[idx:]
        # find next '## ' after the first line
        parts = rest.split('\n## ', 1)
        if len(parts) > 1:
            section = parts[0]
        else:
            section = rest
        content = section
    else:
        content = "## Report After Merge section not found in README.md"
else:
    content = "README.md not found"

st.title("Report After Merge")
st.markdown(content)

st.sidebar.header("Actions")
st.sidebar.markdown("- File: README.md\n- Viewer: dashboard/report_after_merge.py")

st.caption("This viewer displays the 'Report After Merge' section from README.md.")
