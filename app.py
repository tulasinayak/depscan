"""depscan GUI.  Run:  uv run streamlit run app.py

Two pages: Check (which known vulnerabilities affect the repo, checked step by step) and Advanced (everything else).
"""

import streamlit as st

from depscan.ui import state

st.set_page_config(page_title="depscan", page_icon="🛡️", layout="wide")
state.init()
st.navigation([st.Page("ui_pages/check.py", title="Check", icon="🛡️", default=True),
               st.Page("ui_pages/advanced.py", title="Advanced", icon="⚙️")]).run()
