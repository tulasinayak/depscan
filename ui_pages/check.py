"""Check page (the main page): which of the known vulnerabilities actually affect the scanned repository."""

from depscan.ui import state
from depscan.ui.check_page import page

state.init()
page(state.orchestrator)
