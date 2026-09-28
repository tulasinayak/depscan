"""Shared helpers for the real-browser GUI runs (Playwright + a running `streamlit run app.py`).

These tests use the real local model and take many minutes, so they are marked `gui` and `llm` and excluded from
the normal suite. Run them with:  uv run pytest -m gui tests/gui -s
They reuse a GUI already running on http://localhost:8501, or start one for the session.
"""

import os
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from playwright.sync_api import Page, expect, sync_playwright

ROOT = Path(__file__).parent.parent.parent
BASE = os.environ.get("DEPSCAN_GUI_URL", "http://localhost:8501")
REPO_URL = "https://github.com/tulasinayak/depscan-test-reachability"
SHOTS = Path(__file__).parent / "screenshots"
DOWNLOADS = Path(__file__).parent / "downloads"
LLM_TIMEOUT_MS = 20 * 60 * 1000            # one CPU analysis can take several minutes
ROW_HEIGHT = 35                            # st.dataframe default row (and header) height in px


def log(msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"      # Windows consoles/pipes: cp1252
    print(line.encode(enc, errors="replace").decode(enc), flush=True)


def _healthy() -> bool:
    try:
        return httpx.get(f"{BASE}/_stcore/health", timeout=2).text.strip() == "ok"
    except httpx.HTTPError:
        return False


@pytest.fixture(scope="session")
def server():
    proc = None
    if not _healthy():
        port = BASE.rsplit(":", 1)[-1]
        proc = subprocess.Popen([sys.executable, "-m", "streamlit", "run", "app.py", "--server.headless", "true",
                                 "--server.port", port, "--browser.gatherUsageStats", "false"], cwd=ROOT)
        for _ in range(60):
            if _healthy():
                break
            time.sleep(1)
        else:
            proc.kill()
            pytest.fail(f"streamlit did not start on {BASE}")
    yield BASE
    if proc:
        proc.terminate()


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture
def page(server, browser) -> Page:
    SHOTS.mkdir(parents=True, exist_ok=True)
    context = browser.new_context(viewport={"width": 1500, "height": 1800}, accept_downloads=True)
    page = context.new_page()
    page.set_default_timeout(90_000)
    page.goto(server)
    page.locator('input[aria-label="Repository"]').wait_for()          # the Check page (default page)
    yield page
    context.close()


# ---------------------------------------------------------------- helpers

def open_advanced(page: Page) -> None:
    """Go to the Advanced page (the former single page) through the sidebar navigation, like a user."""
    page.locator('[data-testid="stSidebarNav"]').get_by_text("Advanced", exact=True).click()
    page.locator('input[aria-label="GitHub URL or local path"]').wait_for()
    wait_idle(page)


def wait_idle(page: Page, timeout: int = 120_000) -> None:
    """Wait until the Streamlit script run triggered by the last interaction has finished."""
    page.wait_for_timeout(400)
    page.locator('[data-testid="stStatusWidget"]').wait_for(state="hidden", timeout=timeout)
    # elements from the previous run stay (marked stale) until the new run has replaced or removed them
    page.wait_for_function("() => !document.querySelector('[data-stale=\"true\"]')", timeout=timeout)
    page.wait_for_timeout(300)


def shot(page: Page, name: str, target=None) -> Path:
    if target is not None:
        target.scroll_into_view_if_needed()
    path = SHOTS / f"{name}.png"
    page.screenshot(path=path)
    log(f"screenshot {path.name}")
    return path


def main_text(page: Page) -> str:
    return page.locator('[data-testid="stMain"]').inner_text()


def metric_values(page: Page) -> dict[str, str]:
    out = {}
    for m in page.locator('[data-testid="stMetric"]').all():
        label = m.locator('[data-testid="stMetricLabel"]').inner_text().strip()
        out[label] = m.locator('[data-testid="stMetricValue"]').inner_text().strip()
    return out


def dependency_table(page: Page) -> list[dict[str, str]]:
    """Rows of the dependency table, read from the grid's accessible table (the grid itself is a canvas)."""
    grid = page.locator('[data-testid="stDataFrame"]').first
    headers = [h.strip() for h in grid.locator("thead th").all_inner_texts() if h.strip()]
    cells = grid.locator("tbody td").all_inner_texts()
    n = len(headers)
    return [dict(zip(headers, cells[i:i + n])) for i in range(0, len(cells), n)] if n else []


def select_dependency(page: Page, name: str) -> None:
    """Click the dependency's row in the table (single-row selection), like a user would."""
    grid = page.locator('[data-testid="stDataFrame"]').first
    grid.scroll_into_view_if_needed()
    names = [r["Dependency"] for r in dependency_table(page)]
    box = grid.bounding_box()
    y = box["y"] + ROW_HEIGHT + names.index(name) * ROW_HEIGHT + ROW_HEIGHT / 2
    page.mouse.click(box["x"] + 18, y)                      # the row-selection marker column
    wait_idle(page)
    expect(page.locator("h3").filter(has_text=re.compile(rf"^{re.escape(name)} "))).to_be_visible()


def open_expander(expander) -> None:
    details = expander.locator("details").first
    if details.get_attribute("open") is None:
        expander.locator("summary").first.click()
        expander.page.wait_for_timeout(500)
        wait_idle(expander.page)


def vuln_expander(page: Page, dep: str, vuln_id: str):
    return page.locator(f".st-key-vx-{dep}-{vuln_id}")
