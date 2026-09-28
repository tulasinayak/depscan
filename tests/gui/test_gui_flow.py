"""The Check page (main page) in a real browser, the way a user clicks through it (real local LLM; slow).

  dead-code repo: scan -> list + counters -> check a not-affected CVE (the code decides) and open a checklist row
  -> check the feature-flag CVE (needs review) -> Check all for the rest
  reachability repo: scan -> check the PyYAML CVE that is affected -> upgrade command
  -> Advanced page with the same result.   Screenshots go to tests/gui/screenshots/check_*.png.
"""

import re

import pytest
from playwright.sync_api import expect

from gui_helpers import (LLM_TIMEOUT_MS, ROW_HEIGHT, dependency_table, log, main_text, metric_values,
                         open_expander, shot, wait_idle)

pytestmark = [pytest.mark.gui, pytest.mark.llm]

DEAD_CODE = "https://github.com/tulasinayak/depscan-test-dead-code"
REACHABILITY = "https://github.com/tulasinayak/depscan-test-reachability"
USED = "How it's used"
STATUSES = ["Affected", "Probably not affected", "Not affected", "Needs review", "Not checked"]
INTERNAL_TERMS = ["usage_status", "bundled_native", "indirect_sites", "no_direct_usage", "direct_usage", "fuzz_crash",
                  "version_in_range", "trigger_spec", "dangerous_form", "attacker_input", "likely_affected",
                  "likely_not_affected", "needs_review", "probably_not_affected", "not_checked"]


def row_key(dep: str, vid: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", f"{dep}__{vid}")


def scan(page, url: str) -> None:
    box = page.locator('input[aria-label="Repository"]')
    box.fill(url)
    box.press("Enter")
    wait_idle(page)
    page.locator(".st-key-check_scan button").click()
    wait_idle(page, timeout=300_000)
    expect(page.locator('[data-testid="stMetric"]').first).to_be_visible()


def check(page, dep: str, vid: str):
    """Click the row's Check button and wait for the check to finish; returns the detail panel."""
    log(f"checking {vid} ({dep})")
    page.locator(f".st-key-check-{row_key(dep, vid)} button").click()
    wait_idle(page, timeout=LLM_TIMEOUT_MS)
    detail = page.locator(".st-key-cve_detail")
    expect(detail).to_be_visible()
    expect(detail).to_contain_text(vid)
    return detail


def click_package(page, index: int) -> None:
    """Select a row of the dependency table by clicking its selection marker, like a user."""
    grid = page.locator('[data-testid="stDataFrame"]').first
    grid.scroll_into_view_if_needed()
    box = grid.bounding_box()
    page.mouse.click(box["x"] + 18, box["y"] + ROW_HEIGHT + index * ROW_HEIGHT + ROW_HEIGHT / 2)
    wait_idle(page)


def no_internal_terms(page) -> None:
    text = main_text(page)
    found = [t for t in INTERNAL_TERMS if t in text]
    assert not found, f"internal terms on the main page: {found}"


def test_check_page_flow(page):
    # 1. scan the dead-code repo: one list of CVEs, the summary sentence and the five counters
    scan(page, DEAD_CODE)
    counters = metric_values(page)
    log(f"counters: {counters}")
    assert list(counters) == STATUSES
    assert counters["Not checked"] == "5" and all(counters[s] == "0" for s in STATUSES[:-1])
    expect(page.get_by_text("5 known vulnerabilities in 5 packages. 0 checked.")).to_be_visible()
    for vid in ("CVE-2020-14343", "CVE-2026-45409", "CVE-2020-25658", "CVE-2024-5569", "CVE-2025-27516"):
        expect(page.get_by_role("button", name=vid, exact=True)).to_be_visible()
    expect(page.get_by_role("button", name=re.compile(r"^Check all \(5\)"))).to_be_visible()
    expect(page.get_by_text(re.compile(r"About .* for 5 unchecked"))).to_be_visible()
    no_internal_terms(page)
    shot(page, "check_01_scanned")

    # 1b. dependencies found: every dependency, clean ones say "none known"; clicking one filters the list
    label = page.locator('[data-testid="stExpander"] summary').filter(has_text="Dependencies found").inner_text()
    n = int(re.search(r"Dependencies found \((\d+)\)", label).group(1))
    deps = dependency_table(page)
    log(f"dependencies found: {n}: {[(d['Package'], d[USED], d['Known vulnerabilities']) for d in deps]}")
    assert len(deps) == n and n > 5
    assert [d for d in deps if d["Known vulnerabilities"] == "none known"], "a clean package shows none known"
    assert all(d["Known vulnerabilities"] != "none known" for d in deps[:5])               # vulnerable ones first
    assert not [t for t in INTERNAL_TERMS if t in str(deps)]
    shot(page, "check_00_dependencies", page.locator('[data-testid="stDataFrame"]').first)
    click_package(page, [d["Package"] for d in deps].index("zipp"))
    expect(page.get_by_text("Showing only")).to_contain_text("zipp")
    visible = [vid for vid in ("CVE-2020-14343", "CVE-2026-45409", "CVE-2020-25658", "CVE-2024-5569", "CVE-2025-27516")
               if page.get_by_role("button", name=vid, exact=True).count()]
    assert visible == ["CVE-2024-5569"], visible
    shot(page, "check_00b_package_filter")
    page.get_by_role("button", name="Show all", exact=True).click()
    wait_idle(page)
    expect(page.get_by_role("button", name="CVE-2020-14343", exact=True)).to_be_visible()

    # 2. a not-affected CVE, decided by code: the verdict, the reason and the checklist
    detail = check(page, "idna", "CVE-2026-45409")
    expect(detail).to_contain_text("Not affected")
    expect(detail).to_contain_text("old_domains.py")
    expect(detail).to_contain_text("What this vulnerability is")
    expect(detail).to_contain_text("No action needed")
    expect(detail.get_by_text(re.compile(r"^Checked by code only · no AI calls"))).to_be_visible()
    row = detail.locator('[data-testid="stExpander"]').filter(has_text="That code can actually run")
    expect(row).to_contain_text("✗")
    open_expander(row)
    expect(row).to_contain_text("decided by code")
    expect(row).to_contain_text("never imported")
    used = detail.locator('[data-testid="stExpander"]').filter(has_text="Your code uses the vulnerable part")
    open_expander(used)
    expect(used.locator('[data-testid="stCode"]').first).to_contain_text("idna.encode")   # evidence with its code
    assert metric_values(page)["Not affected"] == "1"
    no_internal_terms(page)
    shot(page, "check_02_not_affected")

    # 3. the feature-flag CVE: the code can't rule it out, so it needs review
    detail = check(page, "jinja2", "CVE-2025-27516")
    expect(detail).to_contain_text("Needs review")
    expect(detail.locator('[data-testid="stExpander"]').filter(has_text="?").first).to_be_visible()
    shot(page, "check_03_needs_review")

    # 4. Check all: the remaining three, with progress; then hide checked
    page.get_by_role("button", name=re.compile(r"^Check all \(3\)")).click()
    expect(page.get_by_text(re.compile(r"of 3 checked · now checking"))).to_be_visible()
    shot(page, "check_04a_check_all_running")
    expect(page.get_by_text("5 known vulnerabilities in 5 packages. 5 checked.")).to_be_visible(timeout=LLM_TIMEOUT_MS)
    wait_idle(page, timeout=LLM_TIMEOUT_MS)
    counters = metric_values(page)
    log(f"counters after Check all: {counters}")
    assert counters["Not checked"] == "0" and counters["Not affected"] == "4" and counters["Needs review"] == "1"
    expect(page.get_by_text("5 known vulnerabilities in 5 packages. 5 checked.")).to_be_visible()
    page.get_by_text("Hide checked", exact=True).click()
    wait_idle(page)
    expect(page.get_by_text("Nothing matches these filters.")).to_be_visible()
    shot(page, "check_04_all_checked")
    page.get_by_text("Hide checked", exact=True).click()
    wait_idle(page)

    # 5. an affected CVE in the reachability repo, with the upgrade command
    scan(page, REACHABILITY)
    detail = check(page, "pyyaml", "CVE-2020-14343")
    expect(detail).to_contain_text("Affected")
    expect(detail).to_contain_text("What to do")
    expect(detail.locator('[data-testid="stCode"]').filter(has_text='uv add "pyyaml>=')).to_be_visible()
    expect(detail.locator('[data-testid="stCode"]').filter(has_text='pip install --upgrade "pyyaml>=')).to_be_visible()
    marks = detail.locator('[data-testid="stExpander"] summary').all_inner_texts()
    log(f"checklist: {marks}")
    assert sum(m.splitlines()[-1].strip().startswith("✓") for m in marks) == 6   # the last line, after the icon name
    no_internal_terms(page)
    shot(page, "check_05_affected")

    # 6. the Advanced page keeps everything else, on the same result
    page.locator('[data-testid="stSidebarNav"]').get_by_text("Advanced", exact=True).click()
    page.locator('input[aria-label="GitHub URL or local path"]').wait_for()
    wait_idle(page)
    expect(page.get_by_role("heading", name="depscan · Advanced")).to_be_visible()
    expect(page.locator('[data-testid="stDataFrame"]').first).to_be_visible()   # the dependency table
    assert "depscan-test-reachability" in main_text(page)
    shot(page, "check_06_advanced")
