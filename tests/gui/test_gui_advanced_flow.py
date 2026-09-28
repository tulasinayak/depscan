"""The Advanced page flow in a real browser, the way a user clicks through it (real local LLM; slow).

  scan the test repo -> check overview/chart/table -> open every dependency -> generate repo context
  -> analyze one reachable and one imported-but-unused CVE, without and with context
  -> Evaluation tab -> downloads.   Screenshots go to tests/gui/screenshots/.
"""

import csv
import io
import json
import re

import pytest
import yaml
from playwright.sync_api import expect

from gui_helpers import (open_advanced, DOWNLOADS, LLM_TIMEOUT_MS, REPO_URL, ROOT, dependency_table, log, main_text, metric_values,
                      open_expander, select_dependency, shot, vuln_expander, wait_idle)

pytestmark = [pytest.mark.gui, pytest.mark.llm]

EXPECTED_USAGE = {"idna": "used directly", "jinja2": "used directly", "pygments": "used directly",
                  "pyyaml": "used directly", "requests": "used directly", "rsa": "not imported directly",
                  "tqdm": "used directly"}
ANALYZE = [("pyyaml", "CVE-2020-14343", "likely_affected"),        # reachable with untrusted input
           ("jinja2", "CVE-2024-22195", "likely_not_affected")]    # imported, vulnerable feature unused


def expected_labels() -> list[dict]:
    clone = ROOT / "workspace" / "tulasinayak__depscan-test-reachability" / ".depscan" / "expected.yaml"
    return yaml.safe_load(clone.read_text(encoding="utf-8"))


def analyze(page, dep, vid, with_context):
    exp = vuln_expander(page, dep, vid)
    open_expander(exp)
    box = exp.get_by_role("checkbox", name="use repo context")
    if box.is_checked() != with_context:
        exp.get_by_text("use repo context", exact=True).click()
        wait_idle(page)
    mode = "with context" if with_context else "without context"
    log(f"analyze {vid} ({dep}) {mode}")
    exp.get_by_role("button", name="Analyze exploitability").click()
    expect(exp.get_by_text(mode, exact=True)).to_be_visible(timeout=LLM_TIMEOUT_MS)
    wait_idle(page, LLM_TIMEOUT_MS)
    return exp


def test_gui_advanced_flow(page):
    open_advanced(page)                                  # this flow uses the Advanced page
    # 1 · scan by URL ---------------------------------------------------------------------------------------
    url = page.locator('input[aria-label="GitHub URL or local path"]')
    url.fill(REPO_URL)
    url.press("Enter")
    wait_idle(page)
    page.get_by_role("button", name="Scan", exact=True).click()
    expect(page.get_by_text(re.compile(r"Scan complete in"))).to_be_visible(timeout=300_000)
    wait_idle(page)
    shot(page, "01_scan_done")

    # 2 · overview tiles, chart, table ----------------------------------------------------------------------
    labels = expected_labels()
    m = metric_values(page)
    assert m["Dependencies"] == "9", m                  # 7 runtime pins + pytest + tqdm (dev)
    assert m["Vulnerable deps"] == "7", m
    assert m["Vulnerabilities"] == str(len(labels)), m  # every advisory OSV returns is labelled
    assert m["Analyzed"] == f"0/{len(labels)}", m
    assert int(m["Critical"]) + int(m["High"]) + int(m["Medium"]) + int(m["Low"]) == len(labels)
    chart = page.locator('[data-testid="stVegaLiteChart"]').first
    expect(chart).to_be_visible()
    rows = {r["Dependency"]: r for r in dependency_table(page)}
    assert set(rows) == set(EXPECTED_USAGE), rows
    for name, usage in EXPECTED_USAGE.items():
        assert rows[name]["Usage"].startswith(usage), (name, rows[name]["Usage"])
    assert rows["tqdm"]["Scope"] == "dev" and rows["pyyaml"]["Scope"] == "main"
    shot(page, "02_overview_chart_table", chart)

    # 3 · every dependency's detail view --------------------------------------------------------------------
    for name in EXPECTED_USAGE:
        select_dependency(page, name)
        heading = page.locator("h3").filter(has_text=re.compile(rf"^{name} "))
        text = main_text(page)
        if name == "rsa":
            assert "not imported directly" in text and "does NOT mean" in text
        else:
            sites = page.locator('[data-testid="stExpander"]').filter(has_text="Usage sites (")
            open_expander(sites.first)
            text = main_text(page)
            assert re.search(r"\b[\w/]+\.py:\d+\b", text), name                    # file:line of a usage site
            assert sites.first.locator('[data-testid="stCode"]').count() >= 1, name  # snippet
        if name == "pygments":
            assert "tests/test_docs.py:12" in text and "🧪 test" in text
        if name == "tqdm":
            assert "scope: dev" in text and "🛠️ script" in text
        shot(page, f"03_detail_{name}", heading)

    # 4 · repo context --------------------------------------------------------------------------------------
    log("generate repo context")
    page.get_by_role("button", name="Generate repo context").click()
    card = page.locator('[data-testid="stVerticalBlock"]').filter(has_text="background only, never used as evidence").last
    expect(card).to_be_visible(timeout=LLM_TIMEOUT_MS)
    wait_idle(page, LLM_TIMEOUT_MS)
    ctx_text = card.inner_text()
    assert "web_service" in ctx_text and "flask" in ctx_text.lower() and "request.data" in ctx_text
    shot(page, "04_repo_context", card)

    # 5 · analyze two CVEs, without then with context -------------------------------------------------------
    for i, (dep, vid, expected) in enumerate(ANALYZE):
        select_dependency(page, dep)
        analyze(page, dep, vid, with_context=False)
        exp = analyze(page, dep, vid, with_context=True)
        for title in ("Evidence", "Inference", "Unknowns"):
            assert exp.locator("strong", has_text=title).count() == 2, title
        badges = exp.get_by_text(re.compile(r"^[✓✗] expected: "))
        assert badges.count() == 2
        assert all(expected.replace("_", " ") in b for b in badges.all_inner_texts())
        a = exp.get_by_text("without context", exact=True).bounding_box()
        b = exp.get_by_text("with context", exact=True).bounding_box()
        assert abs(a["y"] - b["y"]) < 30 and b["x"] > a["x"] + 200             # side by side
        log(f"{vid}: " + " | ".join(badges.all_inner_texts()))
        shot(page, f"05_verdicts_{i + 1}_{dep}", exp)

    # 6 · evaluation tab ------------------------------------------------------------------------------------
    page.get_by_role("tab", name="Evaluation").click()
    wait_idle(page)
    m = metric_values(page)
    assert "Accuracy without context" in m and "Accuracy with context" in m
    expect(page.get_by_text(re.compile(r"Confusion matrix · without context"))).to_be_visible()
    shot(page, "06_evaluation_tab", page.get_by_role("tab", name="Evaluation"))
    page.get_by_role("tab", name="Analysis").click()
    wait_idle(page)

    # 7 · downloads -----------------------------------------------------------------------------------------
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    saved = {}
    for label in ("Result JSON", "CSV (deps × vulns × verdict)", "Markdown report"):
        with page.expect_download() as d:
            page.get_by_role("button", name=label, exact=True).click()
        path = DOWNLOADS / d.value.suggested_filename
        d.value.save_as(path)
        saved[label] = path.read_text(encoding="utf-8")
    result = json.loads(saved["Result JSON"])
    analyzed = [v for dv in result["vulnerabilities"] for v in dv["vulnerabilities"] if v["verdicts"]]
    assert len(analyzed) == 2 and all(len(v["verdicts"]) >= 2 for v in analyzed)
    assert result["repo_context"]["app_type"] == "web_service"
    rows = list(csv.DictReader(io.StringIO(saved["CSV (deps × vulns × verdict)"])))
    assert len(rows) == len(labels)
    assert "# depscan report: depscan-test-reachability" in saved["Markdown report"]
    assert ".depscan" not in saved["Result JSON"]
    shot(page, "07_downloads_done", page.get_by_role("button", name="Markdown report", exact=True))
