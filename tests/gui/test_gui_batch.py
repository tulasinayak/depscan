"""Batch analysis through the GUI (real local LLM; long): progress, Stop, and resume-after-stop, in both modes.

Run after test_gui_flow (it loads the newest saved result from the sidebar and analyzes whatever is left).
"""

import re
import time

import pytest
from playwright.sync_api import expect

from gui_helpers import open_advanced, LLM_TIMEOUT_MS, ROOT, log, metric_values, shot, wait_idle

pytestmark = pytest.mark.real_llm
PER_ANALYSIS_BUDGET_S = 8 * 60


def batch_button(page):
    return page.get_by_role("button", name=re.compile(r"^Analyze all filtered \(\d+\)$"))


def remaining(page) -> int:
    return int(re.search(r"\((\d+)\)", batch_button(page).inner_text()).group(1))


def progress_text(page) -> str:
    bar = page.locator('[data-testid="stProgress"]')
    return bar.first.inner_text().strip() if bar.count() else ""


def start_batch(page, tag: str) -> int:
    n = remaining(page)
    batch_button(page).click()
    wait_idle(page)
    warning = page.get_by_text(re.compile(r"^Run \d+ analyses .* estimated"))
    expect(warning).to_be_visible()
    log(f"{tag}: {warning.inner_text()}")
    shot(page, f"10_{tag}_confirm", warning)
    page.get_by_role("button", name="Confirm", exact=True).click()
    return n


def wait_progress(page, until, tag: str, budget_s: float) -> None:
    """Poll the progress bar, logging each change, until until() is true."""
    deadline, last = time.time() + budget_s, None
    while not until():
        text = progress_text(page)
        if text and text != last:
            log(f"{tag}: {text}")
            last = text
        assert time.time() < deadline, f"{tag}: no finish within {budget_s:.0f}s (last: {last})"
        page.wait_for_timeout(5000)


def run_pass(page, with_context: bool) -> None:
    tag = "with_context" if with_context else "without_context"
    box = page.locator(".st-key-batch-ctx").get_by_role("checkbox")
    if box.is_checked() != with_context:
        page.locator(".st-key-batch-ctx").get_by_text("use repo context").click()
        wait_idle(page)
    n = start_batch(page, tag)
    assert n > 1

    # progress: wait until the first analysis is saved and the second is running, then Stop
    wait_progress(page, lambda: re.match(r"^[1-9]\d*/\d+", progress_text(page)) is not None, tag,
                  PER_ANALYSIS_BUDGET_S)
    shot(page, f"11_{tag}_progress", page.locator('[data-testid="stProgress"]').first)
    log(f"{tag}: Stop at '{progress_text(page)}'")
    page.get_by_role("button", name="⏹ Stop").click()
    expect(batch_button(page)).to_be_visible(timeout=LLM_TIMEOUT_MS)   # waits for the in-flight analysis
    wait_idle(page, LLM_TIMEOUT_MS)
    left = remaining(page)
    log(f"{tag}: stopped; {n - left} done, {left} left")
    assert 0 < left < n and page.locator('[data-testid="stProgress"]').count() == 0
    assert page.get_by_text(re.compile(rf"{n - left} already analyzed {'with' if with_context else 'without'} context"))\
        .count() == 1
    shot(page, f"12_{tag}_stopped", batch_button(page))

    # resume: only what is left is queued, and it runs to the end
    assert start_batch(page, f"{tag}_resume") == left
    done = page.get_by_text(re.compile(r"^Batch finished"))
    wait_progress(page, lambda: done.count() > 0, f"{tag}_resume", left * PER_ANALYSIS_BUDGET_S)
    wait_idle(page)
    assert remaining_or_zero(page) == 0
    shot(page, f"13_{tag}_finished", done)


def remaining_or_zero(page) -> int:
    return remaining(page) if batch_button(page).count() else 0


def test_gui_batch(page):
    open_advanced(page)                                  # this flow uses the Advanced page
    page.get_by_role("button", name="Load", exact=True).click()
    wait_idle(page)
    expect(page.get_by_text("Vulnerable deps")).to_be_visible(timeout=60_000)
    assert "depscan-test-reachability" in page.locator('[data-testid="stMain"]').inner_text()
    total = int(metric_values(page)["Vulnerabilities"])

    run_pass(page, with_context=False)
    run_pass(page, with_context=True)

    assert metric_values(page)["Analyzed"] == f"{total}/{total}"
    page.get_by_role("tab", name="Evaluation").click()
    wait_idle(page)
    m = metric_values(page)
    log(f"evaluation: {m}")
    assert m["Uncertain without context"].endswith(f"/{total}") and m["Uncertain with context"].endswith(f"/{total}")
    shot(page, "14_evaluation_final", page.get_by_role("tab", name="Evaluation"))
    assert not list((ROOT / "results").glob("*.tmp"))
