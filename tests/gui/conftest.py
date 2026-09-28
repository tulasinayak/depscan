import pytest

from gui_helpers import SHOTS, browser, page, server  # noqa: F401  (fixtures for the real-browser GUI runs)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """On failure, save a screenshot of the page as it was (tests/gui/screenshots/FAILED_<test>.png)."""
    outcome = yield
    rep = outcome.get_result()
    page = item.funcargs.get("page") if rep.when == "call" and rep.failed else None
    if page is not None:
        page.screenshot(path=SHOTS / f"FAILED_{item.name}.png", full_page=True)
