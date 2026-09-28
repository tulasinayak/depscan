"""Test categories (markers). `uv run pytest` runs only `fast`; see README "Tests" for the others.

A test without a category marker is `fast`: offline, no LLM, well under a second. Everything else says what it needs.
"""

import pytest

CATEGORIES = {"slow", "network", "llm", "gui", "realworld"}


def pytest_collection_modifyitems(config, items):
    for item in items:
        if not CATEGORIES & {m.name for m in item.iter_markers()}:
            item.add_marker(pytest.mark.fast)
