"""T9: GUI edge cases in a real browser. No real LLM: a fake OpenAI-compatible server answers "unknown" after a delay.

Runs its own Streamlit server on port 8502 with a config in a temp folder (its own results, logs, trigger cache and
a copy of the OSV cache; OSV itself points at a dead address, so only cached answers work).
Run:  uv run pytest -m gui tests/gui/test_gui_edge.py -s
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from playwright.sync_api import expect

from gui_helpers import ROOT, SHOTS, log, metric_values, wait_idle

pytestmark = pytest.mark.gui
PORT = 8502
BASE = f"http://localhost:{PORT}"
WORKSPACE = ROOT / "workspace"


class FakeLLM(BaseHTTPRequestHandler):
    delay = 2.0

    def log_message(self, *a):
        pass

    def _send(self, body: dict):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send({"object": "list", "data": [{"id": "fake-model", "object": "model"}]})

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        time.sleep(FakeLLM.delay)
        content = json.dumps({"answer": "unknown", "line": None, "reason": "test double",
                              "plain_summary": "A test description.", "trigger_symbols": []})
        self._send({"id": "x", "object": "chat.completion", "created": 0, "model": "fake-model",
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": content}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}})


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def copy_repo(name: str, dst: Path) -> Path:
    shutil.copytree(WORKSPACE / f"tulasinayak__{name}", dst, ignore=shutil.ignore_patterns(".git", ".depscan"))
    return dst


@pytest.fixture(scope="module")
def edge(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("edge")
    llm = ThreadingHTTPServer(("127.0.0.1", free_port()), FakeLLM)
    threading.Thread(target=llm.serve_forever, daemon=True).start()
    for d in ("ws", "results", "logs", "overrides"):
        (tmp / d).mkdir()
    shutil.copy(WORKSPACE / "cache.sqlite", tmp / "ws" / "cache.sqlite")
    shutil.copytree(ROOT / "cache" / "triggers", tmp / "cache" / "triggers")
    cfg = tmp / "config.toml"
    cfg.write_text(f"""
[llm]
default_profile = "local_qwen"
json_mode = true
timeout_seconds = 30
[llm.profiles.local_qwen]
base_url = "http://127.0.0.1:{llm.server_address[1]}/v1"
model = "fake-model"
api_key = "x"
reasoning_effort = ""
max_context_tokens = 8192
[osv]
base_url = "http://127.0.0.1:9"
cache_ttl_hours = 1000000
offline = false
retries = 1
[grounding]
pypi = false
[paths]
workspace = "{(tmp / 'ws').as_posix()}"
results = "{(tmp / 'results').as_posix()}"
logs = "{(tmp / 'logs').as_posix()}"
cache = "{(tmp / 'cache').as_posix()}"
overrides = "{(tmp / 'overrides').as_posix()}"
""", encoding="utf-8")
    env = {**os.environ, "DEPSCAN_CONFIG": str(cfg)}
    proc = subprocess.Popen([sys.executable, "-m", "streamlit", "run", "app.py", "--server.headless", "true",
                             "--server.port", str(PORT), "--browser.gatherUsageStats", "false"], cwd=ROOT, env=env)
    for _ in range(90):
        try:
            if httpx.get(f"{BASE}/_stcore/health", timeout=2).text.strip() == "ok":
                break
        except httpx.HTTPError:
            pass
        time.sleep(1)
    else:
        proc.kill()
        pytest.fail("edge-case GUI server did not start")
    yield {"tmp": tmp, "cfg": cfg}
    proc.terminate()
    llm.shutdown()


@pytest.fixture
def epage(edge, browser):
    SHOTS.mkdir(parents=True, exist_ok=True)
    ctx = browser.new_context(viewport={"width": 1500, "height": 1800})
    page = ctx.new_page()
    page.set_default_timeout(90_000)
    page.goto(BASE)
    page.locator('input[aria-label="Repository"]').wait_for()
    yield page
    ctx.close()


def scan(page, target: str) -> None:
    box = page.locator('input[aria-label="Repository"]')
    box.fill(target)
    box.press("Enter")
    wait_idle(page)
    page.locator(".st-key-check_scan button").click()
    wait_idle(page, timeout=300_000)


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    root.mkdir(parents=True, exist_ok=True)
    return root


# ---------------------------------------------------------------- friendly "nothing found" views

def test_empty_repo_no_manifests_and_no_vulnerabilities(epage, edge):
    tmp = edge["tmp"]
    notice = epage.locator('[data-testid="stAlert"]').filter(has_text="No dependency files were found")
    scan(epage, str(write(tmp / "empty", {})))
    expect(notice).to_be_visible()
    expect(epage.get_by_text("No known vulnerabilities in the pinned dependencies.")).to_be_visible()
    scan(epage, str(write(tmp / "no_manifests", {"app.py": "print('hi')\n"})))
    expect(notice).to_be_visible()
    scan(epage, str(write(tmp / "clean", {"requirements.txt": "flask==3.1.3\n", "app.py": "import flask\n"})))
    expect(epage.get_by_text("No known vulnerabilities in the pinned dependencies.")).to_be_visible()
    expect(epage.get_by_text("Dependencies found (1)")).to_be_visible()
    expect(epage.locator('[data-testid="stDataFrame"]')).to_contain_text("none known")
    epage.screenshot(path=SHOTS / "edge_01_clean_repo.png")


# ---------------------------------------------------------------- failures give a clear message, app stays usable

def test_clone_failure_then_a_normal_scan(epage, edge):
    scan(epage, "https://invalid.invalid/owner/repo")
    expect(epage.locator('[data-testid="stAlert"]').filter(has_text="Could not clone")).to_be_visible()
    epage.screenshot(path=SHOTS / "edge_02_clone_failure.png")
    scan(epage, "file:///etc")
    expect(epage.locator('[data-testid="stAlert"]').filter(has_text="https://")).to_be_visible()
    scan(epage, str(copy_repo("depscan-test-dead-code", edge["tmp"] / "dead1")))
    expect(epage.get_by_text(re.compile(r"\d+ known vulnerabilit"))).to_be_visible()


def test_osv_unreachable_is_reported(epage, edge):
    repo = write(edge["tmp"] / "uncached", {"requirements.txt": "flask==3.1.3\nzzz-depscan-not-cached==0.0.1\n"})
    scan(epage, str(repo))
    expect(epage.get_by_text("Some known-vulnerability lookups failed")).to_be_visible()
    epage.screenshot(path=SHOTS / "edge_03_osv_unreachable.png")


def test_ai_model_not_running(epage, edge):
    epage.locator('[data-testid="stSidebarNav"]').get_by_text("Advanced", exact=True).click()
    url = epage.locator('input[aria-label="Base URL"]')
    url.fill("http://127.0.0.1:9/v1")
    url.press("Enter")
    wait_idle(epage)
    epage.locator('[data-testid="stSidebarNav"]').get_by_text("Check", exact=True).click()
    wait_idle(epage)
    scan(epage, str(copy_repo("depscan-test-dead-code", edge["tmp"] / "dead2")))
    epage.locator(".st-key-check-jinja2__CVE-2025-27516 button").click()
    wait_idle(epage, timeout=180_000)
    expect(epage.get_by_text(re.compile("The AI model could not be reached"))).to_be_visible()
    epage.screenshot(path=SHOTS / "edge_04_ai_unreachable.png")


# ---------------------------------------------------------------- a big result stays usable

def big_result(edge, n_copies: int = 14) -> Path:
    from depscan.config import load_config
    from depscan.orchestrator import Orchestrator
    orch = Orchestrator(load_config(edge["cfg"]))
    result = orch.scan(str(copy_repo("depscan-test-reachability", edge["tmp"] / "reach_big")))
    base = list(result.vulnerabilities)
    for i in range(1, n_copies):
        for dv in base:
            dep = dv.dependency.model_copy(update={"name": f"{dv.dependency.name}-copy{i}"})
            vulns = [v.model_copy(update={"id": f"{v.id}-C{i}"}) for v in dv.vulnerabilities]
            result.vulnerabilities.append(dv.model_copy(update={"dependency": dep, "vulnerabilities": vulns}))
            result.repo.dependencies.append(dep)
    result.repo.repo_name = "big-synthetic"
    orch.save(result)
    return Path(result.result_file)


def test_two_hundred_vulnerabilities_render_and_filter(epage, edge):
    path = big_result(edge)
    total = sum(len(dv["vulnerabilities"]) for dv in json.loads(path.read_text(encoding="utf-8"))["vulnerabilities"])
    assert total >= 200
    epage.locator('[data-testid="stSidebarNav"]').get_by_text("Advanced", exact=True).click()
    wait_idle(epage)
    sidebar = epage.locator('[data-testid="stSidebar"]')
    sidebar.get_by_role("button", name="Load").click()            # the newest result file is preselected
    wait_idle(epage)
    start = time.perf_counter()
    epage.locator('[data-testid="stSidebarNav"]').get_by_text("Check", exact=True).click()
    expect(epage.get_by_text(f"{total} known vulnerabilities")).to_be_visible(timeout=120_000)
    wait_idle(epage, timeout=120_000)
    render = time.perf_counter() - start
    log(f"{total} vulnerabilities rendered in {render:.1f}s")
    (SHOTS.parent / "perf_render.txt").write_text(f"{total} vulnerabilities: {render:.1f}s\n", encoding="utf-8")
    assert render < 60, render
    epage.screenshot(path=SHOTS / "edge_05_two_hundred.png")
    epage.locator('[data-testid="stMain"] [data-testid="stSelectbox"]').first.click()   # the only one: Severity
    epage.get_by_role("option", name="Critical").click()
    wait_idle(epage, timeout=120_000)
    rows = epage.locator('[class*="st-key-open-"]')
    expect(rows).not_to_have_count(total, timeout=120_000)          # wait for the filtered list, not a count mid-rerun
    epage.screenshot(path=SHOTS / "edge_05b_critical_filter.png")
    shown = rows.count()
    log(f"critical filter shows {shown} rows")
    assert 0 < shown < total


# ---------------------------------------------------------------- Check all -> Stop -> Check all; reload mid-check

def stepwise_counts(path: Path) -> list[int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [sum(1 for r in v["verdicts"] if r.get("method") == "stepwise")
            for dv in data["vulnerabilities"] for v in dv["vulnerabilities"]]


def newest_result(edge, name: str) -> Path:
    return max((edge["tmp"] / "results").glob(f"{name}_*.json"), key=lambda p: p.stat().st_mtime)


def test_check_all_stop_and_resume_never_redoes_a_check(epage, edge):
    FakeLLM.delay = 3.0
    scan(epage, str(copy_repo("depscan-test-reachability", edge["tmp"] / "reach_stop")))
    epage.get_by_role("button", name=re.compile(r"^Check all \(")).click()
    expect(epage.get_by_text(re.compile(r"[1-9]\d* of \d+ checked"))).to_be_visible(timeout=300_000)
    epage.get_by_role("button", name="⏹ Stop").last.click()       # during a rerun the old one is still shown
    wait_idle(epage, timeout=300_000)
    first = int(metric_values(epage)["Not checked"])
    log(f"stopped with {first} not checked")
    assert first > 0
    epage.screenshot(path=SHOTS / "edge_06_stopped.png")
    epage.get_by_role("button", name=re.compile(r"^Check all \(")).click()
    expect(epage.get_by_text(re.compile(r"\d+ known vulnerabilities in \d+ packages\. (\d+) checked\."))).to_be_visible()
    for _ in range(600):
        if metric_values(epage).get("Not checked") == "0":
            break
        epage.wait_for_timeout(1000)
    wait_idle(epage, timeout=300_000)
    counts = stepwise_counts(newest_result(edge, "reach_stop"))
    assert counts and all(c == 1 for c in counts), counts        # every advisory checked exactly once
    FakeLLM.delay = 2.0


def test_reload_mid_check_keeps_the_result_file_valid(epage, edge):
    FakeLLM.delay = 3.0
    scan(epage, str(copy_repo("depscan-test-reachability", edge["tmp"] / "reach_reload")))
    epage.get_by_role("button", name=re.compile(r"^Check all \(")).click()
    expect(epage.get_by_text(re.compile(r"[1-9]\d* of \d+ checked"))).to_be_visible(timeout=300_000)
    epage.reload()
    epage.locator('input[aria-label="Repository"]').wait_for()
    time.sleep(8)                                                 # let the check that was running finish
    path = newest_result(edge, "reach_reload")
    counts = stepwise_counts(path)                                # parses: the file is valid JSON
    assert max(counts) <= 1 and sum(counts) >= 1, counts
    assert not list(path.parent.glob("*.tmp")), "no half-written files are left behind"
    FakeLLM.delay = 2.0
