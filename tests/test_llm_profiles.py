"""LLM provider profiles: key from the environment only, model picked from the models endpoint, rate limits, HTTP 429
handling, response caching, spec-writing profile per variant and the privacy notice. No network: fake clients only."""

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import openai
import pytest
from pydantic import BaseModel

from depscan.cache import ResponseCache
from depscan.config import LLMConfig, load_config
from depscan.errors import LLMUnavailable
from depscan.llm.client import LLMClient, RateLimiter, pick_model, resolve_key
from fake_llm import FakeOpenAI

SECRET = "FAKE-KEY-" + "x7Q2" * 10          # never a real key; the test looks for it everywhere afterwards

CONFIG = """
[llm]
default_profile = "local_qwen"
temperature = 0.1

[llm.profiles.local_qwen]
base_url = "http://localhost:11434/v1"
model = "qwen3:8b"
api_key = "ollama"

[llm.profiles.gemini]
base_url = "https://generativelanguage.googleapis.com/v1beta/openai/"
api_key = ""
api_key_env = "DEPSCAN_TEST_KEY"
model = "auto:flash"
cloud = true
requests_per_minute = 8
cache_responses = true
"""


class Answer(BaseModel):
    answer: str


def config(tmp_path: Path):
    path = tmp_path / "config.toml"
    path.write_text(CONFIG, encoding="utf-8")
    return load_config(path)


# ---------------------------------------------------------------- profiles and the key

def test_profiles_load_and_select(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    assert cfg.llm.profile == "local_qwen" and set(cfg.profiles) == {"local_qwen", "gemini"}
    g = cfg.with_profile("gemini").llm
    assert g.cloud and g.api_key_env == "DEPSCAN_TEST_KEY" and g.api_key == "" and g.temperature == 0.1
    monkeypatch.setenv("DEPSCAN_LLM_PROFILE", "gemini")
    assert config(tmp_path).llm.profile == "gemini"


def test_key_comes_from_the_environment_only(tmp_path, monkeypatch):
    cfg = config(tmp_path).with_profile("gemini").llm
    monkeypatch.delenv("DEPSCAN_TEST_KEY", raising=False)
    with pytest.raises(LLMUnavailable, match="DEPSCAN_TEST_KEY, which is not set"):
        LLMClient(cfg)._call([{"role": "user", "content": "x"}], True, 10)
    monkeypatch.setenv("DEPSCAN_TEST_KEY", SECRET)
    assert resolve_key(cfg) == SECRET
    assert SECRET not in json.dumps(cfg.__dict__)                      # never copied into the config


def test_key_never_reaches_logs_or_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("DEPSCAN_TEST_KEY", SECRET)
    cfg = config(tmp_path).with_profile("gemini").llm
    cache = ResponseCache(tmp_path / "cache.sqlite", 3600)
    fake = FakeOpenAI(lambda m: json.dumps({"answer": "yes"}), models=("models/gemini-2.5-flash",))
    client = LLMClient(cfg, log_path=tmp_path / "logs" / "llm_calls.jsonl", client=fake, response_cache=cache,
                       sleep=lambda s: None)
    client.complete_json("T", "system", "user", Answer)
    cache.close()
    for path in tmp_path.rglob("*"):
        if path.is_file() and path.name != "config.toml":
            assert SECRET.encode() not in path.read_bytes(), path.name


# ---------------------------------------------------------------- model choice

def test_model_is_picked_from_the_models_endpoint(tmp_path):
    ids = ["models/gemini-2.0-flash", "models/gemini-2.5-flash", "models/gemini-2.5-flash-lite",
           "models/gemini-2.5-pro", "models/gemini-3.0-flash-preview", "models/gemini-2.5-flash-image",
           "models/text-embedding-004"]
    assert pick_model(ids, "flash") == "gemini-2.5-flash"
    cfg = config(tmp_path).with_profile("gemini").llm
    fake = FakeOpenAI(lambda m: json.dumps({"answer": "ok"}), models=ids)
    client = LLMClient(cfg, client=fake, sleep=lambda s: None)
    client.complete_json("T", "s", "u", Answer)
    assert client.model == "gemini-2.5-flash" and fake.calls[0]["model"] == "gemini-2.5-flash"
    assert fake.calls[0]["reasoning_effort"] == "none"                  # thinking off


# ---------------------------------------------------------------- rate limits and 429

def test_rate_limiter_waits_for_the_window():
    now = [0.0]
    slept = []
    lim = RateLimiter(rpm=2, tpm=1000, clock=lambda: now[0], sleep=lambda s: (slept.append(s), now.__setitem__(0, now[0] + s)))
    assert lim.wait(100) == 0 and lim.wait(100) == 0
    msgs = []
    assert lim.wait(100, msgs.append) > 59 and msgs[0].startswith("waiting for rate limit")
    now[0] += 61
    lim.events.clear()
    assert lim.wait(900) == 0 and lim.wait(200) > 0                    # tokens per minute


def rate_limited(retry_after: str | None) -> openai.RateLimitError:
    headers = {"retry-after": retry_after} if retry_after else {}
    resp = httpx.Response(429, headers=headers, request=httpx.Request("POST", "https://x"))
    return openai.RateLimitError("slow down", response=resp, body=None)


class Flaky(FakeOpenAI):
    def __init__(self, errors, **kw):
        super().__init__(lambda m: json.dumps({"answer": "ok"}), **kw)
        real = self.chat.completions.create
        self.errors = list(errors)

        def create(**kwargs):
            if self.errors:
                raise self.errors.pop(0)
            return real(**kwargs)
        self.chat.completions.create = create


def test_429_respects_retry_after_then_backs_off(tmp_path):
    slept = []
    cfg = LLMConfig(profile="t", max_retries_429=3)
    client = LLMClient(cfg, client=Flaky([rate_limited("7"), rate_limited(None), rate_limited(None)]),
                       sleep=slept.append)
    parsed, _ = client.complete_json("T", "s", "u", Answer)
    assert parsed.answer == "ok" and slept == [7.0, 4.0, 8.0]
    stuck = LLMClient(LLMConfig(profile="t", max_retries_429=1), client=Flaky([rate_limited(None)] * 5),
                      sleep=lambda s: None)
    with pytest.raises(LLMUnavailable, match="still rate-limiting after 1 retries"):
        stuck.complete_json("T", "s", "u", Answer)


# ---------------------------------------------------------------- response cache

def test_identical_requests_are_replayed_from_the_cache(tmp_path):
    cache = ResponseCache(tmp_path / "c.sqlite", 3600)
    cfg = LLMConfig(profile="gemini", model="gemini-2.5-flash", cache_responses=True)
    fake = FakeOpenAI(lambda m: json.dumps({"answer": "first"}))
    a = LLMClient(cfg, client=fake, response_cache=cache)
    assert a.complete_json("T", "s", "u", Answer)[0].answer == "first"
    b = LLMClient(cfg, client=FakeOpenAI(lambda m: json.dumps({"answer": "second"})), response_cache=cache)
    assert b.complete_json("T", "s", "u", Answer)[0].answer == "first"         # no call, no quota
    c = LLMClient(LLMConfig(profile="other", model="gemini-2.5-flash", cache_responses=True),
                  client=FakeOpenAI(lambda m: json.dumps({"answer": "third"})), response_cache=cache)
    assert c.complete_json("T", "s", "u", Answer)[0].answer == "third"         # keyed by profile too
    off = LLMClient(LLMConfig(profile="gemini", model="gemini-2.5-flash"), client=FakeOpenAI(
        lambda m: json.dumps({"answer": "live"})), response_cache=cache)
    assert off.complete_json("T", "s", "u", Answer)[0].answer == "live"        # caching is per profile setting


# ---------------------------------------------------------------- spec variants and the privacy notice

def test_gemini_variant_writes_specs_with_the_gemini_profile(tmp_path, monkeypatch):
    from test_orchestrator import make_orch
    monkeypatch.setenv("DEPSCAN_TEST_KEY", SECRET)
    orch = make_orch(tmp_path)
    orch.cfg.profiles = config(tmp_path).profiles
    assert orch.triggers("gemini").spec_llm.cfg.profile == "gemini"
    assert orch.triggers("gemini+facts").spec_llm.cfg.profile == "gemini"
    assert orch.triggers("llm").spec_llm is None and orch.triggers("llm+facts").spec_llm is None
    assert orch.triggers("gemini").cache_dir.name == "triggers__gemini"


def test_cli_privacy_notice_only_when_cloud_gets_repo_code(tmp_path, capsys):
    from depscan import cli
    cfg = config(tmp_path)
    for profile, cmd, shown in [("gemini", "analyze", True), ("gemini", "evaluate", False),
                                ("local_qwen", "analyze", False)]:
        orch = SimpleNamespace(cfg=cfg.with_profile(profile))
        cli.privacy_notice(argparse.Namespace(cmd=cmd, no_llm=False), orch)
        out = capsys.readouterr().out
        assert ("Don't use this for private code" in out) == shown, (profile, cmd)


def test_gui_cloud_profile_needs_confirmation(tmp_path):
    from streamlit.testing.v1 import AppTest
    from depscan.ui import state
    if not state.BASE_CFG.profiles.get("gemini"):
        pytest.skip("no gemini profile in config.toml")
    at = AppTest.from_file(str(Path(__file__).parent.parent / "ui_pages" / "advanced.py"), default_timeout=60)
    at.session_state["llm_profile"] = "gemini"
    at.run()
    assert any("Don't use this for private code" in w.value for w in at.warning)
    assert at.session_state["_orch_key"][0] == "local_qwen"                     # not used before confirming
    next(b for b in at.button if b.key == "cloud_confirm").click().run()
    assert at.session_state["cloud_ok"] and at.session_state["_orch_key"][0] == "gemini"


def test_overloaded_provider_is_retried(tmp_path):
    slept = []
    busy = openai.InternalServerError("high demand", response=httpx.Response(
        503, request=httpx.Request("POST", "https://x")), body=None)
    client = LLMClient(LLMConfig(profile="t", max_retries_429=3), client=Flaky([busy, busy]), sleep=slept.append)
    assert client.complete_json("T", "s", "u", Answer)[0].answer == "ok" and slept == [2.0, 4.0]
