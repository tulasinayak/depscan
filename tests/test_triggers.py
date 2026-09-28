"""Trigger specs: fix-diff URLs and trimming, the cache, human overrides, and generation with a fake LLM/HTTP."""

import json

import httpx

from depscan.cache import ResponseCache
from depscan.config import LLMConfig
from depscan.llm.client import LLMClient
from depscan.models import TriggerSpec, Vulnerability
from depscan.triggers import TriggerStore, diff_url, fix_diff_urls, spec_as_yaml, trim_diff
from fake_llm import FakeOpenAI
from test_cve_matcher import Clock

DIFF = """diff --git a/lib/yaml/constructor.py b/lib/yaml/constructor.py
index 1..2 100644
--- a/lib/yaml/constructor.py
+++ b/lib/yaml/constructor.py
@@ -10,6 +10,9 @@ class FullConstructor(SafeConstructor):
     def construct_python_object_apply(self, suffix, node):
-        instance = self.make_python_instance(suffix, node)
+        if not self.is_safe(suffix):
+            raise ConstructorError("blocked")
+        instance = self.make_python_instance(suffix, node)
diff --git a/tests/lib/test_recursive.py b/tests/lib/test_recursive.py
--- a/tests/lib/test_recursive.py
+++ b/tests/lib/test_recursive.py
@@ -1,2 +1,3 @@
+def test_blocked(): SECRET_TEST_LINE
diff --git a/CHANGES b/CHANGES
--- a/CHANGES
+++ b/CHANGES
@@ -1 +1,2 @@
+5.4: fix CHANGELOG_LINE
"""

SPEC = {"plain_summary": "Loading an attacker's YAML can run code.", "trigger_symbols": ["yaml.full_load"],
        "dangerous_condition": "", "arg_forms": [], "needs_untrusted_input": True, "untrusted_input": "the document",
        "input_arg": "0", "parent_triggers": [], "native_feature": None}


def vuln(**kw) -> Vulnerability:
    base = dict(id="CVE-2020-14343", aliases=["GHSA-8q59-q68h-6hv4"], summary="full_load is unsafe",
                match="affected", match_reason="x", references=[
                    "https://github.com/yaml/pyyaml/issues/420",
                    "https://github.com/yaml/pyyaml/pull/472",
                    "https://github.com/yaml/pyyaml/commit/a001f2782501ad2d24986959f0239a354675f9dc"],
                fix_references=["https://github.com/yaml/pyyaml/commit/a001f2782501ad2d24986959f0239a354675f9dc"])
    return Vulnerability(**{**base, **kw})


def test_diff_urls():
    assert diff_url("https://github.com/o/r/commit/abc1234") == "https://github.com/o/r/commit/abc1234.diff"
    assert diff_url("https://github.com/o/r/pull/12/") == "https://github.com/o/r/pull/12.diff"
    assert diff_url("https://github.com/o/r/pull/12/commits/abcdef1") == "https://github.com/o/r/commit/abcdef1.diff"
    assert diff_url("https://gitlab.com/g/p/-/commit/abcdef1") == "https://gitlab.com/g/p/-/commit/abcdef1.diff"
    assert diff_url("https://github.com/o/r/issues/3") is None and diff_url("https://nvd.nist.gov/x") is None
    urls = fix_diff_urls(vuln())
    assert urls[0][1].endswith("a001f2782501ad2d24986959f0239a354675f9dc.diff")      # commits before pull requests
    assert [u for _, u in urls][-1].endswith("pull/472.diff")


def test_trim_diff_keeps_only_changed_source_lines():
    out = trim_diff(DIFF)
    assert "### lib/yaml/constructor.py" in out and "+        if not self.is_safe(suffix):" in out
    assert "SECRET_TEST_LINE" not in out and "CHANGELOG_LINE" not in out
    assert "index 1..2" not in out and "+++" not in out
    assert len(trim_diff(DIFF * 20, budget=500)) <= 510


def store(tmp_path, transport=None, offline=False) -> TriggerStore:
    http = ResponseCache(tmp_path / "http.sqlite", 3600, Clock())
    return TriggerStore(tmp_path / "cache", tmp_path / "overrides", http, offline=offline, transport=transport)


def test_generate_fetches_the_fix_once_and_caches_the_spec(tmp_path):
    hits = []

    def handler(request: httpx.Request) -> httpx.Response:
        hits.append(str(request.url))
        return httpx.Response(200, text=DIFF)

    fake = FakeOpenAI([json.dumps(SPEC)])
    llm = LLMClient(LLMConfig(), client=fake)
    st = store(tmp_path, httpx.MockTransport(handler))
    spec, generated, problem = st.get(vuln(), "pyyaml", llm)
    assert generated and not problem and spec.source == "llm" and spec.model == "qwen3:8b"
    assert spec.trigger_symbols == ["yaml.full_load"] and spec.diff_used
    prompt = fake.calls[0]["messages"][1]["content"]
    assert "is_safe(suffix)" in prompt and "SECRET_TEST_LINE" not in prompt and "package: pyyaml" in prompt
    assert (tmp_path / "cache" / "triggers" / "CVE-2020-14343__pyyaml.json").exists()

    again, generated, _ = st.get(vuln(), "pyyaml", llm)             # cached: no LLM call, no download
    assert not generated and again.trigger_symbols == spec.trigger_symbols and len(fake.calls) == 1
    assert st.fetch_diff(hits[0]) == DIFF and len(hits) == len(set(hits))


def test_human_override_wins_and_is_marked(tmp_path):
    st = store(tmp_path)
    cached = TriggerSpec(**SPEC, vuln_id="CVE-2020-14343", package="pyyaml")
    (tmp_path / "cache" / "triggers").mkdir(parents=True)
    st.cache_path(vuln(), "pyyaml").write_text(cached.model_dump_json(), encoding="utf-8")
    assert st.get(vuln(), "pyyaml")[0].source == "llm"
    override = spec_as_yaml(cached).replace("yaml.full_load", "yaml.unsafe_load")
    (tmp_path / "overrides" / "triggers").mkdir(parents=True)
    (tmp_path / "overrides" / "triggers" / "GHSA-8q59-q68h-6hv4.yaml").write_text(override, encoding="utf-8")  # by alias
    spec, generated, _ = st.get(vuln(), "pyyaml", llm=object())      # the LLM is never touched
    assert spec.source == "human" and spec.trigger_symbols == ["yaml.unsafe_load"] and not generated
    assert st.get(vuln(), "requests")[0] is None                      # an override for another package is ignored


def test_offline_and_llm_errors_give_no_spec(tmp_path):
    def boom(request):
        raise AssertionError("no network in offline mode")

    fake = FakeOpenAI(["not json", "still not json"])
    st = store(tmp_path, httpx.MockTransport(boom), offline=True)
    spec, generated, problem = st.get(vuln(), "pyyaml", LLMClient(LLMConfig(), client=fake))
    assert spec is None and generated and "valid JSON" in problem
    assert any("offline" in m for m in st.log)
    assert "no fix diff is available" in fake.calls[0]["messages"][1]["content"]
    assert st.get(vuln(), "pyyaml")[0] is None                        # without an LLM: simply no spec yet
