"""The whole pipeline on tests/fixtures/flask_vuln_repo with replayed OSV data and a fake LLM.

The fake model answers from what it is shown, the way a well-behaved model should:
- PyYAML CVE-2017-18342 (yaml.load) with the yaml.load(request.data) route snippet -> likely_affected
- any requests advisory while only requests.get(...) is shown -> likely_not_affected
- anything else -> uncertain
So this tests the plumbing (scan -> context -> analyze -> verdict validation -> saved file), not model quality.
"""

import json
import re

from depscan.config import LLMConfig
from depscan.llm.client import LLMClient
from fake_llm import FakeOpenAI, verdict_json
from test_orchestrator import FIX, make_orch


def fake_model(messages: list[dict]) -> str:
    system, user = messages[0]["content"], messages[1]["content"]
    if "at most 3 short sentences" in system:
        return "A Flask web service that imports YAML sent over HTTP. It also calls an upstream status endpoint."
    advisory = re.search(r"## Advisory (\S+)", user).group(1)
    if advisory == "CVE-2017-18342" and "[app/routes.py:11]" in user:
        return verdict_json("likely_affected", 0.85, evidence=[
            ("yaml.load(request.data) parses the raw request body without a SafeLoader", "app/routes.py:11"),
            ("yaml.load() could execute arbitrary code", "advisory")],
            inference=["Request data reaches the vulnerable yaml.load call"], recommendation="upgrade to 5.1")
    if "## Installed: requests" in user:
        return verdict_json("likely_not_affected", 0.6, evidence=[
            ("Only requests.get(url, timeout=5) to a fixed internal URL", "app/client.py:5")],
            inference=["The vulnerable redirect/session paths are not used"], recommendation="upgrade when convenient")
    return verdict_json()


def test_full_pipeline_with_fake_llm(tmp_path):
    fake = FakeOpenAI(fake_model)
    orch = make_orch(tmp_path, llm=LLMClient(LLMConfig(), log_path=tmp_path / "logs" / "llm_calls.jsonl", client=fake))

    # Step 1
    result = orch.scan(str(FIX / "flask_vuln_repo"))
    names = {dv.dependency.name for dv in result.vulnerabilities}
    assert {"pyyaml", "requests"} <= names
    yaml_usage = result.usages["pyyaml"]
    assert yaml_usage.usage_status == "direct_usage"
    load_site = next(s for s in yaml_usage.sites if s.file == "app/routes.py" and s.symbol == "yaml.load")
    assert "CVE-2017-18342" in load_site.matched_vulns

    # Step 3 without context: the production call is ranked before the tests/ call
    orch.analyze(result, "CVE-2017-18342")
    prompt = fake.calls[-1]["messages"][1]["content"]
    assert prompt.index("[app/routes.py:11]") < prompt.index("[tests/test_yaml_compat.py:5]")
    assert "Background (not evidence)" not in prompt

    # Step 2, then step 3 with context
    orch.build_context(result)
    assert result.repo_context.app_type == "web_service" and result.repo_context.summary
    orch.analyze(result, "CVE-2017-18342", use_context=True)
    prompt = fake.calls[-1]["messages"][1]["content"]
    assert "## Background (not evidence)" in prompt and "context: test" in prompt

    # requests: vulnerable paths unused
    requests_dv = next(dv for dv in result.vulnerabilities if dv.dependency.name == "requests")
    for v in requests_dv.vulnerabilities:
        orch.analyze(result, v.id, dependency="requests")

    saved = orch.load(result.result_file)
    yaml_vuln = saved.find("CVE-2017-18342")[0][1]
    assert [(r.verdict, r.used_repo_context) for r in yaml_vuln.verdicts] == [("likely_affected", False),
                                                                              ("likely_affected", True)]
    assert all(r.evidence[0].citation == "app/routes.py:11" for r in yaml_vuln.verdicts)
    for v in next(dv for dv in saved.vulnerabilities if dv.dependency.name == "requests").vulnerabilities:
        assert v.verdicts[-1].verdict in ("likely_not_affected", "uncertain")
    assert saved.repo_context is not None

    log = [json.loads(line) for line in (tmp_path / "logs" / "llm_calls.jsonl").read_text().splitlines()]
    assert {r["agent"] for r in log} == {"ExploitabilityAgent", "RepoContextAgent"}
