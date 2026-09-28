"""The known answers in <repo>/.depscan/ must never reach an agent, a result file or an LLM prompt."""

import json
import shutil

from depscan.config import LLMConfig
from depscan.llm.client import LLMClient
from fake_llm import FakeOpenAI
from test_end_to_end import fake_model
from test_orchestrator import FIX, make_orch

EXPECTED = """\
- id: CVE-2017-18342
  package: pyyaml
  expected: likely_affected
  scenario: canary_scenario_q7x
  reason: "canary-reason-9f3k the answer is affected"
  key_location: app/routes.py:11
"""


def test_depscan_dir_never_reaches_agents_or_prompts(tmp_path):
    repo = tmp_path / "flask_vuln_repo"
    shutil.copytree(FIX / "flask_vuln_repo", repo)
    hidden = repo / ".depscan"
    hidden.mkdir()
    (hidden / "expected.yaml").write_text(EXPECTED, encoding="utf-8")
    (hidden / "README.md").write_text("canary-readme-2b8d: CVE-2017-18342 is reachable\n", encoding="utf-8")
    (hidden / "requirements.txt").write_text("canarypkg==1.0\n", encoding="utf-8")
    (hidden / "answers.py").write_text("import yaml\nyaml.load('canary-code-5m1z')\n", encoding="utf-8")

    log = tmp_path / "logs" / "llm_calls.jsonl"
    fake = FakeOpenAI(fake_model)
    orch = make_orch(tmp_path, llm=LLMClient(LLMConfig(), log_path=log, client=fake))
    result = orch.scan(str(repo))
    assert not any(f.startswith(".depscan") for f in result.repo.source_files + result.repo.manifest_files)
    assert "canarypkg" not in {d.name for d in result.repo.dependencies}
    sites = [s for u in result.usages.values() for s in u.sites + u.indirect_sites + u.native_reach_sites]
    assert sites and not any(s.file.startswith(".depscan") for s in sites)

    orch.build_context(result)
    orch.analyze(result, "CVE-2017-18342", use_context=False)
    orch.analyze(result, "CVE-2017-18342", use_context=True)
    orch.analyze(result, "CVE-2018-18074", use_context=True)

    prompts = [json.dumps(c["messages"]) for c in fake.calls]
    assert len(prompts) == 4 and log.exists()
    canaries = ["canary", "canary_scenario_q7x", "canary-reason-9f3k", "canary-readme-2b8d", "canary-code-5m1z"]
    canaries += [line.strip() for line in EXPECTED.splitlines() if "reason" in line or "scenario" in line]
    for text in prompts + [log.read_text(encoding="utf-8"), open(result.result_file, encoding="utf-8").read()]:
        assert not any(c in text for c in canaries)
    assert ".depscan" not in "".join(prompts)
