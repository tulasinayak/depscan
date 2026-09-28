from pathlib import Path

import pytest

from depscan.cache import ResponseCache
from depscan.config import Config
from depscan.errors import CloneError, NotFound
from depscan.orchestrator import Orchestrator
from depscan.osv import OSVClient
from test_cve_matcher import Clock, FakeOSV

FIX = Path(__file__).parent / "fixtures"


def make_orch(tmp_path, llm=None) -> Orchestrator:
    cfg = Config(workspace=tmp_path / "workspace", results=tmp_path / "results", logs=tmp_path / "logs",
                 cache=tmp_path / "cache", overrides=tmp_path / "overrides")
    client = OSVClient(ResponseCache(tmp_path / "cache.sqlite", 3600, Clock()), transport=FakeOSV().transport(),
                       sleep=lambda s: None)
    return Orchestrator(cfg, llm=llm, osv_client=client)


def test_scan_reports_progress_saves_and_reloads(tmp_path):
    orch = make_orch(tmp_path)
    events = []
    result = orch.scan(str(FIX / "usage_repo"), lambda stage, msg, frac: events.append((stage, frac)))
    assert [s for s, _ in events] == ["cloning", "dependencies", "vulnerabilities", "usages", "done"]
    assert [f for _, f in events] == sorted(f for _, f in events) and events[-1][1] == 1.0
    assert [t.stage for t in result.timings] == ["cloning", "dependencies", "vulnerabilities", "usages"]

    path = Path(result.result_file)
    assert path.parent == tmp_path / "results" and path.name.startswith("usage_repo_") and path.exists()
    assert not list(path.parent.glob("*.tmp"))                    # atomic write leaves nothing behind
    loaded = orch.load(path)
    assert loaded.schema_version == result.schema_version
    assert [dv.dependency.name for dv in loaded.vulnerabilities] == ["urllib3"]
    assert loaded.usages["urllib3"].usage_status == "direct_usage"
    assert loaded.config["llm"]["model"] == orch.cfg.llm.model

    orch.save(loaded)                                             # later steps update the same file
    assert orch.list_results() == [path]


def test_clone_failure_is_friendly(tmp_path):
    with pytest.raises(CloneError) as e:
        make_orch(tmp_path).scan("https://invalid.invalid/owner/repo")
    assert "Could not clone" in e.value.message and e.value.detail


def test_analyze_unknown_vuln(tmp_path):
    orch = make_orch(tmp_path)
    result = orch.scan(str(FIX / "usage_repo"))
    with pytest.raises(NotFound):
        orch.analyze(result, "CVE-0000-0000")
    # the deterministic repo context comes with every scan; only its LLM summary is step 2
    assert result.repo_context is not None and result.repo_context.summary == ""
    with pytest.raises(NotFound, match="Repo context"):
        result.repo_context = None
        orch.analyze(result, "CVE-2021-33503", use_context=True)


def test_analyze_stepwise_appends_a_gate_verdict(tmp_path):
    orch = make_orch(tmp_path)                    # no LLM configured calls: no spec, gates decided in code
    orch.llm = lambda: None
    result = orch.scan(str(FIX / "usage_repo"))
    result = orch.analyze(result, "CVE-2021-33503", method="stepwise")
    rec = result.find("CVE-2021-33503")[0][1].verdicts[-1]
    assert rec.method == "stepwise" and [g.gate for g in rec.gates] == [
        "version_in_range", "trigger_spec", "present", "reachable", "dangerous_form", "attacker_input"]
    assert rec.spec_source == "none" and rec.llm_calls == 0 and rec.reason
    assert orch.load(result.result_file).find("CVE-2021-33503")[0][1].verdicts[-1].method == "stepwise"
