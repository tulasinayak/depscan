"""evaluate: matching known answers to saved verdicts, the confusion matrix, accuracy and the CLI command."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from rich.console import Console

from depscan import cli
from depscan import evaluate as ev
from depscan.models import VerdictRecord
from test_orchestrator import FIX, make_orch

EXPECTED = """\
- id: CVE-2017-18342
  package: pyyaml
  expected: likely_affected
  scenario: reachable
  key_location: app/routes.py:11
- id: GHSA-x84v-xcm2-53pg          # an alias of CVE-2018-18074 in the scan
  package: requests
  expected: likely_not_affected
  scenario: unused_feature
- id: CVE-2023-32681
  package: requests
  expected: uncertain
  scenario: unused_feature
- id: CVE-2099-00000
  package: requests
  expected: likely_not_affected
  scenario: unused_feature
"""
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def verdict(v, verdict, ctx, minutes=0):
    v.verdicts.append(VerdictRecord(verdict=verdict, confidence=0.7, used_repo_context=ctx, model="m",
                                    timestamp=T0 + timedelta(minutes=minutes)))


@pytest.fixture
def scanned(tmp_path):
    orch = make_orch(tmp_path)
    result = orch.scan(str(FIX / "flask_vuln_repo"))
    path = tmp_path / "expected.yaml"
    path.write_text(EXPECTED, encoding="utf-8")
    return orch, result, path


def test_load_expected_validates(tmp_path):
    p = tmp_path / "e.yaml"
    p.write_text("- {id: X, package: y, expected: maybe}\n", encoding="utf-8")
    with pytest.raises(Exception):
        ev.load_expected(p)


def test_evaluate_scores_latest_verdict_per_mode(scanned):
    _, result, path = scanned
    yaml_vuln = result.find("CVE-2017-18342")[0][1]
    req_vuln = result.find("CVE-2018-18074")[0][1]
    verdict(yaml_vuln, "uncertain", False, 0)
    verdict(yaml_vuln, "likely_affected", False, 5)          # latest one counts
    verdict(yaml_vuln, "likely_affected", True, 1)
    verdict(req_vuln, "likely_affected", False, 0)            # wrong
    verdict(req_vuln, "uncertain", True, 0)                    # uncertain on a scored label = wrong

    rep = ev.evaluate(result, ev.load_expected(path), path)
    rows = {r.id: r for r in rep.rows}
    assert rows["CVE-2017-18342"].without_context == "likely_affected" and rows["CVE-2017-18342"].match_without_context
    assert rows["GHSA-x84v-xcm2-53pg"].vuln_id == "CVE-2018-18074"                # matched through the alias
    assert rows["GHSA-x84v-xcm2-53pg"].match_without_context is False
    assert rows["CVE-2023-32681"].match_without_context is None                  # expected "uncertain": not scored
    assert rep.missing_in_scan == ["CVE-2099-00000"]
    assert rep.unlabelled_in_scan and not any("CVE-2017-18342" in u for u in rep.unlabelled_in_scan)

    without, with_ = rep.modes["without_context"], rep.modes["with_context"]
    assert (without.scored, without.correct, without.accuracy) == (2, 1, 0.5)
    assert (with_.scored, with_.correct, with_.accuracy, with_.uncertain) == (2, 1, 0.5, 1)
    assert with_.uncertain_rate == 0.5
    assert without.matrix["likely_not_affected"]["likely_affected"] == 1
    assert without.matrix["likely_not_affected"]["not_run"] == 1                 # the missing one
    assert without.matrix["uncertain"]["not_run"] == 1
    assert rep.per_scenario["reachable"]["with_context"].accuracy == 1.0
    md = ev.to_markdown(rep)
    assert "| CVE-2017-18342 | pyyaml | reachable | likely_affected | likely_affected ✓ |" in md
    assert "Labelled but not in the scan: CVE-2099-00000" in md


def test_expected_for_matches_alias_and_package(scanned):
    _, result, path = scanned
    idx = ev.expected_index(ev.load_expected(path))
    req_dv, req_vuln = result.find("CVE-2018-18074")[0]
    yaml_dv = result.find("CVE-2017-18342")[0][0]
    assert ev.expected_for(idx, req_vuln, req_dv.dependency).expected == "likely_not_affected"
    assert ev.expected_for(idx, req_vuln, yaml_dv.dependency) is None
    other_project = req_dv.dependency.model_copy(update={"project": "services/worker"})
    assert ev.expected_for(idx, req_vuln, other_project) is None      # labels are per sub-project


def test_cli_evaluate_prints_and_saves(scanned, monkeypatch, capsys):
    orch, result, path = scanned
    monkeypatch.setattr(cli, "Orchestrator", lambda *a, **k: orch)
    monkeypatch.setattr(cli, "console", Console(width=220))
    assert cli.main(["evaluate", result.result_file, "--expected", str(path)]) == 0
    out = capsys.readouterr().out
    assert "Confusion matrix" in out and "CVE-2017-18342" in out and "Per scenario" in out
    saved = sorted(orch.cfg.results.glob("*_eval_*"))
    assert [p.suffix for p in saved] == [".json", ".md"]
    assert json.loads(saved[0].read_text(encoding="utf-8"))["repo"] == "flask_vuln_repo"
    assert orch.list_results() == [Path(result.result_file)]   # eval files are not results


def test_cli_evaluate_default_path_missing(scanned, monkeypatch):
    orch, result, _ = scanned
    monkeypatch.setattr(cli, "Orchestrator", lambda *a, **k: orch)
    assert cli.main(["evaluate", result.result_file]) == 1           # friendly NotFound, no traceback


def test_dependency_and_site_scoring(scanned, tmp_path):
    _, result, _ = scanned
    p = tmp_path / "full.yaml"
    p.write_text("""
advisories: []
expected_dependencies:
  - {name: pyyaml, version: "3.13", scope: main, direct: true, match: affected}
  - {name: requests, version: "2.19.1", scope: dev}
  - {name: missing-pkg, version: null}
expected_sites:
  - {package: pyyaml, location: "app/routes.py:11", symbol: load}
  - {package: pyyaml, location: "app/routes.py:99"}
""", encoding="utf-8")
    spec = ev.load_expected_file(p)
    rep = ev.evaluate(result, spec, p)
    d = rep.dependencies
    assert (d.expected, d.correct) == (3, 1) and d.missing == ["missing-pkg"] and "flask" in d.unexpected
    assert any("scope main (expected dev)" in x for r in d.rows for x in r.problems)
    s = rep.sites
    assert s.expected == 2 and s.matched == 1 and s.recall == 0.5
    assert s.missed == ["pyyaml app/routes.py:99"] and s.precision < 1 and not s.symbol_mismatches


def test_site_scoring_counts_parent_sites_and_project_keys(tmp_path):
    from depscan.models import DependencyUsage, UsageSite
    orch = make_orch(tmp_path)
    result = orch.scan(str(FIX / "requests_repo"))
    site = lambda pkg, line: UsageSite(id=f"U{line}", package=pkg, file="app.py", line=line, kind="call",  # noqa: E731
                                       symbol=f"{pkg}.get", confidence="high", in_test_path=False)
    result.usages = {
        "urllib3": DependencyUsage(package="urllib3", import_names=["urllib3"], import_name_source="builtin_table", usage_status="no_direct_usage", indirect_sites=[site("requests", 3)]),
        "svc/api:pyyaml": DependencyUsage(package="pyyaml", import_names=["yaml"], import_name_source="builtin_table", usage_status="direct_usage", sites=[site("pyyaml", 7)]),
    }
    got = ev.score_sites(result, [ev.ExpectedSite(package="requests", location="app.py:3"),
                                  ev.ExpectedSite(package="pyyaml", location="app.py:7")])
    assert (got.matched, got.recall, got.precision) == (2, 1.0, 1.0)


def test_methods_side_by_side_with_decided_accuracy_coverage_and_missed(scanned):
    _, result, path = scanned
    yaml_vuln = result.find("CVE-2017-18342")[0][1]      # expected likely_affected
    req_vuln = result.find("CVE-2018-18074")[0][1]       # expected likely_not_affected
    verdict(yaml_vuln, "likely_affected", False, 0)
    verdict(req_vuln, "likely_affected", False, 0)        # false alarm
    yaml_vuln.verdicts.append(VerdictRecord(verdict="likely_not_affected", confidence=0.9, used_repo_context=False,
                                            model="none", method="stepwise", llm_calls=0, llm_called=False,
                                            duration_ms=500, timestamp=T0, reason="Not affected: x"))
    req_vuln.verdicts.append(VerdictRecord(verdict="uncertain", confidence=0.3, used_repo_context=False, model="m",
                                           method="stepwise", llm_calls=2, duration_ms=60_000, timestamp=T0))
    rep = ev.evaluate(result, ev.load_expected_file(path), path)
    rows = {r.id: r for r in rep.rows}
    assert rows["CVE-2017-18342"].stepwise == "likely_not_affected" and rows["CVE-2017-18342"].match_stepwise is False
    assert rows["CVE-2017-18342"].without_context == "likely_affected"         # holistic ignores stepwise records
    assert rows["CVE-2017-18342"].stepwise_reason == "Not affected: x"
    h, s = rep.modes["without_context"], rep.modes["stepwise"]
    assert (h.decided, h.decided_correct, h.decided_accuracy, h.coverage) == (2, 1, 0.5, 1.0)
    assert (h.missed_affected, h.false_alarms) == (0, 1)
    assert (s.decided, s.decided_accuracy, s.coverage, s.missed_affected) == (1, 0.0, 0.5, 1)
    assert (s.llm_calls, s.seconds) == (2, 60.5)
    md = ev.to_markdown(rep)
    assert "| stepwise |" in md and "missed affected" in md


def test_suite_carries_over_verdicts_of_the_same_commit(tmp_path):
    from depscan import suite as su
    orch = make_orch(tmp_path)
    first = orch.scan(str(FIX / "flask_vuln_repo"))
    verdict(first.find("CVE-2017-18342")[0][1], "likely_affected", False, 0)
    orch.save(first)
    second = orch.scan(str(FIX / "flask_vuln_repo"))
    assert second.result_file != first.result_file
    assert su.carry_over(orch, second) == 1
    assert [r.verdict for r in orch.load(second.result_file).find("CVE-2017-18342")[0][1].verdicts] == ["likely_affected"]
    assert su.carry_over(orch, second) == 0                                   # nothing twice
    second.repo.commit = "another-commit"
    third = second.model_copy(deep=True)
    third.result_file = ""
    for dv in third.vulnerabilities:
        for v in dv.all_vulns():
            v.verdicts = []
    orch.save(third)
    assert su.carry_over(orch, third) == 0                                    # other commit: not reused


def test_probably_not_affected_is_its_own_bucket(scanned):
    _, result, path = scanned
    yaml_vuln = result.find("CVE-2017-18342")[0][1]      # expected likely_affected
    req_vuln = result.find("CVE-2018-18074")[0][1]       # expected likely_not_affected
    for v in (yaml_vuln, req_vuln):
        v.verdicts.append(VerdictRecord(verdict="likely_not_affected", confidence=0.6, used_repo_context=False,
                                        model="m", method="stepwise", status="probably_not_affected", timestamp=T0))
    rep = ev.evaluate(result, ev.load_expected_file(path), path)
    s = rep.modes["stepwise"]
    assert (s.probably_not, s.probably_not_right, s.hidden_affected, s.missed_affected) == (2, 1, 1, 0)
    assert (s.decided, s.decided_correct) == (2, 1)
    assert {r.id: r.stepwise for r in rep.rows}["CVE-2017-18342"] == "probably_not_affected"
    assert "| probably_not_affected |" in ev.to_markdown(rep) or "probably_not_affected" in ev.to_markdown(rep)


def test_suite_reports_groups_separately(tmp_path):
    from depscan import suite as su
    rows = [ev.EvalRow(id="A", package="p", scenario="s", expected="likely_affected", stepwise="likely_affected"),
            ev.EvalRow(id="B", package="p", scenario="s", expected="likely_affected", stepwise="uncertain")]
    rep = lambda r: ev.EvalReport(created_at=T0, repo="x", result_file="", expected_file="", rows=r, modes={},
                                  per_scenario={})
    outcomes = [su.RepoOutcome(name="dev", url="u", report=rep(rows[:1])),
                su.RepoOutcome(name="ho", url="u", group="heldout", report=rep(rows[1:]))]
    groups = su.group_stats(outcomes)
    assert groups["development"]["stepwise"].decided == 1 and groups["heldout"]["stepwise"].decided == 0
    srep = su.SuiteReport(created_at=T0, suite_file="s", no_llm=False, repos=outcomes, modes={}, per_scenario={},
                          groups=groups)
    assert {r["group"] for r in su.method_rows(srep)} == {"development", "heldout"}


def test_report_paths_never_show_the_home_folder():
    from depscan.config import PROJECT_ROOT
    from depscan.evaluate import shown_path
    assert shown_path(PROJECT_ROOT / "results" / "x.json") == "results/x.json"
    assert shown_path(Path.home() / "some-repo" / ".depscan" / "expected.yaml") == "~/some-repo/.depscan/expected.yaml"
    assert Path.home().name not in shown_path(Path.home() / "a" / "b.yaml")
