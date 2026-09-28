"""Headless GUI tests (streamlit.testing.AppTest) plus the pure filter/export helpers."""

import csv
import io
import shutil
from concurrent.futures import Future
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from depscan.config import LLMConfig
from depscan.llm.client import LLMClient
from depscan.ui import components
from depscan.ui.export import CSV_COLUMNS, to_csv, to_markdown
from depscan.ui.filters import Filters, filtered_deps, filtered_vulns
from fake_llm import FakeOpenAI
from test_end_to_end import fake_model
from test_orchestrator import FIX, make_orch

ROOT = Path(__file__).parent.parent
APP = str(ROOT / "ui_pages" / "advanced.py")        # the old single page is now the Advanced page
MAIN = str(ROOT / "app.py")


@pytest.fixture
def scanned(tmp_path):
    fake = FakeOpenAI(fake_model)
    orch = make_orch(tmp_path, llm=LLMClient(LLMConfig(), log_path=tmp_path / "logs" / "llm_calls.jsonl", client=fake))
    return orch, orch.scan(str(FIX / "flask_vuln_repo"))


def app_with(orch, result, path: str = APP) -> AppTest:
    at = AppTest.from_file(path, default_timeout=60)
    at.session_state["result"] = result
    # the app keeps one orchestrator per (base_url, model, offline); pre-seed it with the fake-LLM one
    at.session_state["llm_base_url"], at.session_state["llm_model"] = orch.cfg.llm.base_url, orch.cfg.llm.model
    at.session_state["offline"] = False
    at.session_state["_orch"] = orch
    at.session_state["_orch_key"] = (orch.cfg.llm.base_url, orch.cfg.llm.model, False)
    return at


def test_empty_app_renders():
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    assert any("Scan a repository" in i.value for i in at.info)


def test_result_renders_all_sections(scanned):
    orch, result = scanned
    at = app_with(orch, result).run()
    assert not at.exception, at.exception
    headers = [h.value for h in at.header]
    assert headers == ["1 · Scan", "2 · Repo context (optional)", "Results", "3 · Analyze"]
    assert {m.label for m in at.metric} >= {"Dependencies", "Vulnerabilities", "Critical", "Analyzed"}
    assert len(at.dataframe) >= 1
    ctx_boxes = [c for c in at.checkbox if c.label == "use repo context"]
    assert ctx_boxes and not any(c.disabled for c in ctx_boxes)   # the deterministic context comes with the scan


def test_analyze_button_and_context_flow(scanned):
    orch, result = scanned
    at = app_with(orch, result).run()
    at.session_state["selected_dep"] = "pyyaml"
    at.run()
    at.button(key="an-pyyaml:CVE-2017-18342").click().run()
    assert not at.exception, at.exception
    saved = orch.load(result.result_file)                          # every analysis is saved immediately
    assert [r.verdict for r in saved.find("CVE-2017-18342")[0][1].verdicts] == ["likely_affected"]

    assert not orch.load(result.result_file).repo_context.summary            # scan: deterministic part only
    at.button[[b.label for b in at.button].index("Regenerate repo context")].click().run()
    assert orch.load(result.result_file).repo_context.summary                # + the LLM summary
    box = next(c for c in at.checkbox if c.key == "ctx-pyyaml:CVE-2017-18342")
    assert not box.disabled
    box.check().run()
    at.button(key="an-pyyaml:CVE-2017-18342").click().run()
    saved = orch.load(result.result_file)
    assert [r.used_repo_context for r in saved.find("CVE-2017-18342")[0][1].verdicts] == [False, True]
    assert not at.exception
    assert any("likely affected" in m.value for m in at.markdown)  # verdict badges rendered


def test_batch_needs_confirmation_and_runs(scanned):
    orch, result = scanned
    at = app_with(orch, result).run()
    start = next(b for b in at.button if b.label.startswith("Analyze all filtered"))
    start.click().run()
    assert any("estimated" in w.value for w in at.warning)
    assert not any(v.verdicts for dv in result.vulnerabilities for v in dv.vulnerabilities)   # nothing yet
    next(b for b in at.button if b.label == "Confirm").click().run()
    assert not at.exception, at.exception
    saved = orch.load(result.result_file)
    assert all(v.verdicts for dv in saved.vulnerabilities for v in dv.vulnerabilities)
    assert any("Batch finished" in s.value for s in at.success)


# ---------------------------------------------------------------- pure helpers

def test_filters(scanned):
    _, result = scanned
    everything = filtered_vulns(result, Filters())
    assert everything
    only_high = filtered_vulns(result, Filters(severities={"high", "critical"}))
    assert only_high and all(v.cvss.severity in ("high", "critical") for _, v in only_high)
    assert filtered_vulns(result, Filters(scopes={"dev"})) == []
    assert filtered_deps(result, Filters(usage={"no_direct_usage"})) == []
    assert len(filtered_vulns(result, Filters(only_unanalyzed=True))) == len(everything)   # none analyzed yet


def test_exports(scanned):
    orch, result = scanned
    orch.analyze(result, "CVE-2017-18342")
    rows = list(csv.DictReader(io.StringIO(to_csv(result))))
    assert list(rows[0].keys()) == CSV_COLUMNS
    assert len(rows) == sum(len(dv.all_vulns()) for dv in result.vulnerabilities)
    yaml_row = next(r for r in rows if r["vulnerability"] == "CVE-2017-18342")
    assert yaml_row["latest_verdict"] == "likely_affected" and yaml_row["used_repo_context"] == "False"
    md = to_markdown(result)
    assert "# depscan report: flask_vuln_repo" in md and "### CVE-2017-18342 in pyyaml" in md
    assert "Evidence:" in md and "`app/routes.py:11`" in md and "Unknowns:" in md


# ---------------------------------------------------------------- known answers, batch resume, reruns

LABELS = """\
- {id: CVE-2017-18342, package: pyyaml, expected: likely_affected, scenario: reachable}
- {id: CVE-2018-18074, package: requests, expected: likely_affected, scenario: reachable}
"""


@pytest.fixture
def labelled(tmp_path):
    repo = tmp_path / "flask_vuln_repo"
    shutil.copytree(FIX / "flask_vuln_repo", repo)
    (repo / ".depscan").mkdir()
    (repo / ".depscan" / "expected.yaml").write_text(LABELS, encoding="utf-8")
    fake = FakeOpenAI(fake_model)
    orch = make_orch(tmp_path, llm=LLMClient(LLMConfig(), log_path=tmp_path / "logs" / "llm_calls.jsonl", client=fake))
    return orch, orch.scan(str(repo))


def test_evaluation_tab_and_expected_badges(labelled):
    orch, result = labelled
    orch.analyze(result, "CVE-2017-18342")          # fake model: likely_affected (matches)
    orch.analyze(result, "CVE-2018-18074")          # fake model: likely_not_affected (does not match)
    at = app_with(orch, result)
    at.session_state["selected_dep"] = "pyyaml"
    at.run()
    assert not at.exception, at.exception
    assert [t.label for t in at.tabs] == ["Analysis", "Evaluation"]
    assert any("✓ expected: likely affected" in m.value for m in at.markdown)
    at.session_state["selected_dep"] = "requests"
    at.run()
    assert any("✗ expected: likely affected" in m.value for m in at.markdown)
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["holistic w/o ctx"] == "50%" and metrics["holistic w/ ctx"] == "n/a" and metrics["stepwise"] == "n/a"


def test_no_evaluation_tab_without_answers(scanned):
    orch, result = scanned
    at = app_with(orch, result).run()
    assert [t.label for t in at.tabs] == ["Analysis"]


def test_batch_skips_what_is_already_analyzed_in_that_mode(scanned):
    orch, result = scanned
    orch.analyze(result, "CVE-2017-18342")
    total = len(filtered_vulns(result, Filters()))
    at = app_with(orch, result).run()
    labels = [b.label for b in at.button]
    assert f"Analyze all filtered ({total - 1})" in labels
    assert any("1 already analyzed without context, skipped" in c.value for c in at.caption)


def test_rerun_waits_for_inflight_analysis_and_never_repeats_it(scanned):
    orch, result = scanned
    first, second = (("pyyaml", "CVE-2017-18342", False), ("requests", "CVE-2018-18074", False))
    done = Future()
    done.set_result(None)                          # an analysis a Stop/rerun interrupted, finished meanwhile
    components._INFLIGHT[result.result_file] = (done, first, "CVE-2017-18342 (pyyaml)")
    at = app_with(orch, result)
    at.session_state["batch_queue"] = [first, second]
    at.run()
    assert not at.exception, at.exception
    saved = orch.load(result.result_file)
    assert not saved.find("CVE-2017-18342")[0][1].verdicts        # popped from the queue, not re-run
    assert len(saved.find("CVE-2018-18074")[0][1].verdicts) == 1  # the rest of the queue continued
    assert result.result_file not in components._INFLIGHT


def test_vulnerability_expander_stays_open_after_its_label_changes(scanned):
    orch, result = scanned
    at = app_with(orch, result)
    at.session_state["selected_dep"] = "pyyaml"
    at.run()
    at.button(key="an-pyyaml:CVE-2017-18342").click().run()
    at.run()                                          # the next run renders the label with the new verdict
    assert not at.exception, at.exception
    exp = next(e for e in at.expander if "CVE-2017-18342" in e.label)
    assert "likely_affected" in exp.label            # the label now carries the verdict (a new element id) ...
    assert exp.proto.expanded                         # ... and it is still rendered open


def test_clean_result_shows_empty_state(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.1.3\n", encoding="utf-8")
    orch = make_orch(tmp_path)
    result = orch.scan(str(tmp_path))
    assert not result.vulnerabilities
    at = app_with(orch, result).run()
    assert not at.exception, at.exception
    assert any("No known vulnerabilities" in s.value for s in at.success)
    assert "3 · Analyze" not in [h.value for h in at.header]
    assert not any(b.label.startswith("Analyze") for b in at.button)


def test_suite_page_renders_saved_suite(tmp_path, labelled):
    from depscan import suite as su
    from depscan.orchestrator import write_atomic
    orch, result = labelled
    orch.analyze(result, "CVE-2017-18342")
    spec = su.SuiteSpec(repos=[su.SuiteRepo(name="flask", url=result.repo.local_path, analyze=False)])
    rep = su.run_suite(orch, spec, "suite.yaml", no_llm=True)
    write_atomic(orch.cfg.results / "suite_eval_20260101-000000.json", rep.model_dump_json())
    at = app_with(orch, result)
    at.session_state["adv_view"] = "Suite"
    at.run()
    assert not at.exception, at.exception
    assert "depscan · test suite" in [t.value for t in at.title]
    assert {"Repos", "Labelled advisories", "Accuracy w/o context"} <= {m.label for m in at.metric}
    assert len(at.dataframe) >= 1


# ---------------------------------------------------------------- Check page (main page)

INTERNAL_TERMS = ["usage_status", "bundled_native", "indirect_sites", "no_direct_usage", "direct_usage", "fuzz_crash",
                  "version_in_range", "trigger_spec", "dangerous_form", "attacker_input", "likely_affected",
                  "likely_not_affected", "needs_review", "probably_not_affected", "not_checked"]


def main_with(orch, result) -> AppTest:
    return app_with(orch, result, MAIN)


def page_text(at) -> str:
    parts = [m.value for m in at.markdown] + [c.value for c in at.caption] + [t.value for t in at.title]
    parts += [m.label for m in at.metric] + [b.label for b in at.button] + [e.label for e in at.expander]
    parts += [w.value for w in at.warning] + [i.value for i in at.info]
    return "\n".join(str(p) for p in parts)


def test_check_page_is_the_default_page():
    at = AppTest.from_file(MAIN, default_timeout=60).run()
    assert not at.exception, at.exception
    assert any("affect my repo" in t.value for t in at.title)
    assert [b.label for b in at.button if b.label == "Scan"]


def test_check_page_lists_cves_and_counts(scanned):
    orch, result = scanned
    at = main_with(orch, result).run()
    assert not at.exception, at.exception
    from depscan.ui import plain
    rows = plain.rows(result)
    assert rows and all(r.v.kind != "fuzz_crash" for r in rows)
    assert {m.label for m in at.metric} == {"Affected", "Probably not affected", "Not affected", "Needs review",
                                           "Not checked"}
    assert next(m for m in at.metric if m.label == "Not checked").value == str(len(rows))
    assert any(plain.summary_sentence(rows) in m.value for m in at.markdown)
    assert {r.v.id for r in rows} <= {b.label for b in at.button}
    assert any(b.label.startswith("Check all") for b in at.button)
    text = page_text(at)
    assert not [t for t in INTERNAL_TERMS if t in text], [t for t in INTERNAL_TERMS if t in text]


@pytest.fixture
def stepwise_scanned(tmp_path):
    """A scan whose LLM answers every narrow question with a cited "yes"; the specs come from override files."""
    import json
    fake = FakeOpenAI(lambda messages: json.dumps({"answer": "yes", "line": None, "reason": "the input is used"}))
    orch = make_orch(tmp_path, llm=LLMClient(LLMConfig(), log_path=tmp_path / "logs" / "llm_calls.jsonl", client=fake))
    result = orch.scan(str(FIX / "flask_vuln_repo"))
    d = orch.cfg.overrides / "triggers"
    d.mkdir(parents=True, exist_ok=True)
    from depscan.ui import plain
    for r in plain.rows(result):
        (d / f"{r.v.id}.yaml").write_text(f"package: {r.dv.dependency.name}\nplain_summary: Plain words for {r.v.id}.\n"
                                         "trigger_symbols: [yaml.load]\nneeds_untrusted_input: false\n",
                                         encoding="utf-8")
    return orch, result


def test_check_button_runs_stepwise_and_opens_the_checklist(stepwise_scanned):
    orch, result = stepwise_scanned
    at = main_with(orch, result).run()
    row = __import__("depscan.ui.plain", fromlist=["rows"]).rows(result)[0]
    next(b for b in at.button if b.key == f"check-{row.key}").click().run()
    assert not at.exception, at.exception
    shown = at.session_state["result"]                 # the app's own copy of the result
    v = next(v for dv, v in shown.find(row.v.id, row.dv.dependency.key))
    rec = next(r for r in v.verdicts if r.method == "stepwise")
    assert rec.gates and at.session_state["open_cve"] == row.key
    labels = [e.label for e in at.expander]
    assert any("Your installed version is in the affected range" in label for label in labels)
    assert any(c.value.startswith(("Checked with", "Checked by code only")) for c in at.caption)
    assert any(f"Plain words for {row.v.id}." in m.value for m in at.markdown)
    text = page_text(at)
    assert not [t for t in INTERNAL_TERMS if t in text], [t for t in INTERNAL_TERMS if t in text]
    next(b for b in at.button if b.key == "close_detail").click().run()
    assert "open_cve" not in at.session_state


def test_advanced_page_reachable_from_navigation(scanned):
    orch, result = scanned
    at = main_with(orch, result).run()
    at.switch_page("ui_pages/advanced.py").run()
    assert not at.exception, at.exception
    assert "depscan · Advanced" in [t.value for t in at.title]


def test_plain_helpers():
    from datetime import datetime, timezone

    from depscan.models import Dependency, DependencyVulns, GateResult, VerdictRecord, Vulnerability
    from depscan.ui import plain
    dep = Dependency(name="quuxarc", version_spec="==1.0", resolved_version="1.0", source_file="requirements.txt",
                     scope="main", direct=False, required_by=["zorbakit"])
    v = Vulnerability(id="CVE-Q", summary="x", fixed_version="1.2", match="affected", match_reason="r")
    dv = DependencyVulns(dependency=dep, vulnerabilities=[v])
    assert plain.upgrade_commands(dv, v) == ('uv add "quuxarc>=1.2"', 'pip install --upgrade "quuxarc>=1.2"')
    advice, show = plain.what_to_do("affected", dv, v, None)
    assert show and "1.2" in advice and "installed through zorbakit" in advice
    rec = VerdictRecord(verdict="likely_not_affected", confidence=0.9, used_repo_context=False, model="m",
                        timestamp=datetime.now(timezone.utc), method="stepwise", status="not_affected",
                        reason="Not affected: app/old.py is never imported by the app.",
                        gates=[GateResult(gate="reachable", result="fail", explanation="never runs"),
                               GateResult(gate="attacker_input", result="unknown", explanation="n", skipped=True)])
    assert plain.verdict_line("not_affected", rec) == ("Not affected", "app/old.py is never imported by the app.")
    assert plain.duration_words(20) == "under a minute" and plain.duration_words(3900) == "about 1 h 5 min"
    advice, show = plain.what_to_do("not_affected", dv, v, rec)
    assert advice.startswith("No action needed") and not show
    assert [m for m, *_ in plain.gate_rows(rec)] == ["✗", "–"]
    assert plain.gate_rows(rec)[0][1] == "That code can actually run"
    assert plain.what_to_do("affected", dv, v.model_copy(update={"fixed_version": None}), None)[1] is False


def test_code_lines_stay_inside_the_repo(scanned):
    from depscan.ui import plain
    _, result = scanned
    site = next(s for u in result.usages.values() for s in u.sites if s.kind == "call")
    text, _ = plain.code_lines(result, f"{site.file}:{site.line}")
    marked = [ln for ln in text.splitlines() if ln.startswith(">")]
    assert len(marked) == 1 and marked[0].split()[1] == str(site.line)
    assert plain.code_lines(result, "../../etc/passwd:1") is None
    assert plain.code_lines(result, "advisory") is None


def test_dependencies_found_lists_every_dependency(scanned):
    from depscan.ui import plain
    orch, result = scanned
    rows = plain.rows(result)
    deps = plain.dependency_rows(result, rows, plain.all_usages(result))
    assert len(deps) == len(result.repo.dependencies)
    vulnerable = [d for d in deps if d.vulns]
    clean = [d for d in deps if not d.vulns]
    assert vulnerable and clean and deps[:len(vulnerable)] == vulnerable          # vulnerable first
    assert all(d.checks == "not checked yet" for d in vulnerable) and all(d.checks == "" for d in clean)
    ranks = [d.severity_rank for d in vulnerable]
    assert ranks == sorted(ranks)
    assert all(d.usage for d in deps) and not [d for d in deps if "_" in d.usage.split(" ")[0]]

    at = main_with(orch, result).run()
    assert not at.exception, at.exception
    assert any(e.label.startswith(f"Dependencies found ({len(deps)})") for e in at.expander)
    table = at.dataframe[0].value
    assert len(table) == len(deps) and "none known" in set(table["Known vulnerabilities"])
    text = page_text(at) + "\n" + table.to_string()
    assert not [t for t in INTERNAL_TERMS if t in text], [t for t in INTERNAL_TERMS if t in text]


def test_package_filter_and_show_all(scanned):
    from depscan.ui import plain
    orch, result = scanned
    rows = plain.rows(result)
    key = rows[-1].dv.dependency.key
    at = main_with(orch, result)
    at.session_state["check_pkg"] = key
    at.run()
    shown = {b.label for b in at.button if b.key and b.key.startswith("open-")}
    assert shown == {r.v.id for r in rows if r.dv.dependency.key == key}
    next(b for b in at.button if b.key == "check_show_all").click().run()
    assert "check_pkg" not in at.session_state
    assert {b.label for b in at.button if b.key and b.key.startswith("open-")} == {r.v.id for r in rows}


def test_breakdown_after_checks():
    from datetime import datetime, timezone
    from depscan.models import Dependency, DependencyVulns, VerdictRecord, Vulnerability
    from depscan.ui import plain
    dep = Dependency(name="quuxarc", resolved_version="1.0", source_file="r.txt", direct=True)
    rec = VerdictRecord(verdict="likely_affected", confidence=1, used_repo_context=False, model="m", method="stepwise",
                        status="affected", timestamp=datetime.now(timezone.utc))
    vs = [Vulnerability(id=f"CVE-{i}", summary="x", match="affected", match_reason="r") for i in range(3)]
    vs[0].verdicts.append(rec)
    dv = DependencyVulns(dependency=dep, vulnerabilities=vs)
    rows = [plain.Row(dv, v, plain.status_of(v), plain.check_record(v)) for v in vs]
    assert plain.check_breakdown(rows) == "1 affected · 2 not checked"
    assert plain.check_breakdown(rows[1:]) == ""
