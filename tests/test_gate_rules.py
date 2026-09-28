"""T5: gates and verdict rules. Every combination of gate results, missing input never fails, spec validation."""

import itertools
import random
from pathlib import Path

import pytest

from depscan.agents.stepwise import VERDICT, StepwiseAgent, status_of
from depscan.models import GATE_ORDER, GateResult

STATES = [(r, by) for r in ("pass", "fail", "unknown") for by in ("code", "llm")]


def reference(gates: list[tuple[str, str]]) -> str:
    """The documented rules, written independently of the implementation."""
    if any(r == "fail" and by == "code" for r, by in gates):
        return "not_affected"                       # only a code-decided fail proves it
    if any(r == "fail" for r, _ in gates):
        return "probably_not_affected"              # the only fails are AI answers
    if all(r == "pass" for r, _ in gates):
        return "affected"
    return "needs_review"                           # something unknown, nothing failed


def as_gates(combo) -> list[GateResult]:
    return [GateResult(gate=name, result=r, decided_by=by, explanation=f"{name} {r} by {by}")
            for name, (r, by) in zip(GATE_ORDER, combo)]


def test_every_combination_follows_the_documented_rules():
    n = 0
    for combo in itertools.product(STATES, repeat=len(GATE_ORDER)):
        assert status_of(as_gates(combo)) == reference(combo), combo
        n += 1
    assert n == 6 ** 6 and len(GATE_ORDER) == 6


def test_status_maps_to_the_three_way_verdict():
    assert VERDICT == {"affected": "likely_affected", "not_affected": "likely_not_affected",
                       "probably_not_affected": "likely_not_affected", "needs_review": "uncertain"}


def test_reasons_match_the_status_on_a_sample(tmp_path):
    from test_stepwise import store
    from depscan.models import Dependency, DependencyVulns, Vulnerability
    agent = StepwiseAgent(store(tmp_path, {}), None, None)
    agent.calls, agent.questions, agent.rejected = 0, 0, []          # what run() sets up before finish()
    dv = DependencyVulns(dependency=Dependency(name="demo", source_file="r.txt", direct=True), vulnerabilities=[])
    v = Vulnerability(id="CVE-X", summary="x", match="affected", match_reason="r")
    prefix = {"affected": "Affected: ", "not_affected": "Not affected: ",
              "probably_not_affected": "Probably not affected (AI judgement", "needs_review": "Needs review: "}
    rng = random.Random(7)
    combos = list(itertools.product(STATES, repeat=6))
    for combo in rng.sample(combos, 300):
        rec = agent.finish(dv, v, as_gates(combo), None, 0.0)
        assert rec.status == reference(combo) and rec.reason.startswith(prefix[rec.status])
        assert rec.verdict == VERDICT[rec.status]
        if rec.status == "not_affected":            # the reason names a code-decided failure, never an AI one
            assert "by code" in rec.reason


# ---------------------------------------------------------------- missing / empty / malformed input: never "fail"

@pytest.fixture(scope="module")
def unsafe_repo():
    from test_stepwise import FIX, build, vuln
    return build(FIX / "unsafe_args", {"pyyaml": [vuln("CVE-M")]})


SPECS = {
    "no_spec": None,
    "empty_lists": "package: pyyaml\nplain_summary: x\ntrigger_symbols: []\narg_forms: []\nparent_triggers: []\n",
    "only_whitespace_symbols": "package: pyyaml\nplain_summary: x\ntrigger_symbols: ['  ', '()']\n",
    "garbled_symbols": "package: pyyaml\nplain_summary: x\ntrigger_symbols: ['yaml.load, full', 'yaml..x']\n",
    "arg_form_without_kwarg_or_position": "package: pyyaml\nplain_summary: x\ntrigger_symbols: [yaml.load]\n"
                                          "arg_forms: [{call: yaml.load, dangerous: [], safe: []}]\n",
    "input_arg_that_does_not_exist": "package: pyyaml\nplain_summary: x\ntrigger_symbols: [yaml.load]\n"
                                     "needs_untrusted_input: true\ninput_arg: nonexistent_kw\n",
    "native_without_wrappers": "package: pyyaml\nplain_summary: x\ntrigger_symbols: []\n"
                               "native_feature: {library: libyaml, wrapper_symbols: []}\n",
}


@pytest.mark.parametrize("case", sorted(SPECS))
def test_missing_or_malformed_spec_input_never_fails_a_gate(tmp_path, unsafe_repo, case):
    from test_stepwise import check, gates
    specs = {} if SPECS[case] is None else {"CVE-M": SPECS[case]}
    rec = check(unsafe_repo, tmp_path, "CVE-M", specs, package="pyyaml")
    g = gates(rec)
    for name in ("trigger_spec", "present", "dangerous_form", "attacker_input"):
        assert g[name].result != "fail", (case, name, g[name].explanation)
    assert rec.status != "not_affected" or g["reachable"].result == "fail", (case, rec.reason)


def test_version_gate_without_a_known_version_is_unknown():
    from depscan.models import Dependency, DependencyVulns, Vulnerability
    dep = Dependency(name="demo", version_spec=">=1.0", source_file="r.txt", direct=True)
    v = Vulnerability(id="CVE-X", summary="x", match="possibly_affected", match_reason="range >=1.0 includes 1.4")
    g = StepwiseAgent.version_gate(DependencyVulns(dependency=dep, vulnerabilities=[v]), v)
    assert g.result == "unknown"


def test_reach_of_an_unknown_place_is_unknown(unsafe_repo):
    from depscan.codeindex import CodeIndex
    idx = CodeIndex(Path(unsafe_repo.repo.local_path), unsafe_repo.repo.source_files, "web_service")
    assert idx.reach("app/nope.py", 3).result == "unknown"
    assert idx.reach(unsafe_repo.repo.source_files[0], 99_999).result == "unknown"


# ---------------------------------------------------------------- spec validation

@pytest.mark.parametrize("given,expected", [
    ("quuxarc.QuuxFile.extractall", "quuxarc.QuuxFile.extractall"),          # already public
    ("quuxarc.archive.QuuxFile.extractall", "quuxarc.QuuxFile.extractall"),  # defining module -> public re-export
    ("QuuxArc.QuuxFile", "quuxarc.QuuxFile"),                                # casing
    ("quux-arc.QuuxFile", None),                                             # not the dist name either: dropped
    ("quuxarc.checksum", "quuxarc.checksum"),                                # star re-export with __all__
    ("quuxarc.somewhere.open_archive", "quuxarc.open_archive"),              # unique by last name part
    ("quuxarc.Invented", None),                                              # invented: dropped
    ("quuxarc._private", "quuxarc.util._private"),                           # real, though private: kept
    ("requests.QuuxFile", None),                                             # another package's root: dropped
])
def test_spec_validation_table(tmp_path, given, expected):
    from datetime import datetime, timezone
    from depscan.grounding import validate_spec
    from depscan.models import TriggerSpec
    from test_grounding import FakePyPI, source
    idx = source(tmp_path, FakePyPI()).index("quuxarc", "2.0.0")
    spec = TriggerSpec(vuln_id="X", package="quuxarc", plain_summary="x", trigger_symbols=[given],
                       created_at=datetime.now(timezone.utc))
    out = validate_spec(spec, idx)
    assert out.trigger_symbols == ([expected] if expected else []), out.validation_issues
