"""T6: metamorphic tests of the code-decided checks (no LLM).

Fast tests check the transformations themselves on a small fixture. The sweep (`pytest -m metamorphic`) applies
every transformation to every development test repo and writes results/metamorphic_report.md.
"""

import ast
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import metamorphic_lib as mm

pytestmark = pytest.mark.metamorphic
FIX = Path(__file__).parent / "fixtures" / "stepwise"


def all_parse(repo: Path) -> bool:
    for p in repo.rglob("*.py"):
        ast.parse(p.read_text(encoding="utf-8"))
    return True


@pytest.mark.parametrize("name", sorted(mm.PRESERVING))
def test_each_transformation_keeps_valid_python(tmp_path, name):
    repo = mm.copy_repo(FIX / "dead_code", tmp_path / "repo")
    before = mm.snapshot(repo)
    change = mm.PRESERVING[name](repo)
    assert all_parse(repo)
    if change is not None:
        assert mm.snapshot(repo) != before or list(repo.rglob(f"*{mm.SUFFIX}.py"))


def test_rename_locals_renames_consistently(tmp_path):
    repo = mm.copy_repo(FIX / "unsafe_args", tmp_path / "repo")
    mm.rename_locals(repo)
    text = "\n".join(p.read_text(encoding="utf-8") for p in mm.py_files(repo))
    assert mm.SUFFIX in text and all_parse(repo)


def test_held_out_repos_are_never_used():
    assert not [p for p in mm.dev_repos() if any(f in p.name for f in mm.FORBIDDEN)]


# ---------------------------------------------------------------- the sweep

def sites(outcome, gate: str) -> list[mm.Site]:
    """The usage sites cited by the 'present' gate of an advisory whose `gate` passed by code."""
    rec = outcome.record
    g = {x.gate: x for x in rec.gates}
    if gate not in g or g[gate].result != "pass" or g[gate].decided_by != "code":
        return []
    out = []
    for e in g["present"].evidence:
        if e.citation and ":" in e.citation and e.citation.rsplit(":", 1)[1].isdigit():
            file, line = e.citation.rsplit(":", 1)
            out.append(mm.Site(file, int(line), e.text.split(" ")[0]))
    return out[:1]


@pytest.mark.slow
def test_metamorphic_sweep(tmp_path):
    harness = mm.Harness(tmp_path / "h")
    report = {"generated": datetime.now(timezone.utc).isoformat(), "repos": {}, "variants": 0, "applied": 0,
              "unexpected": [], "changing": []}
    for src in mm.dev_repos():
        name = src.name.split("__", 1)[1]
        base_dir = mm.copy_repo(src, tmp_path / name / "base")
        baseline, _, base_index = harness.run(base_dir)
        report["repos"][name] = {"advisories": len(baseline)}
        for tname, transform in sorted(mm.PRESERVING.items()):
            repo = mm.copy_repo(src, tmp_path / name / tname)
            before = mm.snapshot(repo)
            report["variants"] += 1
            change = transform(repo)
            if change is None:
                continue
            report["applied"] += 1
            after, _, _ = harness.run(repo)
            diffs = mm.diff_outcomes(baseline, after)
            if diffs:
                report["unexpected"].append({"repo": name, "transformation": change.name, "changes": diffs,
                                             "diff": mm.file_diff(before, repo)[:4000]})
        # meaning-changing: one site per advisory and kind
        for key, out in baseline.items():
            spec = harness.store.get(out.vuln, out.dv.dependency.name)[0]
            for kind, gate in (("constant_argument", "attacker_input"), ("insert_return", "reachable"),
                               ("remove_only_import", "reachable")):
                for site in sites(out, gate):
                    site.input_arg = spec.input_arg if spec else None
                    repo = mm.copy_repo(src, tmp_path / name / f"{kind}-{abs(hash(key)) % 10**6}")
                    before = mm.snapshot(repo)
                    ok = {"constant_argument": lambda: mm.constant_argument(repo, site),
                          "insert_return": lambda: mm.insert_return(repo, site),
                          "remove_only_import": lambda: mm.remove_only_import(repo, base_index, site)}[kind]()
                    report["variants"] += 1
                    if not ok:
                        continue
                    report["applied"] += 1
                    after, result, index = harness.run(repo)
                    line = site.line + (1 if kind == "insert_return" else 0)
                    if kind == "constant_argument":
                        call = index.node_at(site.file, line, site.symbol)
                        got = index.taint(site.file, call, site.input_arg).state if call is not None else "no call"
                        expected_ok = got != "tainted"
                    else:
                        got = index.reach(site.file, line, site.symbol).result
                        expected_ok = got == "fail"
                    entry = {"repo": name, "advisory": key, "kind": kind, "site": f"{site.file}:{site.line}",
                             "site_result": got, "status": f"{out.status} -> {after[key].status if key in after else '-'}",
                             "as_expected": expected_ok}
                    report["changing"].append(entry)
                    if not expected_ok:
                        report["unexpected"].append({**entry, "diff": mm.file_diff(before, repo)[:3000]})
    write_report(report)
    assert not report["unexpected"], json.dumps(report["unexpected"], indent=1)[:6000]


def write_report(r: dict) -> None:
    ok = sum(c["as_expected"] for c in r["changing"])
    lines = ["# Metamorphic test report (T6)", "", f"Generated {r['generated']}. No LLM: only code-decided results "
             "are compared. OSV answers come from the cache; held-out repos are never used.", "",
             f"- variants generated: {r['variants']} (applied: {r['applied']}; the rest had no suitable target)",
             f"- repos: {', '.join(f'{k} ({v['advisories']} advisories)' for k, v in r['repos'].items())}",
             f"- meaning-changing variants: {len(r['changing'])}, as expected: {ok}",
             f"- unexpected results: {len(r['unexpected'])}", ""]
    if r["changing"]:
        lines += ["## Meaning-changing variants", "", "| repo | advisory | kind | site | site result | status |",
                  "|---|---|---|---|---|---|"]
        lines += [f"| {c['repo']} | {c['advisory']} | {c['kind']} | {c['site']} | {c['site_result']}"
                  f"{'' if c['as_expected'] else ' **(unexpected)**'} | {c['status']} |" for c in r["changing"]]
    for u in r["unexpected"]:
        lines += ["", f"## Unexpected: {u['repo']} · {u.get('transformation') or u.get('kind')}", ""]
        lines += [f"- {c}" for c in u.get("changes", [])] or [f"- site result {u.get('site_result')}"]
        lines += ["", "```diff", u.get("diff", ""), "```"]
    out = Path(__file__).parent.parent / "results" / "metamorphic_report.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
