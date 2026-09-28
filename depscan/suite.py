"""evaluate-suite: scan (+ repo context + analyze-all) a list of test repos and score each against its answers.

suite.yaml:
    repos:
      - name: depscan-test-clean
        url: https://github.com/tulasinayak/depscan-test-clean   # or a local path
        context: true      # build repo context and run the with-context pass (default true)
        analyze: true      # run the LLM at all for this repo (default true)
        expected: null     # default: <clone>/.depscan/expected.yaml

With no_llm=True only the deterministic parts are scored (RepoMapper, CVEMatcher labels, UsageLocator).
methods: "holistic" (the one-call baseline, without and with repo context) and/or "stepwise" (the gate method).
Verdicts saved by earlier runs for the same repo commit are carried over (reuse=True), so a method that already
ran is not run again and an interrupted run resumes; redo=True re-runs the chosen methods anyway.
"""

import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import yaml
from pydantic import BaseModel

from depscan import evaluate as ev
from depscan.models import ScanResult
from depscan.orchestrator import Orchestrator
from depscan.report import all_vulns, latest_verdict

METHODS = ("holistic", "stepwise")

Log = Callable[[str], None]


class SuiteRepo(BaseModel):
    name: str
    url: str
    context: bool = True
    analyze: bool = True
    expected: str | None = None
    group: str = "development"        # "heldout": repos written after the method was tuned, reported separately


class SuiteSpec(BaseModel):
    repos: list[SuiteRepo]


class RepoOutcome(BaseModel):
    name: str
    url: str
    analyze: bool = True              # False: verdicts are not part of this repo's evaluation
    group: str = "development"
    result_file: str | None = None
    report: ev.EvalReport | None = None
    error: str | None = None
    scan_seconds: float = 0.0
    llm_seconds: float = 0.0          # wall time of repo context + analyses in this run
    analyses_run: int = 0
    carried_over: int = 0             # verdicts reused from earlier result files of the same commit


class SuiteReport(BaseModel):
    created_at: datetime
    suite_file: str
    no_llm: bool
    methods: list[str] = ["holistic"]
    spec_variant: str | None = None                         # stepwise trigger specs scored in this report
    repos: list[RepoOutcome]
    modes: dict[str, ev.ModeStats]                          # verdicts over all repos
    per_scenario: dict[str, dict[str, ev.ModeStats]]
    groups: dict[str, dict[str, ev.ModeStats]] = {}          # group -> mode -> stats (development / heldout)
    llm_seconds: float = 0.0


def load_suite(path: str | Path) -> SuiteSpec:
    return SuiteSpec.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def carry_over(orch: Orchestrator, result: ScanResult) -> int:
    """Copy verdicts from earlier result files of the same repository commit into this result."""
    slug = result.repo.slug or result.repo.repo_name
    current = Path(result.result_file).resolve()
    found: dict[tuple[str, str], list] = {}
    for path in orch.cfg.results.glob(f"{slug}_*.json"):
        if "_eval_" in path.name or path.resolve() == current:
            continue
        try:
            old = ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if old.repo.commit != result.repo.commit:
            continue
        for dv, v in all_vulns(old, include_fuzz=True):
            found.setdefault((dv.dependency.key, v.id), []).extend(v.verdicts)
    added = 0
    for dv, v in all_vulns(result, include_fuzz=True):
        have = {r.timestamp for r in v.verdicts}
        new = {r.timestamp: r for r in found.get((dv.dependency.key, v.id), []) if r.timestamp not in have}
        v.verdicts = sorted(v.verdicts + list(new.values()), key=lambda r: r.timestamp)
        added += len(new)
    if added:
        orch.save(result)
    return added


def _analyze_all(orch: Orchestrator, result, use_context: bool, log: Log, method: str = "holistic",
                 redo: bool = False, since=None, spec_variant: str | None = None) -> tuple[object, int]:
    def done(v) -> bool:
        rec = latest_verdict(v, use_context if method == "holistic" else None, method, spec_variant)
        return rec is not None and not (redo and (since is None or rec.timestamp < since))

    todo = [(dv, v) for dv, v in all_vulns(result) if not done(v)]
    for i, (dv, v) in enumerate(todo, 1):
        what = method if method == "stepwise" else f"holistic {'with' if use_context else 'without'} context"
        log(f"  {what} {i}/{len(todo)} {v.id} ({dv.dependency.key})")
        result = orch.analyze(result, v.id, use_context, dv.dependency.key, method=method, spec_variant=spec_variant)
        if method == "stepwise":
            rec = latest_verdict(result.find(v.id, dv.dependency.key)[0][1], None, "stepwise", spec_variant)
            log(f"    -> {rec.verdict} ({rec.llm_calls} LLM call(s), {rec.duration_ms / 1000:.0f}s): {rec.reason[:160]}")
    return result, len(todo)


def run_repo(orch: Orchestrator, repo: SuiteRepo, no_llm: bool, log: Log, methods=("holistic",),
             reuse: bool = True, redo: bool = False, spec_variant: str | None = None) -> RepoOutcome:
    out = RepoOutcome(name=repo.name, url=repo.url, analyze=repo.analyze, group=repo.group)
    try:
        t = time.perf_counter()
        result = orch.scan(repo.url)
        out.scan_seconds = round(time.perf_counter() - t, 1)
        out.result_file = result.result_file
        log(f"{repo.name}: scanned in {out.scan_seconds}s, "
            f"{sum(len(dv.vulnerabilities) for dv in result.vulnerabilities)} vulnerabilities")
        if reuse:
            out.carried_over = carry_over(orch, result)
            if out.carried_over:
                log(f"  reused {out.carried_over} verdicts from earlier runs of this commit")
        if repo.analyze and not no_llm:
            t = time.perf_counter()
            since = result.created_at
            if "stepwise" in methods:
                result, n = _analyze_all(orch, result, False, log, "stepwise", redo, since, spec_variant)
                out.analyses_run += n
            if "holistic" in methods:
                result, n = _analyze_all(orch, result, False, log, "holistic", redo, since)
                out.analyses_run += n
                if repo.context:
                    if result.repo_context is None or not result.repo_context.summary:
                        log("  repo context")
                        result = orch.build_context(result)
                    result, n = _analyze_all(orch, result, True, log, "holistic", redo, since)
                    out.analyses_run += n
            out.llm_seconds = round(time.perf_counter() - t, 1)
        path = Path(repo.expected) if repo.expected else ev.default_expected_path(result)
        if not path.exists():
            out.error = f"no expected answers at {path}"
            return out
        out.report = ev.evaluate(result, ev.load_expected_file(path), path, spec_variant)
    except Exception as e:  # noqa: BLE001 - one broken repo must not stop the suite
        out.error = f"{type(e).__name__}: {e}"
        log(f"{repo.name}: FAILED {out.error}")
    return out


def run_suite(orch: Orchestrator, spec: SuiteSpec, suite_file: str | Path, no_llm: bool,
              log: Log = lambda m: None, methods=("holistic",), reuse: bool = True, redo: bool = False,
              spec_variant: str | None = None) -> SuiteReport:
    outcomes = [run_repo(orch, r, no_llm, log, methods, reuse, redo, spec_variant) for r in spec.repos]
    rows = [row for o in outcomes if o.report for row in o.report.rows]
    scenarios = sorted({r.scenario for r in rows})
    return SuiteReport(
        created_at=datetime.now(timezone.utc), suite_file=str(suite_file), no_llm=no_llm, methods=list(methods),
        spec_variant=spec_variant or orch.cfg.grounding.spec_variant,
        repos=outcomes,
        modes={m: ev.mode_stats(rows, m) for m in ev.MODES},
        per_scenario={sc: {m: ev.mode_stats([r for r in rows if r.scenario == sc], m) for m in ev.MODES}
                      for sc in scenarios},
        groups=group_stats(outcomes),
        llm_seconds=round(sum(o.llm_seconds for o in outcomes), 1))


def group_stats(outcomes: list[RepoOutcome]) -> dict[str, dict[str, ev.ModeStats]]:
    groups: dict[str, list] = {}
    for o in outcomes:
        if o.report and o.analyze:
            groups.setdefault(o.group, []).extend(o.report.rows)
    return {g: {m: ev.mode_stats(rows, m) for m in ev.MODES} for g, rows in groups.items()}


# ---------------------------------------------------------------- summaries shared by the CLI, Markdown and GUI

def cell(m: ev.ModeStats | None) -> str:
    """'decided accuracy · coverage · missed affected' for one method, or 'not run'."""
    if m is None or not m.analyzed:
        return "not run"
    hidden = f" (+{m.hidden_affected} hidden)" if m.hidden_affected else ""
    return f"{ev.pct(m.decided_accuracy)} · {ev.pct(m.coverage)} · {m.missed_affected}{hidden}"


def repo_row(o: RepoOutcome) -> dict:
    r = o.report
    row = {"repo": o.name, "group": o.group, "advisories": len(r.rows) if r else "-"}
    for mode, label in ev.MODE_LABELS.items():
        row[label] = cell(r.modes.get(mode)) if r else "-"
    row.update({
        "locator recall": ev.pct(r.sites.recall) if r and r.sites else "-",
        "locator precision": ev.pct(r.sites.precision) if r and r.sites else "-",
        "deps correct": f"{r.dependencies.correct}/{r.dependencies.expected}" if r and r.dependencies else "-",
        "unlabelled": len(r.unlabelled_in_scan) if r and o.analyze else "-",
        "LLM time": f"{o.llm_seconds / 60:.1f} min" if o.llm_seconds else "-",
        "status": o.error or "ok",
    })
    return row


def scenario_row(name: str, modes: dict[str, ev.ModeStats]) -> dict:
    first = next(iter(modes.values()))
    row = {"scenario": name, "advisories": sum(first.matrix[e].get(p, 0) for e in ev.VERDICTS for p in ev.PREDICTED)}
    for mode, label in ev.MODE_LABELS.items():
        row[label] = cell(modes.get(mode))
    return row


def method_rows(rep: SuiteReport) -> list[dict]:
    """One row per method; with several groups, one row per (group, method)."""
    if len(rep.groups) <= 1:
        return [ev.mode_row(ev.MODE_LABELS[m], s) for m, s in rep.modes.items() if m in ev.MODE_LABELS]
    return [{"group": g, **ev.mode_row(ev.MODE_LABELS[m], s)} for g, modes in sorted(rep.groups.items())
            for m, s in modes.items() if m in ev.MODE_LABELS]


def _md_table(rows: list[dict]) -> list[str]:
    if not rows:
        return ["(none)"]
    cols = list(rows[0])
    return (["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
            + ["| " + " | ".join(str(r[c]) for c in cols) + " |" for r in rows])


def to_markdown(rep: SuiteReport) -> str:
    out = [f"# depscan suite evaluation{' (no LLM)' if rep.no_llm else ''}", "",
           f"- suite: `{rep.suite_file}`", f"- generated: {rep.created_at:%Y-%m-%d %H:%M} UTC",
           f"- total LLM time: {rep.llm_seconds / 60:.1f} min", "", "## Methods compared", ""]
    out += _md_table(method_rows(rep))
    out += ["", "decided accuracy = right answers among firm answers (affected / not affected); coverage = share of "
            "labelled advisories with a firm answer (not needs-review); missed affected = expected affected but "
            "answered not affected (the worst error). Cells below: decided accuracy · coverage · missed affected.",
            "", "## Per repo", ""]
    out += _md_table([repo_row(o) for o in rep.repos])
    out += ["", "## Per scenario (verdicts)", ""]
    out += _md_table([scenario_row(sc, m) for sc, m in rep.per_scenario.items()])
    out += ["", "## Details", ""]
    for o in rep.repos:
        out.append(f"### {o.name}")
        if o.error:
            out.append(f"Error: {o.error}")
        if o.report:
            r = o.report
            if r.dependencies:
                bad = [f"{(x.project + '/') if x.project else ''}{x.name}: {'; '.join(x.problems)}"
                       for x in r.dependencies.rows if not x.ok]
                out.append(f"- dependencies: {r.dependencies.correct}/{r.dependencies.expected} correct"
                           + (f"; unexpected: {', '.join(r.dependencies.unexpected)}" if r.dependencies.unexpected else ""))
                out += [f"  - {b}" for b in bad]
            if r.sites:
                out.append(f"- usage sites: recall {ev.pct(r.sites.recall)} ({r.sites.matched}/{r.sites.expected}), "
                           f"precision {ev.pct(r.sites.precision)} ({r.sites.matched}/{r.sites.found})")
                out += [f"  - missed {m}" for m in r.sites.missed] + [f"  - extra {m}" for m in r.sites.extra]
            if r.unlabelled_in_scan and o.analyze:
                out.append(f"- in the scan but not labelled: {', '.join(r.unlabelled_in_scan)}")
            if r.missing_in_scan:
                out.append(f"- labelled but not in the scan: {', '.join(r.missing_in_scan)}")
            if r.rows and o.analyze and not rep.no_llm:
                out += ["", "| id | package | expected | holistic w/o ctx | holistic w/ ctx | stepwise | stepwise reason |",
                        "|---|---|---|---|---|---|---|"]
                out += [f"| {x.id} | {x.package} | {x.expected} | {x.without_context} {ev.mark(x.match_without_context)} | "
                        f"{x.with_context} {ev.mark(x.match_with_context)} | {x.stepwise} {ev.mark(x.match_stepwise)} | "
                        f"{x.stepwise_reason.replace('|', '/')[:220]} |" for x in r.rows]
        out.append("")
    return "\n".join(out)


def generate_specs(orch: Orchestrator, spec: SuiteSpec, variant: str, log: Log = lambda m: None) -> dict[str, int]:
    """Write the trigger spec of one variant for every advisory of the suite's analysed repos (no checks run).
    Existing specs of that variant are kept; returns counts: cached, generated, failed."""
    store = orch.triggers(variant)
    counts = {"cached": 0, "generated": 0, "failed": 0}
    for repo in spec.repos:
        if not repo.analyze:
            continue
        result = orch.scan(repo.url)
        todo = [(dv, v) for dv, v in all_vulns(result)]
        log(f"{repo.name}: {len(todo)} advisories")
        for i, (dv, v) in enumerate(todo, 1):
            t = time.perf_counter()
            got, generated, problem = store.get(v, dv.dependency.name, orch.llm(), dv.dependency.resolved_version)
            key = "generated" if generated and got else "failed" if problem else "cached"
            counts[key] += 1
            if key != "cached":
                log(f"  {i}/{len(todo)} {v.id} ({dv.dependency.name}): {key} in {time.perf_counter() - t:.0f}s"
                    + (f": {problem}" if problem else f", {len(got.trigger_symbols)} trigger symbols"))
    return counts
