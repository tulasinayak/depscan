"""Compare saved verdicts against a repo's known answers (<repo>/.depscan/expected.yaml).

Read-only and display-only: nothing here is ever passed to an agent or a prompt. The scanner skips the
.depscan/ directory entirely (repo_mapper.SKIP_DIRS), so the answers cannot leak into an analysis.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel

from depscan.models import Dependency, ScanResult, Vulnerability
from depscan.parsers.python_manifests import normalize_name
from depscan.report import all_vulns, latest_verdict, stepwise_status

VERDICTS = ["likely_affected", "likely_not_affected", "uncertain"]
# probably_not_affected: a stepwise "not affected" that only an LLM "no" decided (not proven by code)
PREDICTED = ["likely_affected", "likely_not_affected", "probably_not_affected", "uncertain", "not_run"]
STATUS_LABEL = {"affected": "likely_affected", "not_affected": "likely_not_affected",
                "probably_not_affected": "probably_not_affected", "needs_review": "uncertain"}
# mode -> (method, used_repo_context); "holistic" is the one-LLM-call baseline, "stepwise" the gate method
MODES = {"without_context": ("holistic", False), "with_context": ("holistic", True), "stepwise": ("stepwise", None)}
MODE_LABELS = {"without_context": "holistic w/o ctx", "with_context": "holistic w/ ctx", "stepwise": "stepwise"}
SCORED = ("likely_affected", "likely_not_affected")   # entries labelled "uncertain" are reported, never scored


class ExpectedEntry(BaseModel):
    id: str
    package: str
    expected: Literal["likely_affected", "likely_not_affected", "uncertain"]
    scenario: str = "unspecified"
    reason: str = ""
    key_location: str = ""
    project: str | None = None       # sub-project in multi-project repos ("services/api")


class ExpectedDependency(BaseModel):
    """What RepoMapper should report for one package. Fields left out are not scored."""
    name: str
    version: str | None = None       # the resolved version, or null when it cannot be resolved
    scope: Literal["main", "dev", "unknown"] | None = None
    direct: bool | None = None
    match: Literal["affected", "possibly_affected", "none"] | None = None   # how its advisories are matched
    project: str | None = None       # sub-project (monorepos), e.g. "services/api"


class ExpectedSite(BaseModel):
    """A usage site UsageLocator should find. Scored per (package, file, line)."""
    package: str
    location: str                    # "file:line"
    symbol: str | None = None


class ExpectedFile(BaseModel):
    advisories: list[ExpectedEntry] = []
    expected_dependencies: list[ExpectedDependency] | None = None
    expected_sites: list[ExpectedSite] | None = None


class DepRow(BaseModel):
    name: str
    project: str | None = None
    found: bool
    ok: bool
    problems: list[str] = []


class DepScore(BaseModel):
    expected: int
    found: int                       # dependencies the scan reported
    correct: int                     # expected dependencies found with every specified field right
    accuracy: float | None = None    # correct / expected
    missing: list[str] = []
    unexpected: list[str] = []       # reported but not expected
    rows: list[DepRow] = []


class SiteScore(BaseModel):
    expected: int
    found: int                       # distinct (package, file, line) the scan reported, for the scored packages
    matched: int
    recall: float | None = None
    precision: float | None = None
    missed: list[str] = []
    extra: list[str] = []
    symbol_mismatches: list[str] = []


class EvalRow(BaseModel):
    id: str                          # id as written in expected.yaml
    vuln_id: str | None = None       # display id in the scan (may differ: alias match)
    package: str
    scenario: str
    expected: str
    without_context: str = "not_run"
    with_context: str = "not_run"
    stepwise: str = "not_run"
    match_without_context: bool | None = None   # None = not scored (not run, or expected "uncertain")
    match_with_context: bool | None = None
    match_stepwise: bool | None = None
    llm_calls: dict[str, int] = {}               # mode -> LLM calls of the scored verdict
    seconds: dict[str, float] = {}               # mode -> duration of the scored verdict
    stepwise_reason: str = ""
    reason: str = ""
    key_location: str = ""


class ModeStats(BaseModel):
    analyzed: int = 0                # rows with a verdict in this mode
    scored: int = 0                  # analyzed rows whose expected label is affected / not affected
    correct: int = 0
    accuracy: float | None = None
    uncertain: int = 0
    uncertain_rate: float | None = None     # uncertain / analyzed
    not_run: int = 0
    matrix: dict[str, dict[str, int]] = {}  # expected -> predicted -> count
    decided: int = 0                        # scored rows answered affected / not affected
    decided_correct: int = 0
    decided_accuracy: float | None = None   # decided_correct / decided: how often a firm answer is right
    coverage: float | None = None           # decided / scored: how often a firm answer is given
    missed_affected: int = 0                # expected affected, answered NOT affected (proven) (the worst error)
    false_alarms: int = 0                   # expected not affected, answered affected
    probably_not: int = 0                   # scored rows answered probably_not_affected
    probably_not_right: int = 0             # ... that really were not affected
    hidden_affected: int = 0                # expected affected, answered probably_not_affected
    llm_calls: int = 0
    seconds: float = 0.0


class EvalReport(BaseModel):
    created_at: datetime
    repo: str
    result_file: str
    expected_file: str
    rows: list[EvalRow]
    modes: dict[str, ModeStats]
    per_scenario: dict[str, dict[str, ModeStats]]
    missing_in_scan: list[str] = []          # labelled, but the scan has no such advisory
    unlabelled_in_scan: list[str] = []       # in the scan, but not labelled
    dependencies: DepScore | None = None     # RepoMapper, when expected_dependencies is given
    sites: SiteScore | None = None           # UsageLocator, when expected_sites is given
    llm_seconds: float = 0.0                 # time spent in the analyses that are scored here


def default_expected_path(result: ScanResult) -> Path:
    return Path(result.repo.local_path) / ".depscan" / "expected.yaml"


def load_expected_file(path: str | Path) -> ExpectedFile:
    """A plain list = advisories only; a mapping may add expected_dependencies and expected_sites."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    if isinstance(data, list):
        data = {"advisories": data}
    return ExpectedFile.model_validate({"advisories": data.get("advisories") or [],
                                        "expected_dependencies": data.get("expected_dependencies"),
                                        "expected_sites": data.get("expected_sites")})


def load_expected(path: str | Path) -> list[ExpectedEntry]:
    return load_expected_file(path).advisories


def expected_index(entries: list[ExpectedEntry]) -> dict[str, list[ExpectedEntry]]:
    index: dict[str, list[ExpectedEntry]] = {}
    for e in entries:
        index.setdefault(e.id.upper(), []).append(e)
    return index


def expected_for(index: dict[str, list[ExpectedEntry]], v: Vulnerability, dep: Dependency) -> ExpectedEntry | None:
    """The label for a vulnerability of one dependency, matched by id or any alias, package and project."""
    for i in [v.id, *v.aliases, *v.cve_ids]:
        for e in index.get(i.upper(), []):
            if normalize_name(e.package) == dep.name and (e.project or "") == dep.project:
                return e
    return None


def entry_key(e: ExpectedEntry) -> str:
    name = normalize_name(e.package)
    return f"{e.project}:{name}" if e.project else name


def mode_stats(rows: list[EvalRow], mode: str) -> ModeStats:
    s = ModeStats(matrix={exp: {p: 0 for p in PREDICTED} for exp in VERDICTS})
    for r in rows:
        got = getattr(r, mode)
        s.matrix[r.expected][got] += 1
        if got == "not_run":
            s.not_run += 1
            continue
        s.analyzed += 1
        s.uncertain += got == "uncertain"
        right = got == r.expected or (got == "probably_not_affected" and r.expected == "likely_not_affected")
        if r.expected in SCORED:
            s.scored += 1
            s.correct += right
        if r.expected in SCORED and got != "uncertain":
            s.decided += 1
            s.decided_correct += right
        if r.expected in SCORED and got == "probably_not_affected":
            s.probably_not += 1
            s.probably_not_right += r.expected == "likely_not_affected"
        s.hidden_affected += r.expected == "likely_affected" and got == "probably_not_affected"
        s.missed_affected += r.expected == "likely_affected" and got == "likely_not_affected"
        s.false_alarms += r.expected == "likely_not_affected" and got == "likely_affected"
        s.llm_calls += r.llm_calls.get(mode, 0)
        s.seconds += r.seconds.get(mode, 0.0)
    s.accuracy = round(s.correct / s.scored, 3) if s.scored else None
    s.uncertain_rate = round(s.uncertain / s.analyzed, 3) if s.analyzed else None
    s.decided_accuracy = round(s.decided_correct / s.decided, 3) if s.decided else None
    s.coverage = round(s.decided / s.scored, 3) if s.scored else None
    s.seconds = round(s.seconds, 1)
    return s


def dependency_match(result: ScanResult, dep) -> str:
    """How the scan matched a dependency's advisories: affected / possibly_affected / none."""
    dv = next((d for d in result.vulnerabilities if d.dependency == dep), None)
    if dv is None or not dv.vulnerabilities:
        return "none"
    return "affected" if any(v.match == "affected" for v in dv.vulnerabilities) else "possibly_affected"


def score_dependencies(result: ScanResult, expected: list[ExpectedDependency]) -> DepScore:
    deps = result.repo.dependencies

    def key(name: str, project: str | None) -> tuple[str, str]:
        return normalize_name(name), project or ""

    found = {key(d.name, getattr(d, "project", "")): d for d in deps}
    rows, missing = [], []
    for e in expected:
        d = found.get(key(e.name, e.project))
        if d is None:
            missing.append(f"{e.project}/{e.name}" if e.project else e.name)
            rows.append(DepRow(name=e.name, project=e.project, found=False, ok=False, problems=["not reported"]))
            continue
        problems = []
        if "version" in e.model_fields_set and d.resolved_version != e.version:
            problems.append(f"version {d.resolved_version} (expected {e.version})")
        if e.scope is not None and d.scope != e.scope:
            problems.append(f"scope {d.scope} (expected {e.scope})")
        if e.direct is not None and d.direct != e.direct:
            problems.append(f"direct {d.direct} (expected {e.direct})")
        if e.match is not None and (got := dependency_match(result, d)) != e.match:
            problems.append(f"match {got} (expected {e.match})")
        rows.append(DepRow(name=e.name, project=e.project, found=True, ok=not problems, problems=problems))
    wanted = {key(e.name, e.project) for e in expected}
    unexpected = sorted(f"{p}/{n}" if p else n for n, p in found if (n, p) not in wanted)
    correct = sum(r.ok for r in rows)
    return DepScore(expected=len(expected), found=len(deps), correct=correct,
                    accuracy=round(correct / len(expected), 3) if expected else None,
                    missing=missing, unexpected=unexpected, rows=rows)


def score_sites(result: ScanResult, expected: list[ExpectedSite]) -> SiteScore:
    """Line-level recall/precision of UsageLocator over the packages that expected_sites mentions."""
    want: dict[tuple[str, str, int], ExpectedSite] = {}
    for e in expected:
        file, _, line = e.location.rpartition(":")
        want[(normalize_name(e.package), file.replace("\\", "/"), int(line))] = e
    packages = {p for p, _, _ in want}
    got: dict[tuple[str, str, int], list[str]] = {}
    for usage in result.usages.values():
        # indirect_sites are sites of the parent package (requests calls, shown for urllib3)
        for site in usage.sites + usage.indirect_sites:
            pkg = normalize_name(site.package)
            if pkg in packages:
                got.setdefault((pkg, site.file, site.line), []).append(site.symbol)

    def symbol_ok(k: tuple[str, str, int]) -> bool:
        want_sym = want[k].symbol
        return not want_sym or any(s == want_sym or s.endswith("." + want_sym) for s in got[k])

    matched = sorted(want.keys() & got.keys())
    return SiteScore(expected=len(want), found=len(got), matched=len(matched),
                     recall=round(len(matched) / len(want), 3) if want else None,
                     precision=round(len(matched) / len(got), 3) if got else None,
                     missed=[f"{p} {f}:{ln}" for p, f, ln in sorted(want.keys() - got.keys())],
                     extra=[f"{p} {f}:{ln}" for p, f, ln in sorted(got.keys() - want.keys())],
                     symbol_mismatches=[f"{p} {f}:{ln}: expected {want[(p, f, ln)].symbol}, found "
                                        f"{', '.join(got[(p, f, ln)])}" for p, f, ln in matched
                                        if not symbol_ok((p, f, ln))])


def evaluate(result: ScanResult, expected: "ExpectedFile | list[ExpectedEntry]",
             expected_file: str | Path = "", spec_variant: str | None = None) -> EvalReport:
    """spec_variant: score only stepwise verdicts made with that trigger-spec variant (None: the newest of any)."""
    spec = expected if isinstance(expected, ExpectedFile) else ExpectedFile(advisories=list(expected))
    rows, missing, labelled, llm_ms = [], [], set(), 0
    for e in spec.advisories:
        found = result.find(e.id, entry_key(e)) or ([] if e.project else result.find(e.id))
        row = EvalRow(id=e.id, package=e.package, scenario=e.scenario, expected=e.expected,
                      reason=e.reason, key_location=e.key_location, llm_calls={}, seconds={})
        if not found:
            missing.append(e.id)
        else:
            dv, v = found[0]
            row.vuln_id = v.id
            labelled.add((dv.dependency.key, v.id))
            for mode, (method, ctx) in MODES.items():
                rec = latest_verdict(v, ctx, method, spec_variant if method == "stepwise" else None)
                got = STATUS_LABEL[stepwise_status(rec)] if rec and method == "stepwise" else \
                    (rec.verdict if rec else "not_run")
                setattr(row, mode, got)
                llm_ms += rec.duration_ms if rec and rec.llm_called else 0
                if rec:
                    row.llm_calls[mode] = rec.llm_calls if rec.llm_called else 0
                    row.seconds[mode] = round(rec.duration_ms / 1000, 1)
                    if method == "stepwise":
                        row.stepwise_reason = rec.reason
                if rec and e.expected in SCORED:
                    setattr(row, f"match_{mode}", got == e.expected or (
                        got == "probably_not_affected" and e.expected == "likely_not_affected"))
        rows.append(row)
    unlabelled = [f"{v.id} ({dv.dependency.key})" for dv, v in all_vulns(result)
                  if (dv.dependency.key, v.id) not in labelled]
    scenarios = sorted({r.scenario for r in rows})
    return EvalReport(
        created_at=datetime.now(timezone.utc), repo=result.repo.repo_name, result_file=result.result_file or "",
        expected_file=str(expected_file), rows=rows,
        modes={m: mode_stats(rows, m) for m in MODES},
        per_scenario={sc: {m: mode_stats([r for r in rows if r.scenario == sc], m) for m in MODES} for sc in scenarios},
        missing_in_scan=missing, unlabelled_in_scan=unlabelled,
        dependencies=score_dependencies(result, spec.expected_dependencies) if spec.expected_dependencies else None,
        sites=score_sites(result, spec.expected_sites) if spec.expected_sites else None,
        llm_seconds=round(llm_ms / 1000, 1))


def mark(ok: bool | None) -> str:
    return {True: "✓", False: "✗", None: "–"}[ok]


def pct(x: float | None) -> str:
    return f"{x:.0%}" if x is not None else "n/a"


def mode_row(label: str, s: ModeStats) -> dict:
    """One method's numbers, shared by the CLI, Markdown and GUI."""
    n = s.analyzed or 0
    return {"method": label, "decided accuracy": f"{pct(s.decided_accuracy)} ({s.decided_correct}/{s.decided})",
            "coverage": f"{pct(s.coverage)} ({s.decided}/{s.scored})", "missed affected": s.missed_affected,
            "probably not affected (right)": f"{s.probably_not} ({s.probably_not_right})",
            "affected hidden in probably not": s.hidden_affected,
            "false alarms": s.false_alarms, "accuracy (uncertain = wrong)": f"{pct(s.accuracy)} ({s.correct}/{s.scored})",
            "LLM calls / CVE": f"{s.llm_calls / n:.1f}" if n else "-", "s / CVE": f"{s.seconds / n:.0f}" if n else "-",
            "not run": s.not_run}


def md_table(rows: list[dict]) -> list[str]:
    if not rows:
        return ["(none)"]
    cols = list(rows[0])
    return (["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
            + ["| " + " | ".join(str(r[c]) for c in cols) + " |" for r in rows])


def shown_path(path) -> str:
    """A path for a report that may be shared: relative to the project, else ~/... (never the user's name)."""
    from depscan.config import PROJECT_ROOT
    p = Path(str(path))
    for base, prefix in ((PROJECT_ROOT, ""), (Path.home(), "~/")):
        try:
            return prefix + p.resolve().relative_to(base.resolve()).as_posix()
        except (ValueError, OSError):
            continue
    return p.as_posix()


def to_markdown(rep: EvalReport) -> str:
    out = [f"# depscan evaluation: {rep.repo}", "",
           f"- result: `{shown_path(rep.result_file)}`", f"- expected: `{shown_path(rep.expected_file)}`",
           f"- generated: {rep.created_at:%Y-%m-%d %H:%M} UTC", "", "## Summary", ""]
    out += md_table([mode_row(MODE_LABELS[m], s) for m, s in rep.modes.items()])
    out += ["", "decided accuracy = right answers among firm (affected / not affected) answers; coverage = share of "
            "labelled advisories that got a firm answer; missed affected = expected affected but answered not "
            "affected. Advisories labelled `uncertain` are never scored.", "", "## Advisories", "",
            "| id | package | scenario | expected | holistic w/o ctx | holistic w/ ctx | stepwise |",
            "|---|---|---|---|---|---|---|"]
    for r in rep.rows:
        out.append(f"| {r.id} | {r.package} | {r.scenario} | {r.expected} | "
                   f"{r.without_context} {mark(r.match_without_context)} | {r.with_context} {mark(r.match_with_context)} | "
                   f"{r.stepwise} {mark(r.match_stepwise)} |")
    for m, s in rep.modes.items():
        out += ["", f"## Confusion matrix ({MODE_LABELS[m]})", "", "| expected \\ predicted | " + " | ".join(PREDICTED) + " |",
                "|---" * (len(PREDICTED) + 1) + "|"]
        out += [f"| {exp} | " + " | ".join(str(s.matrix[exp].get(p, 0)) for p in PREDICTED) + " |" for exp in VERDICTS]
    out += ["", "## Per scenario (decided accuracy · coverage · missed affected)", "",
            "| scenario | " + " | ".join(MODE_LABELS.values()) + " |", "|---|---|---|---|"]
    for sc, modes in rep.per_scenario.items():
        out.append(f"| {sc} | " + " | ".join(f"{pct(s.decided_accuracy)} · {pct(s.coverage)} · {s.missed_affected}"
                                             for s in modes.values()) + " |")
    if rep.dependencies:
        d = rep.dependencies
        out += ["", "## Dependencies (RepoMapper)", "",
                f"{d.correct} of {d.expected} expected dependencies fully correct ({pct(d.accuracy)}); "
                f"{d.found} reported."]
        out += [f"- {(r.project + '/') if r.project else ''}{r.name}: {'; '.join(r.problems)}"
                for r in d.rows if not r.ok]
        if d.unexpected:
            out.append(f"- reported but not expected: {', '.join(d.unexpected)}")
    if rep.sites:
        t = rep.sites
        out += ["", "## Usage sites (UsageLocator)", "",
                f"recall {pct(t.recall)} ({t.matched}/{t.expected}), precision {pct(t.precision)} ({t.matched}/{t.found})"]
        out += [f"- missed: {m}" for m in t.missed] + [f"- extra: {m}" for m in t.extra]
        out += [f"- symbol: {m}" for m in t.symbol_mismatches]
    if rep.missing_in_scan:
        out += ["", f"Labelled but not in the scan: {', '.join(rep.missing_in_scan)}"]
    if rep.unlabelled_in_scan:
        out += ["", f"In the scan but not labelled: {', '.join(rep.unlabelled_in_scan)}"]
    return "\n".join(out) + "\n"
