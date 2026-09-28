"""Plain-language views for the main (Check) page. Pure functions: no Streamlit, no internal terms in the output."""

import re
from dataclasses import dataclass
from pathlib import Path

from depscan.models import DependencyVulns, GateResult, ScanResult, TriggerSpec, VerdictRecord, Vulnerability
from depscan.report import SEVERITY_ORDER, latest_verdict, stepwise_status

STATUSES = ["affected", "probably_not_affected", "not_affected", "needs_review", "not_checked"]
STATUS_LABEL = {"affected": "Affected", "probably_not_affected": "Probably not affected",
                "not_affected": "Not affected", "needs_review": "Needs review", "not_checked": "Not checked"}
STATUS_COLORS = {"affected": ("#d92d20", "#ffffff"), "probably_not_affected": ("#66c61c", "#1d2939"),
                 "not_affected": ("#079455", "#ffffff"), "needs_review": ("#f79009", "#1d2939"),
                 "not_checked": ("#eaecf0", "#344054")}
PROBABLY_NOTE = "An AI judged this, not proven by code. Worth a quick look."
GATE_LABEL = {"version_in_range": "Your installed version is in the affected range",
              "trigger_spec": "We know what triggers the vulnerability",
              "present": "Your code uses the vulnerable part",
              "reachable": "That code can actually run",
              "dangerous_form": "It is used in the dangerous way",
              "attacker_input": "An attacker can control the input"}
STAGE_WORDS = {"cloning": "Downloading the repository", "dependencies": "Reading the dependency files",
               "vulnerabilities": "Looking up known vulnerabilities", "usages": "Finding where your code uses them",
               "done": "Done"}
DEFAULT_CHECK_SECONDS = 45


@dataclass
class Row:
    dv: DependencyVulns
    v: Vulnerability
    status: str
    record: VerdictRecord | None

    @property
    def key(self) -> str:
        """Widget-key-safe id (it becomes a CSS class name: st-key-check-<key>)."""
        return re.sub(r"[^A-Za-z0-9_-]", "_", f"{self.dv.dependency.key}__{self.v.id}")


def check_record(v: Vulnerability) -> VerdictRecord | None:
    """The newest stepwise check (the main page's method)."""
    return latest_verdict(v, method="stepwise")


def status_of(v: Vulnerability) -> str:
    rec = check_record(v)
    return stepwise_status(rec) if rec else "not_checked"


def rows(result: ScanResult) -> list[Row]:
    """Every checkable advisory (fuzz crashes hidden), most severe first."""
    out = [Row(dv, v, status_of(v), check_record(v)) for dv in result.vulnerabilities for v in dv.vulnerabilities]
    return sorted(out, key=lambda r: (SEVERITY_ORDER.index(r.v.cvss.severity) if r.v.cvss.severity in SEVERITY_ORDER
                                      else len(SEVERITY_ORDER), -(r.v.cvss.base_score or 0), r.v.id))


def filter_rows(all_rows: list[Row], severity: str = "all", hide_checked: bool = False) -> list[Row]:
    return [r for r in all_rows if (severity == "all" or r.v.cvss.severity == severity)
            and not (hide_checked and r.status != "not_checked")]


def status_counts(all_rows: list[Row]) -> dict[str, int]:
    return {s: sum(1 for r in all_rows if r.status == s) for s in STATUSES}


def summary_sentence(all_rows: list[Row]) -> str:
    n, packages = len(all_rows), len({r.dv.dependency.key for r in all_rows})
    if not n:
        return "No known vulnerabilities in the pinned dependencies."
    checked = sum(1 for r in all_rows if r.status != "not_checked")
    return (f"{n} known vulnerabilit{'y' if n == 1 else 'ies'} in {packages} package{'s' if packages != 1 else ''}. "
            f"{checked} checked.")


def one_line(text: str, limit: int = 160) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def what_it_is(v: Vulnerability, spec: TriggerSpec | None) -> str:
    """The trigger spec's plain summary, falling back to the advisory's own summary."""
    return (spec.plain_summary if spec and spec.plain_summary else "") or v.summary or v.details[:300] or v.id


def how_used(result: ScanResult, dv: DependencyVulns, v: Vulnerability) -> str:
    """'used directly' / 'used through requests' / 'not imported by your code', plus the bundled-library note."""
    dep = dv.dependency
    u = result.usages.get(dep.key)
    if u is None:
        text = "not looked at"
    elif u.usage_status == "direct_usage":
        text = f"used directly in {len({s.file for s in u.sites})} file{'s' if len({s.file for s in u.sites}) != 1 else ''}"
    elif u.usage_status == "parse_incomplete":
        text = "some files could not be read, so this is unclear"
    elif u.required_by:
        text = f"used through {', '.join(u.required_by)}"
    else:
        text = "not imported by your code"
    if v.kind == "bundled_native":
        text += "; the flaw is inside a library bundled with the package"
    return text


def verdict_line(status: str, rec: VerdictRecord | None) -> tuple[str, str]:
    """(headline, one-sentence reason)."""
    if rec is None:
        return STATUS_LABEL["not_checked"], "Press Check to find out whether your code is affected."
    reason = rec.reason or rec.recommendation
    for prefix in ("Affected: ", "Not affected: ", "Needs review: ", "Probably not affected (AI judgement, not "
                   "proven by code): "):
        reason = reason.removeprefix(prefix)
    first = reason.split(" ", 1)[0]
    plain_word = first.isalpha()                   # never capitalise a path or a name: app/x.py, idna.encode
    return STATUS_LABEL[status], (reason[:1].upper() + reason[1:]) if plain_word else reason


def duration_words(seconds: float) -> str:
    return "under a minute" if seconds < 60 else f"about {fmt_minutes(seconds)}"


def fmt_minutes(seconds: float) -> str:
    minutes = round(seconds / 60)
    return f"{minutes // 60} h {minutes % 60} min" if minutes >= 60 else f"{minutes} min"


def gate_mark(g: GateResult) -> str:
    if g.skipped and g.result == "unknown":
        return "–"
    return {"pass": "✓", "fail": "✗", "unknown": "?"}[g.result]


def gate_rows(rec: VerdictRecord) -> list[tuple[str, str, str, str, GateResult]]:
    """(mark, label, explanation, decided by) per gate, in checking order."""
    out = []
    for g in rec.gates:
        by = "not checked" if g.skipped and g.result == "unknown" else ("decided by code" if g.decided_by == "code"
                                                                         else "decided by AI")
        out.append((gate_mark(g), GATE_LABEL.get(g.gate, g.gate), g.explanation, by, g))
    return out


def upgrade_commands(dv: DependencyVulns, v: Vulnerability) -> tuple[str, str] | None:
    """(uv command, pip command) that install a fixed version, or None when no fix is listed."""
    if not v.fixed_version:
        return None
    name = dv.dependency.name
    return f'uv add "{name}>={v.fixed_version}"', f'pip install --upgrade "{name}>={v.fixed_version}"'


def what_to_do(status: str, dv: DependencyVulns, v: Vulnerability, rec: VerdictRecord | None) -> tuple[str, bool]:
    """(advice, whether to show the upgrade commands)."""
    fix = upgrade_commands(dv, v)
    through = "" if dv.dependency.direct else (f" It is installed through {', '.join(dv.dependency.required_by)}; "
                                               "adding it pins the fixed version directly."
                                               if dv.dependency.required_by else "")
    if status == "not_affected":
        why = verdict_line(status, rec)[1]
        why = why[:1].lower() + why[1:] if why.split(" ", 1)[0].isalpha() else why
        return f"No action needed: {why}" + (" Upgrading later is still a good idea."
                                                                    if fix else ""), False
    if not fix:
        return "No fixed version is listed yet. Watch the advisory, and avoid the risky use if you can.", False
    if status == "affected":
        return f"Upgrade {dv.dependency.name} to {v.fixed_version} or later.{through}", True
    if status == "probably_not_affected":
        return f"Probably no action needed. If upgrading is easy, upgrade to {v.fixed_version} or later.{through}", True
    if status == "needs_review":
        return (f"Look at the open questions above, or simply upgrade to {v.fixed_version} or later.{through}", True)
    return f"Check it first, or upgrade to {v.fixed_version} or later.{through}", True


def small_print(rec: VerdictRecord) -> str:
    spec = {"llm": "AI-generated", "human": "human-reviewed", "none": "none"}.get(rec.spec_source or "none", "none")
    calls = rec.llm_calls
    who = "Checked by code only · no AI calls" if calls == 0 else         f"Checked with {rec.model} · {calls} AI call{'s' if calls != 1 else ''}"
    return f"{who} · {rec.duration_ms / 1000:.0f} s · trigger description: {spec} · {rec.timestamp:%Y-%m-%d %H:%M} UTC"


def check_estimate(result: ScanResult, n: int) -> tuple[float, bool]:
    """(seconds for n checks, whether it is based on earlier checks in this result)."""
    done = [r.duration_ms for dv in result.vulnerabilities for v in dv.vulnerabilities for r in v.verdicts
            if r.method == "stepwise"]
    measured = len(done) >= 3                  # one or two code-only checks (0 s) would promise far too little
    per = (sum(done) / len(done) / 1000) if measured else DEFAULT_CHECK_SECONDS
    return per * n, measured


def code_lines(result: ScanResult, citation: str | None, around: int = 3) -> tuple[str, int] | None:
    """(numbered source lines around 'file:line', first line number) read from the scanned copy, or None."""
    if not citation or ":" not in citation:
        return None
    file, _, line = citation.rpartition(":")
    if not line.isdigit() or not result.repo.local_path:
        return None
    root = Path(result.repo.local_path).resolve()
    path = (root / file).resolve()
    if root not in path.parents or not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    n = int(line)
    lo, hi = max(1, n - around), min(len(lines), n + around)
    if n > len(lines):
        return None
    width = len(str(hi))
    text = "\n".join(f"{'>' if i == n else ' '} {i:>{width}}  {lines[i - 1]}" for i in range(lo, hi + 1))
    return text, lo


# ---------------------------------------------------------------- dependencies found

@dataclass
class DepRow:
    key: str
    package: str
    version: str
    usage: str
    vulns: int
    checks: str
    severity_rank: int


def all_usages(result: ScanResult) -> dict:
    """How the code uses every dependency. The scan only locates vulnerable ones; the clean ones are located here
    with the same parser (reads the scanned copy, runs nothing). Empty when the copy is gone."""
    from depscan.agents.usage_locator import UsageLocatorAgent
    from depscan.models import UsageLocatorInput
    usages = dict(result.usages)
    clean = [DependencyVulns(dependency=d, vulnerabilities=[]) for d in result.repo.dependencies
             if d.key not in usages]
    if clean:
        try:
            usages.update(UsageLocatorAgent().run(UsageLocatorInput(repo_map=result.repo, vulnerable=clean)).usages)
        except OSError:
            pass
    return usages


def usage_words(dep, usage) -> str:
    """'used directly' / 'used through requests' / 'not imported', plus 'dev only' for dev dependencies."""
    if usage is None:
        text = "unknown"
    elif usage.usage_status == "direct_usage":
        text = "used directly"
    elif usage.usage_status == "parse_incomplete":
        text = "unclear: some files could not be read"
    elif usage.required_by:
        text = f"used through {', '.join(usage.required_by)}"
    else:
        text = "not imported"
    return f"dev only · {text}" if dep.scope == "dev" else text


def check_breakdown(dep_rows: list[Row]) -> str:
    """'1 affected · 2 not affected · 1 not checked' once anything is checked; '' before that."""
    if not any(r.status != "not_checked" for r in dep_rows):
        return ""
    n = status_counts(dep_rows)
    return " · ".join(f"{n[s]} {STATUS_LABEL[s].lower()}" for s in STATUSES if n[s])


def dependency_rows(result: ScanResult, all_rows: list[Row], usages: dict) -> list[DepRow]:
    """Every dependency found; those with known vulnerabilities first (most severe first), then the clean ones."""
    out = []
    for dep in result.repo.dependencies:
        mine = [r for r in all_rows if r.dv.dependency.key == dep.key]
        ranks = [SEVERITY_ORDER.index(r.v.cvss.severity) if r.v.cvss.severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
                 for r in mine]
        name = f"{dep.name} ({dep.project})" if dep.project else dep.name
        out.append(DepRow(key=dep.key, package=name, version=dep.resolved_version or "not pinned",
                          usage=usage_words(dep, usages.get(dep.key)), vulns=len(mine),
                          checks=(check_breakdown(mine) or "not checked yet") if mine else "",
                          severity_rank=min(ranks) if ranks else 99))
    return sorted(out, key=lambda d: (d.vulns == 0, d.severity_rank, -d.vulns, d.package))
