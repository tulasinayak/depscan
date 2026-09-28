"""Streamlit rendering helpers. UI code only renders and calls the Orchestrator; all real work happens there."""

import html
import time
import traceback
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Callable

import altair as alt
import pandas as pd
import streamlit as st

from depscan.agents.repo_context import path_context
from depscan.errors import DepscanError
from depscan.evaluate import (PREDICTED, VERDICTS, ExpectedEntry, ExpectedFile, evaluate, expected_for, pct,
                              to_markdown)
from depscan.llm.client import average_duration_ms
from depscan.models import DependencyVulns, ScanResult, UsageSite, VerdictRecord, Vulnerability
from depscan.orchestrator import Orchestrator
from depscan.report import SEVERITY_ORDER, counts, fixed_in_label, latest_verdict, max_cvss, usage_label
from depscan.ui.filters import Filters, filtered_deps, filtered_vulns

SEV_COLORS = {"critical": ("#b42318", "#ffffff"), "high": ("#e04f16", "#ffffff"), "medium": ("#fdb022", "#1d2939"),
              "low": ("#84caff", "#1d2939"), "none": ("#d0d5dd", "#1d2939"), "unknown": ("#d0d5dd", "#1d2939")}
VERDICT_COLORS = {"likely_affected": ("#d92d20", "#ffffff"), "likely_not_affected": ("#079455", "#ffffff"),
                  "uncertain": ("#667085", "#ffffff")}
KIND_COLORS = {"standard": ("#eaecf0", "#344054"), "bundled_native": ("#7a5af8", "#ffffff"),
               "fuzz_crash": ("#98a2b3", "#ffffff")}
SEV_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "none": "⬜", "unknown": "⬜"}
DEFAULT_SECONDS_PER_VULN = 60
_POOL = ThreadPoolExecutor(max_workers=2)   # long LLM calls run here so the UI can show elapsed time
# result_file -> (future, batch item or None, label). A rerun (Stop, or any click) interrupts the script but not
# the worker thread; the next run waits for it so one result is never analyzed twice or by two threads at once.
_INFLIGHT: dict[str, tuple[Future, tuple | None, str]] = {}


# ---------------------------------------------------------------- small helpers

def badge(text: str, colors: tuple[str, str]) -> str:
    bg, fg = colors
    return (f'<span style="background:{bg};color:{fg};padding:2px 8px;border-radius:10px;'
            f'font-size:0.8rem;font-weight:600;margin-right:4px;white-space:nowrap">{html.escape(text)}</span>')


def md(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def score_text(v: Vulnerability) -> str:
    c = v.cvss
    return f"{c.base_score:.1f} (CVSS v{c.version})" if c.base_score is not None else f"no score ({c.severity})"


def fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 3600}h {seconds % 3600 // 60}m" if seconds >= 3600 else f"{seconds // 60}m {seconds % 60}s"


def show_error(e: Exception) -> None:
    if isinstance(e, DepscanError):
        st.error(e.message)
        if e.detail:
            with st.expander("Error details"):
                st.code(e.detail, language=None)
    else:
        st.error(f"Unexpected error: {type(e).__name__}: {e}")
        with st.expander("Error details"):
            st.code(traceback.format_exc(), language=None)


def run_with_elapsed(fn: Callable, label: str, track: str | None = None, item: tuple | None = None,
                     status: Callable[[], str] | None = None):
    """Run fn in a worker thread, updating an elapsed-time message every half second.
    fn must not touch st.* or st.session_state (no script context in the worker thread).
    track: a result file; the job stays registered in _INFLIGHT until a script run sees it finish."""
    future = _POOL.submit(fn)
    if track:
        _INFLIGHT[track] = (future, item, label)
    placeholder = st.empty()
    start = time.time()
    while not future.done():
        note = status() if status else ""
        placeholder.info(f"⏳ {label} — {int(time.time() - start)}s elapsed" +
                         (f" · {note}" if note else " (CPU inference can take minutes)"))
        time.sleep(0.5)
    placeholder.empty()
    if track:
        _INFLIGHT.pop(track, None)
    return future.result()


def finish_inflight(result: ScanResult) -> None:
    """Wait for an analysis started by an interrupted script run (e.g. the batch Stop button) to finish."""
    key = result.result_file or ""
    entry = _INFLIGHT.get(key)
    if not entry:
        return
    future, item, label = entry
    placeholder = st.empty()
    start = time.time()
    while not future.done():
        placeholder.info(f"⏳ Finishing {label}, which was already running — {int(time.time() - start)}s")
        time.sleep(0.5)
    placeholder.empty()
    _INFLIGHT.pop(key, None)
    queue = st.session_state.get("batch_queue")
    if item and queue and tuple(queue[0]) == item:
        st.session_state["batch_queue"] = queue[1:]
    try:
        future.result()
        st.toast(f"{label}: finished and saved")
    except Exception as e:  # noqa: BLE001
        show_error(e)


def all_sites(result: ScanResult, dep: str) -> list[UsageSite]:
    u = result.usages.get(dep)
    return (u.sites + u.indirect_sites + u.native_reach_sites) if u else []


def context_tag(result: ScanResult, site: UsageSite) -> str:
    """prod / test / example / script: from the repo context when generated, else from the path (same rule)."""
    tag = result.repo_context.usage_contexts.get(site.id) if result.repo_context else None
    return tag or path_context(site.file)


def site_header(result: ScanResult, site: UsageSite, vuln: Vulnerability | None = None) -> str:
    parts = []
    if (vuln and vuln.id in site.matched_vulns) or (vuln is None and site.matched_vulns):
        parts.append("🎯")
    parts.append(f"`{site.file}:{site.line}` · `{site.symbol}` · {site.kind}")
    tag = context_tag(result, site)
    parts.append(f"· **{tag}**" if tag == "prod" else f"· 🧪 **{tag}**" if tag == "test" else f"· 🛠️ **{tag}**")
    if site.confidence == "low":
        parts.append("· ⚠️ low confidence")
    if site.via:
        parts.append(f"· _{site.via}_")
    return " ".join(parts)


def render_site(result: ScanResult, site: UsageSite, vuln: Vulnerability | None = None) -> None:
    st.markdown(site_header(result, site, vuln))
    if site.snippet:
        st.code(site.snippet, language="python")


# ---------------------------------------------------------------- stepper, overview, table

def stepper(result: ScanResult | None) -> None:
    analyzed = counts(result)["analyzed"] if result else 0
    total = counts(result)["vulnerabilities"] if result else 0
    steps = [("1 · Scan", result is not None, result.repo.repo_name if result else "not run yet"),
             ("2 · Repo context (optional)", bool(result and result.repo_context),
              result.repo_context.app_type if result and result.repo_context else "not generated"),
             ("3 · Analyze", analyzed > 0, f"{analyzed}/{total} vulnerabilities analyzed" if result else "—")]
    for col, (title, done, caption) in zip(st.columns(3), steps):
        with col.container(border=True):
            st.markdown(f"{'✅' if done else '⬜'} **{title}**")
            st.caption(caption)


def overview(result: ScanResult) -> None:
    c = counts(result)
    tiles = [("Dependencies", c["dependencies"]), ("Vulnerable deps", c["vulnerable_dependencies"]),
             ("Vulnerabilities", c["vulnerabilities"]), ("Critical", c["critical"]), ("High", c["high"]),
             ("Medium", c["medium"]), ("Low", c["low"]), ("Analyzed", f"{c['analyzed']}/{c['vulnerabilities']}")]
    for col, (label, value) in zip(st.columns(len(tiles)), tiles):
        col.metric(label, value)
    notes = []
    if c["unknown"]:
        notes.append(f"{c['unknown']} vulnerabilities have no CVSS score")
    if c["fuzz_crashes"]:
        notes.append(f"{c['fuzz_crashes']} OSS-Fuzz crash records are not counted (see the kind filter)")
    if notes:
        st.caption(" · ".join(notes))


def vulns_chart(result: ScanResult) -> None:
    rows = [{"dependency": dv.dependency.key, "vulnerabilities": len(dv.vulnerabilities),
             "max severity": max_cvss(dv)[2]} for dv in result.vulnerabilities if dv.vulnerabilities]
    if not rows:
        return
    domain = [s for s in SEVERITY_ORDER if s in {r["max severity"] for r in rows}]
    chart = alt.Chart(pd.DataFrame(rows)).mark_bar().encode(
        x=alt.X("vulnerabilities:Q", title="vulnerabilities", axis=alt.Axis(tickMinStep=1, format="d")),
        y=alt.Y("dependency:N", sort="-x", title=None, axis=alt.Axis(labelOverlap=False, labelLimit=200)),
        color=alt.Color("max severity:N", scale=alt.Scale(domain=domain, range=[SEV_COLORS[s][0] for s in domain])),
        tooltip=["dependency", "vulnerabilities", "max severity"],
    ).properties(height=alt.Step(26))                       # one labelled 26px band per dependency
    st.altair_chart(chart, width="stretch")


def nothing_found(result: ScanResult) -> None:
    """Empty state: the scan found no known vulnerability in any dependency."""
    deps = result.repo.dependencies
    if not deps:
        st.info("No dependencies were found, so there is nothing to check. See Warnings for the manifests that were "
                "looked for.")
        return
    st.success(f"No known vulnerabilities (OSV) in the {len(deps)} dependencies of this repository. "
               "Nothing to analyze.")
    unresolved = sum(1 for d in deps if not d.resolved_version)
    if unresolved:
        st.caption(f"{unresolved} dependencies have no exact version; they were checked against every version "
                   "their range allows.")
    with st.expander(f"Dependencies ({len(deps)})"):
        st.dataframe(pd.DataFrame([{"Dependency": d.key, "Version": d.resolved_version or "unresolved",
                                    "Scope": d.scope, "Direct": d.direct, "Declared in": d.source_file}
                                   for d in deps]), hide_index=True, width="stretch")


def dependency_table(result: ScanResult, filters: Filters) -> str | None:
    """Sortable table of (filtered) vulnerable dependencies. Returns the selected dependency name."""
    deps = filtered_deps(result, filters)
    if not deps:
        st.info("No dependencies match the current filters.")
        return None
    rows = []
    for dv in deps:
        d = dv.dependency
        score, version, sev = max_cvss(dv)
        rows.append({"Dependency": d.key, "Installed": d.resolved_version or "unresolved", "Scope": d.scope,
                     "Direct": d.direct, "Usage": usage_label(result, d.key), "Vulns": len(dv.vulnerabilities),
                     "Max CVSS": score, "CVSS ver": f"v{version}" if version else "", "Severity": sev,
                     "Fixed in": fixed_in_label(dv),
                     "Analyzed": f"{sum(1 for v in dv.vulnerabilities if v.verdicts)}/{len(dv.vulnerabilities)}"})
    df = pd.DataFrame(rows)
    styled = df.style.map(lambda s: f"background-color:{SEV_COLORS.get(s, SEV_COLORS['unknown'])[0]};"
                                    f"color:{SEV_COLORS.get(s, SEV_COLORS['unknown'])[1]}", subset=["Severity"])
    event = st.dataframe(styled, hide_index=True, width="stretch", on_select="rerun",
                         selection_mode="single-row", key="dep_table",
                         column_config={"Max CVSS": st.column_config.NumberColumn(format="%.1f", help="None = no score"),
                                        "Usage": st.column_config.TextColumn(width="large")})
    names = df["Dependency"].tolist()
    if event.selection.rows:
        st.session_state["selected_dep"] = names[event.selection.rows[0]]
    if st.session_state.get("selected_dep") not in names:
        st.session_state["selected_dep"] = names[0]
    st.caption("Select a row to see its usage sites and vulnerabilities. "
               "\"Not imported directly\" never means \"not affected\".")
    return st.session_state["selected_dep"]


def warnings_panel(result: ScanResult) -> None:
    unresolved = [d for d in result.repo.dependencies if not d.resolved_version]
    offline = [w for w in result.warnings if w.startswith("offline:")]
    other = [w for w in result.warnings if not w.startswith("offline:")] + result.repo.warnings
    total = len(unresolved) + len(result.parse_failures) + len(offline) + len(other)
    with st.expander(f"Warnings ({total})", expanded=False):
        if unresolved:
            st.markdown("**Unresolved / unresolvable versions** (their advisories are listed as possibly affected)")
            for d in unresolved:
                st.markdown(f"- `{d.name}` ({d.source_file}): {d.unresolved_reason or 'unresolved'}")
        if result.parse_failures:
            st.markdown("**Files that failed to parse** (regex fallback used, low confidence)")
            for f in result.parse_failures:
                st.markdown(f"- {f}")
        if offline:
            st.markdown("**Offline cache misses**")
            for w in offline:
                st.markdown(f"- {w}")
        if other:
            st.markdown("**Other**")
            for w in other:
                st.markdown(f"- {w}")
        if not total:
            st.caption("No warnings.")


# ---------------------------------------------------------------- repo context (step 2)

def context_card(result: ScanResult) -> None:
    ctx = result.repo_context
    with st.container(border=True):
        md(f"<b>Repo context</b> &nbsp; {badge(ctx.app_type, ('#155eef', '#ffffff'))} "
           + "".join(badge(f, ("#eaecf0", "#344054")) for f in ctx.frameworks)
           + f"<br><small>background only, never used as evidence · generated {ctx.created_at:%Y-%m-%d %H:%M} UTC"
           + (f" · summary by {ctx.model}" if ctx.model else "") + "</small>")
        if ctx.summary:
            st.markdown(f"_{ctx.summary}_")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Entry points**")
            st.markdown("\n".join(f"- `{e}`" for e in ctx.entry_points[:12]) or "- none found")
            if len(ctx.entry_points) > 12:
                st.caption(f"+{len(ctx.entry_points) - 12} more")
        with c2:
            st.markdown("**Untrusted input sources**")
            st.markdown("\n".join(f"- `{u.symbol}` at `{u.file}:{u.line}`" for u in ctx.untrusted_input_sources[:12])
                        or "- none found")
            if len(ctx.untrusted_input_sources) > 12:
                st.caption(f"+{len(ctx.untrusted_input_sources) - 12} more")


# ---------------------------------------------------------------- dependency detail + vulnerabilities

def dependency_detail(result: ScanResult, name: str, filters: Filters, orch: Callable[[], Orchestrator],
                      expected: dict[str, ExpectedEntry] | None = None) -> None:
    dv = next(d for d in result.vulnerabilities if d.dependency.key == name)
    d = dv.dependency
    usage = result.usages.get(name)
    st.subheader(f"{d.name} {d.resolved_version or '(unresolved)'}")
    st.caption((f"project: {d.project} · " if d.project else "")
               + f"scope: {d.scope} · {'direct' if d.direct else 'transitive'} · declared in {d.source_file}"
               + (f" · required by: {', '.join(d.required_by)}" if d.required_by else "")
               + (f" · extras: {', '.join(d.extras)}" if d.extras else "") + (f" · marker: {d.marker}" if d.marker else ""))
    if usage:
        (st.success if usage.usage_status == "direct_usage" else st.warning)(f"**{usage_label(result, name)}** — {usage.note}")
        shown = sorted([s for s in usage.sites if s.snippet],
                       key=lambda s: (not s.matched_vulns, s.in_test_path, s.file, s.line))
        with st.expander(f"Usage sites ({len(usage.sites)}; {len(shown)} with snippets)",
                         expanded=bool(usage.sites) and len(usage.sites) <= 6):
            for s in shown:
                render_site(result, s)
            rest = [s for s in usage.sites if not s.snippet]
            if rest:
                st.caption(f"{len(rest)} more sites without stored snippets (cap: 30 per dependency)")
                st.dataframe(pd.DataFrame([{"file": s.file, "line": s.line, "symbol": s.symbol, "kind": s.kind}
                                           for s in rest]), hide_index=True, width="stretch")
        if usage.indirect_sites:
            with st.expander(f"How the repo reaches it: usage of {', '.join(usage.required_by)} ({len(usage.indirect_sites)})"):
                for s in usage.indirect_sites:
                    render_site(result, s)
        if usage.native_reach_sites:
            with st.expander(f"APIs that may reach the bundled native library ({len(usage.native_reach_sites)})"):
                for s in usage.native_reach_sites:
                    render_site(result, s)

    vulns = sorted(filtered_vulns(result, filters, name),
                   key=lambda p: (p[1].cvss.base_score is None, -(p[1].cvss.base_score or 0), p[1].id))
    st.markdown(f"**Vulnerabilities ({len(vulns)} matching the filters)**")
    for _, v in vulns:
        vulnerability_expander(result, dv, v, orch, expected_for(expected, v, dv.dependency) if expected else None)


def vulnerability_expander(result: ScanResult, dv: DependencyVulns, v: Vulnerability,
                           orch: Callable[[], Orchestrator], expected: ExpectedEntry | None = None) -> None:
    rec = latest_verdict(v)
    verdict_text = f" · 🧠 {rec.verdict}" if rec else ""
    label = f"{SEV_ICON.get(v.cvss.severity, '⬜')} {v.id} · {score_text(v)} · {v.summary[:90]}{verdict_text}"
    # The label changes when a verdict is added, and Streamlit then treats it as a new (collapsed) expander even
    # with a key. So the open/closed state is remembered separately and passed back in as `expanded`.
    key = f"vx-{dv.dependency.key}-{v.id}"
    open_key = f"{key}-open"

    def remember() -> None:
        st.session_state[open_key] = bool(st.session_state.get(key))

    with st.expander(label, expanded=st.session_state.get(open_key, False), key=key, on_change=remember):
        md(badge(v.kind, KIND_COLORS[v.kind]) + badge(v.cvss.severity, SEV_COLORS.get(v.cvss.severity, SEV_COLORS["unknown"]))
           + badge(v.match.replace("_", " "), ("#eaecf0", "#344054")))
        ids = [f"aliases: {', '.join(v.aliases)}" if v.aliases else "", f"related: {', '.join(v.related_ids)}" if v.related_ids else ""]
        st.caption(" · ".join(x for x in ids if x) or "no aliases")
        st.markdown(f"**CVSS:** {score_text(v)}" + (f" · `{v.cvss.vector}`" if v.cvss.vector else ""))
        st.markdown(f"**Summary:** {v.summary or '-'}")
        c1, c2, c3 = st.columns(3)
        with c1.popover("Full details", width="stretch"):
            st.markdown(v.details or "(no details)")
        with c2.popover(f"References ({len(v.references)})", width="stretch"):
            for url in v.references:
                st.markdown(f"- [{url}]({url})")
        c3.markdown(f"**Fixed in:** {v.fixed_version or 'no fix listed'}")
        st.markdown(f"**Affected ranges:** {'; '.join(v.affected_ranges) or 'unknown'} · _{v.match_reason}_")
        if v.advisory_symbols or v.affected_functions:
            st.markdown("**Symbols named in the advisory:** "
                        + ", ".join(f"`{s}`" for s in v.affected_functions + v.advisory_symbols))
        matching = [s for s in all_sites(result, dv.dependency.key) if v.id in s.matched_vulns]
        if matching:
            st.markdown(f"**Usage sites touching those symbols ({len(matching)}):** "
                        + ", ".join(f"`{s.file}:{s.line}` `{s.symbol}`" for s in matching[:8]))
        st.divider()
        analyze_controls(result, dv, v, orch)
        verdict_section(result, dv, v, expected)


def analyze_controls(result: ScanResult, dv: DependencyVulns, v: Vulnerability, orch: Callable[[], Orchestrator]) -> None:
    key = f"{dv.dependency.key}:{v.id}"
    c1, c2 = st.columns([1, 2])
    use_ctx = c2.checkbox("use repo context", key=f"ctx-{key}", disabled=result.repo_context is None,
                          help="Run step 2 (Generate repo context) first." if result.repo_context is None else
                          "Adds the repo context to the prompt as 'Background (not evidence)'.")
    if c1.button("Analyze exploitability", key=f"an-{key}", type="primary"):
        st.session_state[f"vx-{dv.dependency.key}-{v.id}-open"] = True   # keep showing the verdict it produces
        o = orch()  # resolve in the script thread: the worker thread cannot read st.session_state
        try:
            run_with_elapsed(lambda: o.analyze(result, v.id, bool(use_ctx), dv.dependency.key),
                             f"Analyzing {v.id} with {o.cfg.llm.model}", track=result.result_file,
                             status=o.llm_status)
            st.toast(f"{v.id}: {latest_verdict(v, method='holistic').verdict}")
        except Exception as e:  # noqa: BLE001 - shown to the user
            show_error(e)


def verdict_section(result: ScanResult, dv: DependencyVulns, v: Vulnerability,
                    expected: ExpectedEntry | None = None) -> None:
    without, with_ctx = latest_verdict(v, False, "holistic"), latest_verdict(v, True, "holistic")
    shown = [r for r in (without, with_ctx) if r]
    if not shown:
        st.caption("Not analyzed yet.")
        return
    if without and with_ctx:
        if without.verdict != with_ctx.verdict:
            st.info(f"The verdict changed with repo context: **{without.verdict}** → **{with_ctx.verdict}**")
        cols = st.columns(2)
        for col, rec in zip(cols, (without, with_ctx)):
            with col:
                verdict_card(result, dv, rec, expected)
    else:
        verdict_card(result, dv, shown[0], expected)
    older = [r for r in v.verdicts if r not in shown and r.method == "holistic"]
    if older:
        with st.popover(f"Verdict history ({len(older)} older run{'s' if len(older) != 1 else ''})"):
            for r in sorted(older, key=lambda r: r.timestamp, reverse=True):
                st.markdown(f"- {r.timestamp:%Y-%m-%d %H:%M} · **{r.verdict}** {r.confidence:.2f} · "
                            f"{'with' if r.used_repo_context else 'without'} context · {r.model}")


def expected_badge(rec: VerdictRecord, expected: ExpectedEntry | None) -> str:
    """Display-only comparison with the repo's known answer (.depscan/expected.yaml)."""
    if expected is None:
        return ""
    ok = rec.verdict == expected.expected
    return badge(f"{'✓' if ok else '✗'} expected: {expected.expected.replace('_', ' ')}",
                 ("#079455", "#ffffff") if ok else ("#d92d20", "#ffffff"))


def verdict_card(result: ScanResult, dv: DependencyVulns, rec: VerdictRecord,
                 expected: ExpectedEntry | None = None) -> None:
    with st.container(border=True):
        md(badge(rec.verdict.replace("_", " "), VERDICT_COLORS[rec.verdict])
           + badge(f"confidence {rec.confidence:.2f}", ("#eaecf0", "#344054"))
           + badge("with context" if rec.used_repo_context else "without context",
                   ("#155eef", "#ffffff") if rec.used_repo_context else ("#eaecf0", "#344054"))
           + expected_badge(rec, expected)
           + f'<br><small style="white-space:nowrap">{html.escape(rec.model)} · {rec.duration_ms / 1000:.0f}s · '
             f'{rec.timestamp:%Y-%m-%d %H:%M} UTC</small>')
        st.markdown("**Evidence**")
        sites = all_sites(result, dv.dependency.key)
        if not rec.evidence:
            st.caption("(none)")
        for i, e in enumerate(rec.evidence):
            st.markdown(f"- {e.text}")
            site = cited_site(e.citation, sites)
            if site:
                with st.popover(f"📄 {e.citation}"):
                    render_site(result, site)
            elif e.citation:
                st.caption(f"  source: {e.citation}")
        st.markdown("**Inference**")
        st.markdown("\n".join(f"- {x}" for x in rec.inference) or "(none)")
        st.markdown("**Unknowns**")
        st.markdown("\n".join(f"- {x}" for x in rec.unknowns) or "(none)")
        st.markdown(f"**Recommendation:** {rec.recommendation}")
        for note in rec.notes:
            st.caption(note)
        for c in rec.dropped_citations:
            st.caption(f"dropped (not a real usage site): {c}")


def cited_site(citation: str | None, sites: list[UsageSite]) -> UsageSite | None:
    from depscan.agents.exploitability import CITATION
    m = CITATION.match(citation or "")
    if not m:
        return None
    file, line = m.group("file").replace("\\", "/").removeprefix("./"), int(m.group("line"))
    candidates = [s for s in sites if s.file == file and s.snippet]
    return min(candidates, key=lambda s: abs(s.line - line)) if candidates else None


# ---------------------------------------------------------------- batch analysis

def batch_panel(result: ScanResult, filters: Filters, orch: Callable[[], Orchestrator]) -> None:
    c1, c2 = st.columns([2, 3])
    use_ctx = bool(c2.checkbox("use repo context", key="batch-ctx", disabled=result.repo_context is None,
                               help="Run step 2 first." if result.repo_context is None else None))
    redo = c2.checkbox("re-analyze ones that already have a verdict in this mode", key="batch-redo")
    matching = filtered_vulns(result, filters)
    # Skipping what already has a verdict in this mode makes a stopped batch resumable.
    todo = matching if redo else [(dv, v) for dv, v in matching if latest_verdict(v, use_ctx, "holistic") is None]
    llm_todo = [p for p in todo if p[1].kind != "fuzz_crash"]
    avg = average_duration_ms(orch().cfg.logs / "llm_calls.jsonl")
    per = (avg / 1000) if avg else DEFAULT_SECONDS_PER_VULN
    estimate = per * len(llm_todo)
    queue = st.session_state.get("batch_queue")
    if not queue and c1.button(f"Analyze all filtered ({len(todo)})", disabled=not todo):
        st.session_state["batch_confirm"] = True
    skipped = len(matching) - len(todo)
    c2.caption(f"≈ {fmt_duration(estimate)} ({'average of logged runs' if avg else f'{DEFAULT_SECONDS_PER_VULN}s per vulnerability, no history yet'})"
               + (f" · {skipped} already analyzed {'with' if use_ctx else 'without'} context, skipped" if skipped else ""))

    if st.session_state.get("batch_confirm") and not queue:
        st.warning(f"Run {len(todo)} analyses ({len(llm_todo)} LLM calls), estimated {fmt_duration(estimate)}? "
                   "Each result is saved as soon as it finishes.")
        b1, b2 = st.columns(2)
        if b1.button("Confirm", type="primary"):
            st.session_state["batch_queue"] = [(dv.dependency.key, v.id, use_ctx) for dv, v in todo]
            st.session_state["batch_confirm"] = False
            st.rerun()
        if b2.button("Cancel"):
            st.session_state["batch_confirm"] = False
            st.rerun()

    if queue:
        st.button("⏹ Stop", on_click=lambda: st.session_state.update(batch_queue=[]),
                  help="Stops after the analysis in progress; everything finished is already saved.")
        total = len(queue)
        bar = st.progress(0.0, text=f"0/{total}")
        while st.session_state.get("batch_queue"):
            dep, vid, ctx = st.session_state["batch_queue"][0]
            done = total - len(st.session_state["batch_queue"])
            bar.progress(done / total, text=f"{done}/{total} · analyzing {vid} ({dep})")
            o = orch()
            try:
                run_with_elapsed(lambda: o.analyze(result, vid, ctx, dep), f"{vid} ({dep})",
                                 track=result.result_file, item=(dep, vid, ctx), status=o.llm_status)
            except Exception as e:  # noqa: BLE001
                st.session_state["batch_queue"] = []
                show_error(e)
                return
            st.session_state["batch_queue"] = st.session_state["batch_queue"][1:]
        bar.progress(1.0, text=f"{total}/{total} done")
        st.success(f"Batch finished: {total} analyses saved to {result.result_file}")


# ---------------------------------------------------------------- evaluation (display only)

def evaluation_tab(result: ScanResult, spec: ExpectedFile, path: Path) -> None:
    """Compare the saved verdicts with the repo's known answers. Never feeds back into any analysis."""
    rep = evaluate(result, spec, path)
    st.caption(f"Known answers from `{path}` ({len(spec.advisories)} labelled advisories). Display only: the scanner "
               "skips `.depscan/`, and nothing here is sent to the model.")
    deterministic_scores(rep)
    if not spec.advisories:
        st.info("This repository labels no advisories, so there are no verdicts to score.")
        return
    from depscan.evaluate import MODE_LABELS, mode_row
    from depscan.suite import cell
    for col, (mode, s) in zip(st.columns(len(rep.modes)), rep.modes.items()):
        col.metric(MODE_LABELS[mode], pct(s.decided_accuracy),
                   help=f"decided accuracy: {s.decided_correct} of {s.decided} firm answers right; coverage "
                        f"{pct(s.coverage)}; missed affected {s.missed_affected}; {s.not_run} not run")
    st.dataframe(pd.DataFrame([mode_row(MODE_LABELS[m], s) for m, s in rep.modes.items()]), hide_index=True,
                 width="stretch")
    mark = {True: "✓", False: "✗", None: "–"}
    st.dataframe(pd.DataFrame([{"id": r.id, "package": r.package, "scenario": r.scenario, "expected": r.expected,
                                "holistic w/o ctx": f"{r.without_context} {mark[r.match_without_context]}",
                                "holistic w/ ctx": f"{r.with_context} {mark[r.match_with_context]}",
                                "stepwise": f"{r.stepwise} {mark[r.match_stepwise]}",
                                "stepwise reason": r.stepwise_reason,
                                "key location": r.key_location} for r in rep.rows]),
                 hide_index=True, width="stretch")
    for col, (mode, s) in zip(st.columns(len(rep.modes)), rep.modes.items()):
        col.markdown(f"**Confusion matrix · {MODE_LABELS[mode]}** (rows: expected, columns: predicted)")
        col.dataframe(pd.DataFrame(s.matrix).T.reindex(index=VERDICTS, columns=PREDICTED).fillna(0).astype(int),
                      width="stretch")
    st.markdown("**Per scenario** (decided accuracy · coverage · missed affected)")
    st.dataframe(pd.DataFrame([{"scenario": sc, **{MODE_LABELS[m]: cell(s) for m, s in modes.items()}}
                               for sc, modes in rep.per_scenario.items()]), hide_index=True, width="stretch")
    st.caption("decided accuracy: right answers among firm answers (affected / not affected); coverage: share of "
               "labelled advisories with a firm answer; missed affected: expected affected, answered not affected.")
    if rep.missing_in_scan:
        st.warning(f"Labelled but not in the scan: {', '.join(rep.missing_in_scan)}")
    if rep.unlabelled_in_scan:
        st.warning(f"In the scan but not labelled: {', '.join(rep.unlabelled_in_scan)}")
    st.download_button("Evaluation report (Markdown)", to_markdown(rep), file_name=f"{result.repo.slug}_eval.md",
                       mime="text/markdown")


def deterministic_scores(rep) -> None:
    """RepoMapper and UsageLocator scores (expected_dependencies / expected_sites), when the answers have them."""
    if not (rep.dependencies or rep.sites):
        return
    cols = st.columns(3)
    if rep.dependencies:
        d = rep.dependencies
        cols[0].metric("Dependencies correct", f"{d.correct}/{d.expected}",
                       help="name found and every specified field (version, scope, direct, match) right")
    if rep.sites:
        t = rep.sites
        cols[1].metric("Locator recall", pct(t.recall), help=f"{t.matched} of {t.expected} expected usage lines found")
        cols[2].metric("Locator precision", pct(t.precision), help=f"{t.matched} of {t.found} reported lines expected")
    problems = ([f"dependency {(r.project + '/') if r.project else ''}{r.name}: {'; '.join(r.problems)}"
                 for r in rep.dependencies.rows if not r.ok] if rep.dependencies else [])
    problems += [f"reported but not expected: {x}" for x in (rep.dependencies.unexpected if rep.dependencies else [])]
    problems += ([f"missed usage site: {m}" for m in rep.sites.missed] + [f"extra usage site: {m}" for m in rep.sites.extra]
                 if rep.sites else [])
    if problems:
        with st.expander(f"Deterministic problems ({len(problems)})"):
            st.markdown("\n".join(f"- {p}" for p in problems))


# ---------------------------------------------------------------- suite results page

def suite_page(results_dir: Path) -> None:
    """Results of `python -m depscan.cli evaluate-suite`: per repo, per scenario, with vs without context."""
    from depscan import suite as su

    st.title("depscan · test suite")
    files = sorted(results_dir.glob("suite_eval_*.json"), key=lambda f: f.stat().st_mtime, reverse=True) \
        if results_dir.exists() else []
    if not files:
        st.info("No suite results yet. Run `uv run python -m depscan.cli evaluate-suite <suite.yaml>` "
                "(add `--no-llm` for the fast deterministic-only run).")
        return
    with st.sidebar:
        picked = st.selectbox("Suite result", files, format_func=lambda f: f.name)
    try:
        rep = su.SuiteReport.model_validate_json(picked.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        show_error(e)
        return
    st.caption(f"`{rep.suite_file}` · {rep.created_at:%Y-%m-%d %H:%M} UTC"
               + (" · **no-LLM run: only the deterministic parts are scored**" if rep.no_llm else ""))

    w, c = rep.modes["without_context"], rep.modes["with_context"]
    labelled = sum(len(o.report.rows) for o in rep.repos if o.report)
    tiles = [("Repos", len(rep.repos)), ("Labelled advisories", labelled),
             ("Accuracy w/o context", pct(w.accuracy)), ("Accuracy with context", pct(c.accuracy)),
             ("LLM time", f"{rep.llm_seconds / 60:.0f} min" if rep.llm_seconds else "-")]
    for col, (label, value) in zip(st.columns(len(tiles)), tiles):
        col.metric(label, value)

    st.subheader("Per repo")
    st.dataframe(pd.DataFrame([su.repo_row(o) for o in rep.repos]), hide_index=True, width="stretch")

    st.subheader("Per scenario")
    rows = [su.scenario_row(sc, m) for sc, m in rep.per_scenario.items()]
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    scored = [{"scenario": sc, "mode": m.replace("_", " "), "accuracy": s.accuracy}
              for sc, modes in rep.per_scenario.items() for m, s in modes.items() if s.accuracy is not None]
    if scored:
        chart = alt.Chart(pd.DataFrame(scored)).mark_bar().encode(
            y=alt.Y("scenario:N", title=None, axis=alt.Axis(labelLimit=260)),
            yOffset=alt.YOffset("mode:N"),
            x=alt.X("accuracy:Q", scale=alt.Scale(domain=[0, 1]), axis=alt.Axis(format="%"), title="accuracy"),
            color=alt.Color("mode:N", scale=alt.Scale(domain=["without context", "with context"],
                                                      range=["#98a2b3", "#155eef"])),
            tooltip=["scenario", "mode", alt.Tooltip("accuracy:Q", format=".0%")],
        ).properties(height=alt.Step(14))
        st.altair_chart(chart, width="stretch")
    elif rep.no_llm:
        st.caption("No verdicts in a no-LLM run, so there is no accuracy chart.")

    st.subheader("Details")
    for o in rep.repos:
        with st.expander(f"{o.name} · {su.repo_row(o)['status']}"):
            st.caption(o.url + (f" · result `{o.result_file}`" if o.result_file else ""))
            if o.error:
                st.error(o.error)
            if o.report:
                deterministic_scores(o.report)
                if o.report.unlabelled_in_scan and o.analyze:
                    st.warning("In the scan but not labelled: " + ", ".join(o.report.unlabelled_in_scan))
                if o.report.rows:
                    mark = {True: "✓", False: "✗", None: "–"}
                    st.dataframe(pd.DataFrame([{
                        "id": r.id, "scenario": r.scenario, "expected": r.expected,
                        "without context": f"{r.without_context} {mark[r.match_without_context]}",
                        "with context": f"{r.with_context} {mark[r.match_with_context]}"} for r in o.report.rows]),
                        hide_index=True, width="stretch")
    st.download_button("Suite report (Markdown)", su.to_markdown(rep), file_name=picked.with_suffix(".md").name,
                       mime="text/markdown")
