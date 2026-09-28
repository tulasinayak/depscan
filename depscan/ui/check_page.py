"""The Check page: "which of these CVEs actually affect my repo?" Renders only; the Orchestrator does the work."""

import html
import time
from typing import Callable

import pandas as pd
import streamlit as st

from depscan.models import ScanResult
from depscan.orchestrator import Orchestrator
from depscan.ui import plain
from depscan.ui.components import SEV_COLORS, _INFLIGHT, badge, md, run_with_elapsed, show_error

SEVERITY_CHOICES = ["all", "critical", "high", "medium", "low", "unknown"]


def status_pill(status: str) -> str:
    return badge(plain.STATUS_LABEL[status], plain.STATUS_COLORS[status])


def severity_pill(severity: str) -> str:
    return badge(severity, SEV_COLORS.get(severity, SEV_COLORS["unknown"]))


# ---------------------------------------------------------------- scan

def scan_box(orch: Callable[[], Orchestrator]) -> None:
    c1, c2 = st.columns([5, 1])
    url = c1.text_input("Repository", key="check_url", placeholder="GitHub URL or local folder",
                        label_visibility="collapsed")
    slot = st.container()
    if c2.button("Scan", type="primary", disabled=not url, width="stretch", key="check_scan"):
        with slot:
            bar = st.progress(0.0, text="Starting")

            def on_progress(stage: str, message: str, fraction: float) -> None:
                bar.progress(fraction, text=plain.STAGE_WORDS.get(stage, message))

            try:
                st.session_state["result"] = orch().scan(url.strip(), on_progress)
                st.session_state.pop("open_cve", None)
                bar.progress(1.0, text="Done")
            except Exception as e:  # noqa: BLE001 - shown to the user
                bar.empty()
                show_error(e)


# ---------------------------------------------------------------- summary and list

def summary(all_rows: list[plain.Row]) -> None:
    st.markdown(f"#### {plain.summary_sentence(all_rows)}")
    n = plain.status_counts(all_rows)
    for col, s in zip(st.columns(len(plain.STATUSES)), plain.STATUSES):
        col.metric(plain.STATUS_LABEL[s], n[s])


def check_one(result: ScanResult, row: plain.Row, orch: Callable[[], Orchestrator]) -> bool:
    """True when the check finished; on an error it is shown and stays visible (no rerun)."""
    o = orch()                     # resolved in the script thread: the worker thread cannot read session state
    try:
        run_with_elapsed(lambda: o.analyze(result, row.v.id, False, row.dv.dependency.key, method="stepwise"),
                         f"Checking {row.v.id}", track=result.result_file, item=(row.dv.dependency.key, row.v.id), status=o.llm_status)
        return True
    except Exception as e:  # noqa: BLE001
        show_error(e)
        return False


def cve_list(result: ScanResult, all_rows: list[plain.Row], orch: Callable[[], Orchestrator]) -> None:
    f1, f2 = st.columns([1, 1])
    severity = f1.selectbox("Severity", SEVERITY_CHOICES, key="check_sev",
                            format_func=lambda s: "All severities" if s == "all" else s.capitalize())
    hide = f2.checkbox("Hide checked", key="check_hide")
    shown = plain.filter_rows(all_rows, severity, hide)
    pkg = st.session_state.get("check_pkg")
    if pkg:
        shown = [r for r in shown if r.dv.dependency.key == pkg]
        p1, p2 = st.columns([5, 1], vertical_alignment="center")
        p1.markdown(f"Showing only **{html.escape(pkg)}**.")
        if p2.button("Show all", key="check_show_all", type="tertiary"):
            clear_package_filter()
            st.rerun()
    if not shown:
        st.caption(f"No known vulnerabilities in {pkg}." if pkg and not any(r.dv.dependency.key == pkg for r in all_rows)
                   else "Nothing matches these filters.")
    busy = bool(st.session_state.get("check_queue"))
    specs = orch().triggers()
    open_key = st.session_state.get("open_cve")
    for row in shown:
        with st.container(border=True):
            c1, c2, c3, c4 = st.columns([2.2, 6, 1.9, 1.2], vertical_alignment="center")
            with c1:
                md(severity_pill(row.v.cvss.severity))
                if st.button(row.v.id, key=f"open-{row.key}", type="tertiary", help="Show or hide the details"):
                    st.session_state["open_cve"] = None if open_key == row.key else row.key
                    st.rerun()
            spec = specs.override(row.v, row.dv.dependency.name) or specs.cached(row.v, row.dv.dependency.name)
            c2.markdown(f"**{html.escape(row.dv.dependency.name)}@{row.dv.dependency.resolved_version or '?'}** · "
                        f"{html.escape(plain.one_line(plain.what_it_is(row.v, spec)))}")
            with c3:
                md(status_pill(row.status))
            if c4.button("Check" if row.status == "not_checked" else "Re-check", key=f"check-{row.key}",
                         disabled=busy, width="stretch"):
                st.session_state["open_cve"] = row.key
                if check_one(result, row, orch):
                    st.rerun()
        if row.key == open_key:
            detail(result, row, orch)            # opens right under its row, full width


def check_all(result: ScanResult, all_rows: list[plain.Row], orch: Callable[[], Orchestrator]) -> None:
    """One check per script run, then a rerun: the counters and the list update after each check, and Stop
    takes effect before the next one."""
    ss = st.session_state
    todo = [r for r in all_rows if r.status == "not_checked"]
    queue = ss.get("check_queue")
    seconds, measured = plain.check_estimate(result, len(todo))
    c1, c2 = st.columns([1.3, 4], vertical_alignment="center")
    if not queue:
        if c1.button(f"Check all ({len(todo)})", disabled=not todo, key="check_all", width="stretch"):
            ss["check_queue"] = [(r.dv.dependency.key, r.v.id) for r in todo]
            ss["check_total"] = len(todo)
            st.rerun()
        c2.caption(f"{plain.duration_words(seconds).capitalize()} for {len(todo)} unchecked "
                   f"({'from the checks done so far' if measured else 'a rough guess: nothing checked yet'}). "
                   "Each result is saved as soon as it is done, so you can stop at any time.")
        return
    c1.button("⏹ Stop", key="check_stop", width="stretch",
              on_click=lambda: ss.update(check_queue=[]),
              help="Stops after the check in progress; everything finished is already saved.")
    total = max(ss.get("check_total", len(queue)), len(queue))
    done = total - len(queue)
    left, _ = plain.check_estimate(result, len(queue))
    dep, vid = queue[0]
    c2.progress(done / total, text=f"{done} of {total} checked · now checking {vid} · {plain.duration_words(left)} left")
    o = orch()
    try:
        run_with_elapsed(lambda: o.analyze(result, vid, False, dep, method="stepwise"), f"Checking {vid}",
                         track=result.result_file, item=(dep, vid), status=o.llm_status)
    except Exception as e:  # noqa: BLE001
        ss["check_queue"] = []
        show_error(e)
        return
    if ss.get("check_queue"):                  # Stop empties the queue; don't bring it back
        ss["check_queue"] = ss["check_queue"][1:]
    st.rerun()


def finish_running(result: ScanResult) -> None:
    """A check started by a run that was interrupted (Stop, or any click) is awaited, never started twice."""
    entry = _INFLIGHT.get(result.result_file or "")
    if not entry:
        return
    future, item, label = entry
    note = st.empty()
    start = time.time()
    while not future.done():
        note.info(f"⏳ Finishing {label}, which was already running · {int(time.time() - start)}s")
        time.sleep(0.5)
    note.empty()
    _INFLIGHT.pop(result.result_file or "", None)
    queue = st.session_state.get("check_queue")
    if item and queue and tuple(queue[0]) == tuple(item):
        st.session_state["check_queue"] = queue[1:]


# ---------------------------------------------------------------- problems worth telling the user

LOOKUP_FAILED = ("OSV query failed", "OSV fetch failed", "OSV unreachable", "offline: no cached")
LIMITS = ("very large", "over the size limit", "symbolic link", "outside the repository")


def notices(result: ScanResult, all_rows: list[plain.Row]) -> None:
    """Plain warnings for problems that make the answer incomplete; the details stay one click away."""
    failed = [w for w in result.warnings if any(k in w for k in LOOKUP_FAILED)]
    if failed:
        st.warning("Some known-vulnerability lookups failed (the vulnerability database could not be reached, or "
                   "offline mode had no saved answer), so this list may be incomplete. Scan again when online.")
        with st.expander(f"Details ({len(failed)})"):
            st.code("\n".join(failed[:50]), language=None)
    if not result.repo.dependencies:
        st.info("No dependency files were found (requirements*.txt, pyproject.toml, Pipfile, poetry.lock, "
                "Pipfile.lock, uv.lock), so there is nothing to check.")
    unreachable = [r for r in all_rows if r.record and any("Cannot reach the LLM" in g.explanation
                                                           for g in r.record.gates)]
    if unreachable:
        st.warning(f"The AI model could not be reached during {len(unreachable)} check"
                   f"{'s' if len(unreachable) != 1 else ''}, so steps that needed it stayed open (Needs review). "
                   "Start Ollama, or pick another model on the Advanced page, then press Re-check.")
    limited = [w for w in result.warnings if any(k in w for k in LIMITS)]
    if limited:
        st.caption("Some files were not read: " + " ".join(limited[:3]))


# ---------------------------------------------------------------- dependencies found

def clear_package_filter() -> None:
    st.session_state.pop("check_pkg", None)
    st.session_state.pop("_deps_picked", None)
    st.session_state["check_deps_ver"] = st.session_state.get("check_deps_ver", 0) + 1   # resets the selection


def dependencies(result: ScanResult, all_rows: list[plain.Row]) -> None:
    cache_key = (result.result_file, result.repo.commit, len(result.repo.dependencies))
    if st.session_state.get("_usages_key") != cache_key:
        st.session_state["_usages"], st.session_state["_usages_key"] = plain.all_usages(result), cache_key
    deps = plain.dependency_rows(result, all_rows, st.session_state["_usages"])
    with st.expander(f"Dependencies found ({len(deps)})", expanded=True):
        if not deps:
            st.caption("No dependency files were found.")
            return
        st.caption("Click a package to show only its vulnerabilities below.")
        table = pd.DataFrame([{"Package": d.package, "Version": d.version, "How it's used": d.usage,
                               "Known vulnerabilities": d.vulns or "none known", "Checks": d.checks}
                              for d in deps]).astype(str)
        event = st.dataframe(table, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                             key=f"check_deps_{st.session_state.get('check_deps_ver', 0)}",
                             height=min(38 + 35 * len(deps), 400))
        picked = event.selection.rows if event and event.selection else []
        key = deps[picked[0]].key if picked else None
        if key != st.session_state.get("_deps_picked"):      # act on a change of selection only
            st.session_state["_deps_picked"] = key
            if key:
                st.session_state["check_pkg"] = key
                st.session_state.pop("open_cve", None)
            else:
                st.session_state.pop("check_pkg", None)


# ---------------------------------------------------------------- detail panel

def detail(result: ScanResult, row: plain.Row, orch: Callable[[], Orchestrator]) -> None:
    dv, v, rec = row.dv, row.v, row.record
    spec_store = orch().triggers()
    spec = spec_store.override(v, dv.dependency.name) or spec_store.cached(v, dv.dependency.name)
    with st.container(border=True, key="cve_detail"):
        top1, top2 = st.columns([6, 1])
        top1.caption(f"{v.id} · {dv.dependency.name} {dv.dependency.resolved_version or ''} · "
                     f"{plain.how_used(result, dv, v)}")
        if top2.button("✕ Close", key="close_detail", type="tertiary"):
            st.session_state.pop("open_cve", None)
            st.rerun()
        headline, reason = plain.verdict_line(row.status, rec)
        color = plain.STATUS_COLORS[row.status][0]
        md(f'<div style="font-size:2rem;font-weight:700;color:{color};line-height:1.2">{html.escape(headline)}</div>')
        st.markdown(reason)
        if row.status == "probably_not_affected":
            st.warning(plain.PROBABLY_NOTE)

        st.markdown("##### What this vulnerability is")
        st.markdown(plain.what_it_is(v, spec))

        if rec is not None and rec.gates:
            st.markdown("##### The checklist")
            for mark, label, explanation, by, g in plain.gate_rows(rec):
                with st.expander(f"{mark}  **{label}** · {explanation}"):
                    st.caption(by)
                    if not g.evidence:
                        st.caption("No further evidence recorded.")
                    for e in g.evidence:
                        st.markdown(f"- {e.text}" + (f"  \n  `{e.citation}`" if e.citation else ""))
                        code = plain.code_lines(result, e.citation)
                        if code:
                            st.code(code[0], language="python")

        st.markdown("##### What to do")
        advice, show_cmd = plain.what_to_do(row.status, dv, v, rec)
        st.markdown(advice)
        cmds = plain.upgrade_commands(dv, v)
        if show_cmd and cmds:
            st.code(cmds[0], language="bash")
            st.code(cmds[1], language="bash")
        if rec is not None:
            st.caption(plain.small_print(rec))


# ---------------------------------------------------------------- page

def page(orch: Callable[[], Orchestrator]) -> None:
    st.title("🛡️ Which of these vulnerabilities affect my repo?")
    scan_box(orch)
    result: ScanResult | None = st.session_state.get("result")
    if result is None:
        st.caption("Paste a GitHub URL or a local folder and press Scan. Nothing from the repository is run.")
        return
    st.caption(f"{result.repo.repo_name} @ {(result.repo.commit or 'local')[:10]}")
    finish_running(result)
    all_rows = plain.rows(result)
    summary(all_rows)
    notices(result, all_rows)
    if not all_rows:
        dependencies(result, all_rows)
        return
    dependencies(result, all_rows)
    check_all(result, all_rows, orch)
    cve_list(result, all_rows, orch)
