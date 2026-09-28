"""Advanced page: everything behind the Check page (dependency table, usage sites, repo context, holistic analysis
with and without context, verdict history, evaluation, suite, LLM settings, offline mode, exports).

Scan -> Repo context (optional) -> Analyze. The UI only renders and calls the Orchestrator.
"""

from pathlib import Path

import streamlit as st

from depscan.errors import DepscanError
from depscan.evaluate import default_expected_path, expected_index, load_expected_file
from depscan.orchestrator import Orchestrator
from depscan.ui import components as ui
from depscan.ui.export import to_csv, to_markdown
from depscan.ui.filters import KINDS, SCOPES, SEVERITIES, USAGE, Filters
from depscan.ui import state
from depscan.ui.state import orchestrator

state.init()
ss = st.session_state


# ---------------------------------------------------------------- sidebar

with st.sidebar:
    st.title("🛡️ depscan")
    page = st.radio("View", ["Scan & analyze", "Suite"], horizontal=True, key="adv_view", label_visibility="collapsed")
if page == "Suite":
    ui.suite_page(orchestrator().cfg.results)
    st.stop()

with st.sidebar:
    files = orchestrator().list_results()
    st.subheader("Load previous result")
    if files:
        picked = st.selectbox("Result file", files, format_func=lambda p: p.name, label_visibility="collapsed")
        if st.button("Load", width="stretch"):
            try:
                ss["result"] = Orchestrator.load(picked)
                ss.pop("selected_dep", None)
                st.toast(f"Loaded {picked.name}")
            except Exception as e:  # noqa: BLE001
                ui.show_error(e)
    else:
        st.caption("No saved results yet.")

    st.subheader("LLM")
    names = list(state.BASE_CFG.profiles)
    st.selectbox("Profile", names, key="llm_profile_pick", index=names.index(ss.llm_profile),
                 format_func=lambda n: f"{n} (cloud)" if state.is_cloud(n) else f"{n} (local)",
                 on_change=lambda: state.use_profile(ss.llm_profile_pick))
    if state.is_cloud(ss.llm_profile) and not ss.cloud_ok:
        st.warning(state.PRIVACY_NOTICE)
        if st.button(f"I understand, use {ss.llm_profile}", width="stretch", key="cloud_confirm"):
            ss["cloud_ok"] = True
            st.rerun()
        st.caption(f"Until then, analyses use {state.active_profile()}.")
    st.text_input("Base URL", key="llm_base_url")
    st.text_input("Model", key="llm_model", help='"auto:flash" = the newest stable flash model the provider lists')
    if st.button("Test connection", width="stretch"):
        try:
            client = orchestrator().llm()
            models = client.list_models()
            st.success(f"Connected ({state.active_profile()}). {len(models)} models; using {client.model}.")
            if not ss.llm_model.startswith("auto:") and ss.llm_model not in [m.removeprefix("models/") for m in models]:
                st.warning(f"{ss.llm_model!r} is not in the list (for Ollama: ollama pull {ss.llm_model}).")
        except DepscanError as e:
            ui.show_error(e)
    st.toggle("Offline mode (OSV cache only)", key="offline")

    st.subheader("Filters")
    filters = Filters(
        severities=set(st.multiselect("Severity", SEVERITIES, default=SEVERITIES)),
        scopes=set(st.multiselect("Scope", SCOPES, default=SCOPES)),
        kinds=set(st.multiselect("Kind", KINDS, default=KINDS)),
        hide_fuzz=st.checkbox("Hide fuzz crashes", value=True),
        usage=set(st.multiselect("Usage status", USAGE, default=USAGE)),
        only_unanalyzed=st.checkbox("Only unanalyzed", value=False),
    )

    export_slot = st.container()   # filled at the end of the run, so downloads include this run's verdicts

# ---------------------------------------------------------------- main

st.title("depscan · Advanced")
st.caption("Dependencies → known CVEs (OSV) → where the repo uses them → does it actually matter? (local LLM)")
ui.stepper(ss.get("result"))

st.header("1 · Scan")
c1, c2 = st.columns([5, 1])
url = c1.text_input("GitHub URL or local path", key="scan_url", placeholder="https://github.com/owner/repo",
                    label_visibility="collapsed")
# Messages that only appear during one run go into containers that exist on every run, so the elements below
# keep their positions: otherwise Streamlit remounts them on the next run (flicker, reset tab selection).
scan_slot = st.container()
if c2.button("Scan", type="primary", disabled=not url, width="stretch"):
    with scan_slot, st.status("Scanning…", expanded=True) as status:
        bar = st.progress(0.0)

        def on_progress(stage: str, message: str, fraction: float) -> None:
            status.update(label=f"{stage.capitalize()}: {message}")
            st.write(f"**{stage}** — {message}")
            bar.progress(fraction)

        try:
            ss["result"] = orchestrator().scan(url.strip(), on_progress)
            ss.pop("selected_dep", None)
            total = sum(t.seconds for t in ss["result"].timings)
            status.update(label=f"Scan complete in {total:.1f}s", state="complete", expanded=False)
        except Exception as e:  # noqa: BLE001
            status.update(label="Scan failed", state="error", expanded=True)
            ui.show_error(e)

result = ss.get("result")
if result is None:
    st.info("Scan a repository, or load a previous result from the sidebar.")
    st.stop()

st.caption(f"**{result.repo.repo_name}** @ `{(result.repo.commit or 'local')[:10]}` · {result.repo.repo_url} · "
           + " · ".join(f"{t.stage} {t.seconds:.1f}s" for t in result.timings)
           + f" · OSV cache: {result.cache.hits} hits, {result.cache.fetched} fetched"
           + (f", {result.cache.misses} misses (offline)" if result.cache.misses else ""))

st.header("2 · Repo context (optional)")
has_ctx = result.repo_context is not None
ctx_clicked = st.button("Regenerate repo context" if has_ctx else "Generate repo context",
                        help="Deterministic analysis plus one short LLM call for the summary. Never part of Scan.")
ctx_slot = st.container()
if ctx_clicked:
    orch = orchestrator()  # resolved here: the worker thread cannot read st.session_state
    with ctx_slot:
        try:
            ui.run_with_elapsed(lambda: orch.build_context(result), "Building repo context")
        except Exception as e:  # noqa: BLE001
            ui.show_error(e)
if result.repo_context:
    ui.context_card(result)
else:
    st.caption("Optional. Adds app type, entry points and untrusted input sources as background for step 3.")

with st.container():
    ui.finish_inflight(result)   # an analysis interrupted by a rerun (e.g. batch Stop) is awaited, never repeated

# Known answers (.depscan/expected.yaml in the scanned repo): display only, never passed to the Orchestrator.
expected_path, expected = default_expected_path(result), None
if expected_path.exists():
    try:
        expected = load_expected_file(expected_path)
    except Exception as e:  # noqa: BLE001
        st.warning(f"Could not read {expected_path}: {e}")

tabs = st.tabs(["Analysis", "Evaluation"] if expected else ["Analysis"])
with tabs[0]:
    st.header("Results")
    ui.overview(result)
    if not result.vulnerabilities:
        ui.nothing_found(result)          # clean repo: no table, no analyze controls
    else:
        ui.vulns_chart(result)
        selected = ui.dependency_table(result, filters)
    ui.warnings_panel(result)

    if result.vulnerabilities:
        st.header("3 · Analyze")
        with st.container(border=True):
            st.markdown("**Batch:** analyze every vulnerability that matches the sidebar filters, one at a time.")
            ui.batch_panel(result, filters, orchestrator)
        if selected:
            ui.dependency_detail(result, selected, filters, orchestrator,
                                 expected_index(expected.advisories) if expected else None)
if expected:
    with tabs[1]:
        ui.evaluation_tab(result, expected, expected_path)

# ---------------------------------------------------------------- exports (last, so they include this run's work)

with export_slot:
    st.subheader("Export")
    st.download_button("Result JSON", result.model_dump_json(indent=2),
                       file_name=Path(result.result_file).name if result.result_file else "depscan.json",
                       mime="application/json", width="stretch")
    st.download_button("CSV (deps × vulns × verdict)", to_csv(result), file_name=f"{result.repo.slug}.csv",
                       mime="text/csv", width="stretch")
    st.download_button("Markdown report", to_markdown(result), file_name=f"{result.repo.slug}.md",
                       mime="text/markdown", width="stretch")
