"""Session state shared by the Check and Advanced pages (the scan result, the settings, one Orchestrator)."""

import copy

import streamlit as st

from depscan.config import load_config
from depscan.orchestrator import Orchestrator

BASE_CFG = load_config()


def init() -> None:
    ss = st.session_state
    ss.setdefault("llm_base_url", BASE_CFG.llm.base_url)
    ss.setdefault("llm_model", BASE_CFG.llm.model)
    ss.setdefault("offline", BASE_CFG.osv.offline)
    # Widget keys are dropped when their page is not shown; keep the settings in plain keys as well.
    for k in ("llm_base_url", "llm_model", "offline"):
        ss[k] = ss[k]


def orchestrator() -> Orchestrator:
    """One Orchestrator per settings combination, kept for the session (reuses the LLM client)."""
    ss = st.session_state
    key = (ss.llm_base_url, ss.llm_model, ss.offline)
    if ss.get("_orch_key") != key:
        cfg = copy.deepcopy(BASE_CFG)
        cfg.llm.base_url, cfg.llm.model, cfg.osv.offline = ss.llm_base_url, ss.llm_model, ss.offline
        ss["_orch"], ss["_orch_key"] = Orchestrator(cfg), key
    return ss["_orch"]
