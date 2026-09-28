"""Session state shared by the Check and Advanced pages (the scan result, the settings, one Orchestrator)."""

import copy

import streamlit as st

from depscan.config import load_config
from depscan.orchestrator import Orchestrator

BASE_CFG = load_config()
PRIVACY_NOTICE = ("Free-tier cloud APIs may use submitted code and prompts to improve their products, and humans may "
                  "review them. Don't use this for private code.")


def init() -> None:
    ss = st.session_state
    ss.setdefault("llm_profile", BASE_CFG.llm.profile)
    ss.setdefault("llm_base_url", BASE_CFG.llm.base_url)
    ss.setdefault("llm_model", BASE_CFG.llm.model)
    ss.setdefault("offline", BASE_CFG.osv.offline)
    ss.setdefault("cloud_ok", False)          # the privacy notice was confirmed in this session
    # Widget keys are dropped when their page is not shown; keep the settings in plain keys as well.
    for k in ("llm_profile", "llm_base_url", "llm_model", "offline"):
        ss[k] = ss[k]


def is_cloud(profile: str) -> bool:
    return bool(BASE_CFG.profiles.get(profile) and BASE_CFG.profiles[profile].cloud)


def active_profile() -> str:
    """The selected profile, or the local default while a cloud profile's privacy notice is not yet confirmed."""
    ss = st.session_state
    if is_cloud(ss.llm_profile) and not ss.get("cloud_ok"):
        return next((n for n, p in BASE_CFG.profiles.items() if not p.cloud), BASE_CFG.llm.profile)
    return ss.llm_profile


def use_profile(name: str) -> None:
    """Switch the settings to a profile's own base URL and model."""
    ss = st.session_state
    p = BASE_CFG.profiles[name]
    ss["llm_profile"], ss["llm_base_url"], ss["llm_model"] = name, p.base_url, p.model


def orchestrator() -> Orchestrator:
    """One Orchestrator per settings combination, kept for the session (reuses the LLM client)."""
    ss = st.session_state
    profile = active_profile()
    base_url, model = (ss.llm_base_url, ss.llm_model) if profile == ss.llm_profile else \
        (BASE_CFG.profiles[profile].base_url, BASE_CFG.profiles[profile].model) if profile in BASE_CFG.profiles else \
        (ss.llm_base_url, ss.llm_model)
    key = (profile, base_url, model, ss.offline)
    if ss.get("_orch_key") != key:
        cfg = BASE_CFG.with_profile(profile) if profile in BASE_CFG.profiles else copy.deepcopy(BASE_CFG)
        cfg.llm.base_url, cfg.llm.model, cfg.osv.offline = base_url, model, ss.offline
        ss["_orch"], ss["_orch_key"] = Orchestrator(cfg), key
    return ss["_orch"]
