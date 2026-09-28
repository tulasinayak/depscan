import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class LLMConfig:
    base_url: str = "http://localhost:11434/v1"
    model: str = "qwen3:8b"
    api_key: str = "ollama"
    # "none" turns off qwen3's thinking through the OpenAI-compatible API (much faster on CPU).
    # Set to "" to not send the parameter (for endpoints that reject it).
    reasoning_effort: str = "none"
    json_mode: bool = True             # response_format={"type": "json_object"}
    temperature: float = 0.1
    timeout_seconds: int = 900
    # The model's context window. Ollama's OpenAI-compatible endpoint uses the server default (4096)
    # unless the server is started with OLLAMA_CONTEXT_LENGTH; prompts are trimmed to fit.
    max_context_tokens: int = 4096
    max_output_tokens: int = 900
    profile: str = "local_qwen"          # which [llm.profiles.<name>] this is
    # Name of an environment variable holding the key (e.g. GEMINI_API_KEY). The key itself is read from the
    # environment when the client is made and never stored in the config, a result, a cache or a log.
    api_key_env: str = ""
    cloud: bool = False                  # the provider is a remote service: repo code sent to it needs consent
    requests_per_minute: float = 0       # 0 = no limit
    tokens_per_minute: float = 0         # prompt + max output tokens, estimated; 0 = no limit
    cache_responses: bool = False        # replay identical requests (profile, model, prompt) from the cache
    max_retries_429: int = 6             # HTTP 429: wait (Retry-After, else exponential backoff) and retry


@dataclass
class OSVConfig:
    base_url: str = "https://api.osv.dev"
    cache_ttl_hours: float = 24
    offline: bool = False
    timeout_seconds: float = 30
    retries: int = 3
    max_workers: int = 8


@dataclass
class GroundingConfig:
    # Download each vulnerable package's release from PyPI (cached; never executed) for its import names and
    # API index. Off by default so tests and bare configs never touch the network; config.toml turns it on.
    pypi: bool = False
    # Trigger specs used by the stepwise method: "llm" (the LLM from advisory + fix diff) or "llm+facts" (plus
    # facts from the package's API index in the prompt, validated against it, parent triggers from code).
    spec_variant: str = "llm"


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    osv: OSVConfig = field(default_factory=OSVConfig)
    grounding: GroundingConfig = field(default_factory=GroundingConfig)
    profiles: dict[str, LLMConfig] = field(default_factory=dict)   # [llm.profiles.*]; llm is the selected one

    def with_profile(self, name: str) -> "Config":
        """A copy of this config whose llm is the named profile."""
        import copy
        if name not in self.profiles:
            from depscan.errors import NotFound
            raise NotFound(f"No LLM profile {name!r} in config.toml (have: {', '.join(self.profiles) or 'none'}).")
        cfg = copy.deepcopy(self)
        cfg.llm = copy.deepcopy(self.profiles[name])
        return cfg
    workspace: Path = PROJECT_ROOT / "workspace"
    results: Path = PROJECT_ROOT / "results"
    logs: Path = PROJECT_ROOT / "logs"
    cache: Path = PROJECT_ROOT / "cache"          # cache/triggers/<id>.json: LLM trigger specs
    overrides: Path = PROJECT_ROOT / "overrides"  # overrides/triggers/<id>.yaml: human-reviewed specs (win)

    @property
    def cache_path(self) -> Path:
        return self.workspace / "cache.sqlite"


def load_config(path: Path | None = None) -> Config:
    path = path or Path(os.environ.get("DEPSCAN_CONFIG") or PROJECT_ROOT / "config.toml")
    data = tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    llm_data = {k: v for k, v in data.get("llm", {}).items() if k in LLMConfig.__dataclass_fields__}
    base = LLMConfig(**llm_data)
    # [llm] holds the shared settings; each [llm.profiles.<name>] overrides them. Without profiles, [llm] alone
    # is the "local_qwen" profile.
    profiles = {name: LLMConfig(**{**llm_data, **{k: v for k, v in table.items() if k in LLMConfig.__dataclass_fields__},
                                   "profile": name})
                for name, table in data.get("llm", {}).get("profiles", {}).items()}
    profiles = profiles or {base.profile: base}
    chosen = os.environ.get("DEPSCAN_LLM_PROFILE", data.get("llm", {}).get("default_profile", next(iter(profiles))))
    llm = profiles.get(chosen) or next(iter(profiles.values()))
    llm.base_url = os.environ.get("DEPSCAN_LLM_BASE_URL", llm.base_url)
    llm.model = os.environ.get("DEPSCAN_LLM_MODEL", llm.model)
    llm.api_key = os.environ.get("DEPSCAN_LLM_API_KEY", llm.api_key)
    osv = OSVConfig(**data.get("osv", {}))
    osv.base_url = os.environ.get("DEPSCAN_OSV_BASE_URL", osv.base_url)
    osv.offline = os.environ.get("DEPSCAN_OFFLINE", "1" if osv.offline else "0") == "1"
    osv.max_workers = max(1, min(osv.max_workers, 8))
    paths = data.get("paths", {})

    def resolve(key: str, default: str) -> Path:
        p = Path(paths.get(key, default))
        return p if p.is_absolute() else PROJECT_ROOT / p

    grounding = GroundingConfig(**{k: v for k, v in data.get("grounding", {}).items()
                                   if k in GroundingConfig.__dataclass_fields__})
    return Config(llm=llm, osv=osv, grounding=grounding, profiles=profiles, workspace=resolve("workspace", "workspace"),
                  results=resolve("results", "results"), logs=resolve("logs", "logs"),
                  cache=resolve("cache", "cache"), overrides=resolve("overrides", "overrides"))
