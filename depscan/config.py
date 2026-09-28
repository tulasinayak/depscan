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
    workspace: Path = PROJECT_ROOT / "workspace"
    results: Path = PROJECT_ROOT / "results"
    logs: Path = PROJECT_ROOT / "logs"
    cache: Path = PROJECT_ROOT / "cache"          # cache/triggers/<id>.json: LLM trigger specs
    overrides: Path = PROJECT_ROOT / "overrides"  # overrides/triggers/<id>.yaml: human-reviewed specs (win)

    @property
    def cache_path(self) -> Path:
        return self.workspace / "cache.sqlite"


def load_config(path: Path | None = None) -> Config:
    path = path or PROJECT_ROOT / "config.toml"
    data = tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    llm_data = {k: v for k, v in data.get("llm", {}).items() if k in LLMConfig.__dataclass_fields__}
    llm = LLMConfig(**llm_data)
    llm.base_url = os.environ.get("DEPSCAN_LLM_BASE_URL", llm.base_url)
    llm.model = os.environ.get("DEPSCAN_LLM_MODEL", llm.model)
    llm.api_key = os.environ.get("DEPSCAN_LLM_API_KEY", llm.api_key)
    osv = OSVConfig(**data.get("osv", {}))
    osv.offline = os.environ.get("DEPSCAN_OFFLINE", "1" if osv.offline else "0") == "1"
    osv.max_workers = max(1, min(osv.max_workers, 8))
    paths = data.get("paths", {})

    def resolve(key: str, default: str) -> Path:
        p = Path(paths.get(key, default))
        return p if p.is_absolute() else PROJECT_ROOT / p

    grounding = GroundingConfig(**{k: v for k, v in data.get("grounding", {}).items()
                                   if k in GroundingConfig.__dataclass_fields__})
    return Config(llm=llm, osv=osv, grounding=grounding, workspace=resolve("workspace", "workspace"),
                  results=resolve("results", "results"), logs=resolve("logs", "logs"),
                  cache=resolve("cache", "cache"), overrides=resolve("overrides", "overrides"))
