"""Orchestrator: runs the agents and keeps results/<slug>_<timestamp>.json up to date.

scan()           Step 1: RepoMapper -> CVEMatcher -> UsageLocator -> repo structure (all deterministic)
build_context()  Step 2: RepoContextAgent's LLM summary (optional; one short LLM call)
analyze()        Step 3: one vulnerability, method "stepwise" (StepwiseAgent: six gates, mostly code) or
                 "holistic" (ExploitabilityAgent: one LLM call over the usage snippets; the baseline)

Every step saves the result file atomically (temp file + rename), so a crash never leaves a
half-written JSON behind.
"""

import os
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import git

from depscan.agents.cve_matcher import CVEMatcherAgent
from depscan.agents.repo_mapper import RepoMapperAgent
from depscan.agents.usage_locator import UsageLocatorAgent
from depscan.config import Config, load_config
from depscan.errors import CloneError, NotFound
from depscan.models import (
    CVEMatcherInput, ScanResult, StageTiming, UsageLocatorInput,
)
from depscan.osv import OSVClient

Progress = Callable[[str, str, float], None]   # (stage, message, fraction 0..1)
SCAN_STAGES = ["cloning", "dependencies", "vulnerabilities", "usages"]


def _noop(stage: str, message: str, fraction: float) -> None:
    pass


def now() -> datetime:
    return datetime.now(timezone.utc)


def write_atomic(path: Path, text: str) -> Path:
    """Write via a temp file + rename, so readers never see a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    for attempt in range(10):          # Windows: the target may be briefly open in another process
        try:
            os.replace(tmp, path)
            break
        except PermissionError:
            if attempt == 9:
                raise
            time.sleep(0.2)
    return path


class Orchestrator:
    def __init__(self, cfg: Config | None = None, llm=None, osv_client: OSVClient | None = None):
        self.cfg = cfg or load_config()
        self._llm = llm                  # injected in tests; created lazily otherwise
        self._osv_client = osv_client

    # ------------------------------------------------------------ persistence

    def save(self, result: ScanResult) -> Path:
        self.cfg.results.mkdir(parents=True, exist_ok=True)
        if not result.result_file:
            stamp = result.created_at.strftime("%Y%m%d-%H%M%S")
            base = f"{result.repo.slug or result.repo.repo_name}_{stamp}"
            path, n = self.cfg.results / f"{base}.json", 1
            while path.exists():                      # two scans in the same second must not overwrite each other
                n += 1
                path = self.cfg.results / f"{base}-{n}.json"
            result.result_file = str(path)
        path = Path(result.result_file)
        result.updated_at = now()
        return write_atomic(path, result.model_dump_json(indent=2))

    @staticmethod
    def load(path: str | Path) -> ScanResult:
        result = ScanResult.model_validate_json(Path(path).read_text(encoding="utf-8"))
        result.result_file = str(Path(path).resolve())
        return result

    def list_results(self) -> list[Path]:
        if not self.cfg.results.exists():
            return []
        return sorted((p for p in self.cfg.results.glob("*.json") if "_eval_" not in p.name),
                      key=lambda p: p.stat().st_mtime, reverse=True)

    def config_snapshot(self) -> dict:
        llm, osv = self.cfg.llm, self.cfg.osv
        return {"llm": {"base_url": llm.base_url, "model": llm.model, "temperature": llm.temperature,
                        "reasoning_effort": llm.reasoning_effort, "max_context_tokens": llm.max_context_tokens},
                "osv": {"base_url": osv.base_url, "offline": osv.offline, "cache_ttl_hours": osv.cache_ttl_hours}}

    # ------------------------------------------------------------ step 1

    def scan(self, url: str, progress: Progress = _noop) -> ScanResult:
        timings: list[StageTiming] = []
        warnings: list[str] = []

        def stage(name: str, fraction: float, message: str, fn):
            progress(name, message, fraction)
            t = time.perf_counter()
            value = fn()
            timings.append(StageTiming(stage=name, seconds=round(time.perf_counter() - t, 2)))
            return value

        mapper = RepoMapperAgent(self.cfg.workspace)
        try:
            path, name, slug = stage("cloning", 0.0, f"Fetching {url}", lambda: mapper.fetch(url, warnings))
        except git.GitCommandError as e:
            raise CloneError(f"Could not clone {url}. Check the URL and your network connection.",
                             detail=str(e)) from e
        except RuntimeError as e:
            raise CloneError(str(e)) from e
        repo = stage("dependencies", 0.25, "Reading manifests",
                     lambda: mapper.map(url, path, name, slug, warnings))
        matcher = CVEMatcherAgent(self._osv(), self.cfg.osv.max_workers)
        matched = stage("vulnerabilities", 0.5, f"Querying OSV for {len(repo.dependencies)} dependencies",
                        lambda: matcher.run(CVEMatcherInput(dependencies=repo.dependencies)))
        located = stage("usages", 0.75, f"Locating usage of {len(matched.results)} vulnerable dependencies",
                        lambda: UsageLocatorAgent(self.packages()).run(
                            UsageLocatorInput(repo_map=repo, vulnerable=matched.results)))

        result = ScanResult(created_at=now(), repo=repo, vulnerabilities=matched.results, usages=located.usages,
                            parse_failures=located.parse_failures, timings=timings,
                            warnings=warnings + matched.log, cache=matched.cache, config=self.config_snapshot())
        # The deterministic part of the repo context (app type, entry points, input sources) is cheap: always run it.
        # Only its LLM summary stays optional (build_context).
        from depscan.agents.repo_context import RepoContextAgent
        result.repo_context = RepoContextAgent(None).run(result)
        progress("done", "Scan complete", 1.0)
        self.save(result)
        return result

    def _osv(self) -> OSVClient:
        if self._osv_client is not None:
            return self._osv_client
        from depscan.cache import ResponseCache
        cache = ResponseCache(self.cfg.cache_path, ttl_seconds=self.cfg.osv.cache_ttl_hours * 3600)
        return OSVClient(cache, base_url=self.cfg.osv.base_url, offline=self.cfg.osv.offline,
                         timeout=self.cfg.osv.timeout_seconds, retries=self.cfg.osv.retries)

    # ------------------------------------------------------------ steps 2 and 3

    def llm(self):
        """The client of the selected profile (cfg.llm)."""
        if self._llm is None:
            from depscan.llm.client import LLMClient
            self._llm = LLMClient(self.cfg.llm, log_path=self.cfg.logs / "llm_calls.jsonl",
                                  response_cache=self._http_cache())
        return self._llm

    def llm_status(self) -> str:
        """What any LLM client is waiting for right now ("waiting for rate limit (12s)"), else ""."""
        clients = [self._llm, *self.__dict__.get("_llms", {}).values()]
        return next((c.status for c in clients if c is not None and getattr(c, "status", "")), "")

    def llm_for(self, profile: str):
        """The client of another profile (e.g. gemini for writing trigger specs), made once."""
        if profile == self.cfg.llm.profile:
            return self.llm()
        clients = self.__dict__.setdefault("_llms", {})
        if profile not in clients:
            from depscan.llm.client import LLMClient
            if profile not in self.cfg.profiles:
                raise NotFound(f"No LLM profile {profile!r} in config.toml.")
            clients[profile] = LLMClient(self.cfg.profiles[profile], log_path=self.cfg.logs / "llm_calls.jsonl",
                                         response_cache=self._http_cache())
        return clients[profile]

    def build_context(self, result: ScanResult, progress: Progress = _noop) -> ScanResult:
        from depscan.agents.repo_context import RepoContextAgent
        progress("context", "Summarising the repository", 0.0)
        t = time.perf_counter()
        result.repo_context = RepoContextAgent(self.llm()).run(result)
        result.timings = [x for x in result.timings if x.stage != "context"]
        result.timings.append(StageTiming(stage="context", seconds=round(time.perf_counter() - t, 2)))
        progress("done", "Repo context ready", 1.0)
        self.save(result)
        return result

    def _http_cache(self):
        from depscan.cache import ResponseCache
        if getattr(self, "_http", None) is None:
            self._http = ResponseCache(self.cfg.cache_path, ttl_seconds=self.cfg.osv.cache_ttl_hours * 3600)
        return self._http

    def packages(self):
        """PyPI release files of exact versions (import names, API index), or None when [grounding] pypi is off."""
        from depscan.grounding import PackageSource
        if not self.cfg.grounding.pypi:
            return None
        if getattr(self, "_packages", None) is None:
            self._packages = PackageSource(self.cfg.cache, self._http_cache(), offline=self.cfg.osv.offline)
        return self._packages

    def triggers(self, variant: str | None = None):
        """The trigger-spec store of one variant (default: [grounding] spec_variant)."""
        from depscan.triggers import TriggerStore
        variant = variant or self.cfg.grounding.spec_variant
        stores = self.__dict__.setdefault("_triggers", {})
        if variant not in stores:
            # "gemini" / "gemini+facts": the spec is written by that profile, whatever answers the narrow questions
            base = variant.split("+", 1)[0]
            spec_llm = self.llm_for(base) if base != "llm" and base in self.cfg.profiles else None
            stores[variant] = TriggerStore(self.cfg.cache, self.cfg.overrides, self._http_cache(),
                                           offline=self.cfg.osv.offline, variant=variant, source=self.packages(),
                                           spec_llm=spec_llm)
        return stores[variant]

    def code_index(self, result: ScanResult):
        """CodeIndex of the scanned clone, built once per result."""
        from depscan.codeindex import CodeIndex
        root = Path(result.repo.local_path)
        if not root.exists():
            raise NotFound(f"The scanned files are no longer at {root}. Scan the repository again.")
        key = (str(root), result.repo.commit, tuple(result.repo.source_files))
        cached = getattr(self, "_index", None)
        if cached is None or cached[0] != key:
            app_type = result.repo_context.app_type if result.repo_context else "unknown"
            self._index = (key, CodeIndex(root, result.repo.source_files, app_type))
        return self._index[1]

    def analyze(self, result: ScanResult, vuln_id: str, use_context: bool = False,
                dependency: str | None = None, method: str = "holistic",
                spec_variant: str | None = None) -> ScanResult:
        """Check every (dependency, vulnerability) matching vuln_id with one method; appends a verdict."""
        hits = result.find(vuln_id, dependency)
        if not hits:
            raise NotFound(f"No vulnerability {vuln_id!r}" + (f" for {dependency}" if dependency else "")
                           + " in this result.")
        if method == "stepwise":
            from depscan.agents.stepwise import StepwiseAgent
            agent = StepwiseAgent(self.triggers(spec_variant), self.code_index(result), self.llm())
            for dv, vuln in hits:
                vuln.verdicts.append(agent.run(result, dv, vuln))
                self.save(result)
            return result
        if use_context and result.repo_context is None:
            raise NotFound("Repo context has not been generated yet (run step 2 first).")
        from depscan.agents.exploitability import ExploitabilityAgent
        agent = ExploitabilityAgent(self.llm(), self.cfg.llm)
        for dv, vuln in hits:
            vuln.verdicts.append(agent.run(result, dv, vuln, use_context))
            self.save(result)              # after each one, so an interruption loses nothing
        return result
