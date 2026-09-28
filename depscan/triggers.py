"""Trigger specs: what must a program do for ONE advisory to matter? (stepwise gate 2)

A spec is produced once per vulnerability id by the LLM from the advisory text and an excerpt of the fix diff,
independent of any repository, and cached in cache/triggers/<id>.json. A human-written
overrides/triggers/<id>.yaml (same fields) always wins and is marked "human" in the UI.

Only the fix diff is downloaded (GitHub/GitLab `.diff` of the FIX references); repository code is never sent.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
import yaml
from pydantic import ValidationError

from depscan import __version__
from depscan.cache import ResponseCache
from depscan.errors import DepscanError
from depscan.llm.prompts import SPEC_SYSTEM, spec_prompt
from depscan.models import TriggerSpec, TriggerSpecLLM, Vulnerability

DIFF_BUDGET = 2400            # characters of diff shown to the model
MAX_DIFF_BYTES = 400_000
DIFF_TTL = 10 * 365 * 24 * 3600   # a commit's diff never changes
SKIP_FILE = re.compile(r"(^|/)(tests?|testing|docs?|examples?|\.github|benchmarks?)/|(^|/)test_[^/]*$|_test\.py$|"
                       r"(CHANGE|HISTORY|NEWS|README|AUTHORS|SECURITY)[^/]*$|\.(md|rst|txt|cfg|toml|ini|lock|json|"
                       r"ya?ml)$|(^|/)(setup\.py|version\.py|_version\.py|__about__\.py)$", re.I)
SOURCE_FILE = re.compile(r"\.(py|pyx|pxd|c|h|cc|cpp|rs)$")


def diff_url(url: str) -> str | None:
    """The .diff URL for a GitHub/GitLab commit or pull request reference, else None."""
    url = url.split("#")[0].rstrip("/")
    m = re.match(r"https://github\.com/([\w.-]+)/([\w.-]+)/pull/\d+/commits/([0-9a-f]{7,40})$", url)
    if m:
        return f"https://github.com/{m[1]}/{m[2]}/commit/{m[3]}.diff"
    m = re.match(r"https://github\.com/([\w.-]+)/([\w.-]+)/(commit/[0-9a-f]{7,40}|pull/\d+)$", url)
    if m:
        return f"https://github.com/{m[1]}/{m[2]}/{m[3]}.diff"
    m = re.match(r"https://gitlab\.com/(.+)/-/commit/([0-9a-f]{7,40})$", url)
    if m:
        return f"https://gitlab.com/{m[1]}/-/commit/{m[2]}.diff"
    return None


def fix_diff_urls(vuln: Vulnerability, limit: int = 2) -> list[tuple[str, str]]:
    """(reference, diff url) for the fix commits first, then pull requests; FIX-typed references first."""
    refs = list(dict.fromkeys(vuln.fix_references + [r for r in vuln.references if "/commit/" in r or "/pull/" in r]))
    out = [(r, d) for r in refs if (d := diff_url(r))]
    out.sort(key=lambda x: "/pull/" in x[1])
    return out[:limit]


def trim_diff(text: str, budget: int = DIFF_BUDGET) -> str:
    """Only changed lines of source files (no tests, docs, changelogs), each file capped, the whole within budget."""
    files = re.split(r"^diff --git ", text, flags=re.M)
    kept: list[tuple[int, str]] = []
    for chunk in files[1:]:
        header = chunk.split("\n", 1)[0]
        m = re.match(r"a/(\S+) b/(\S+)", header)
        path = m[2] if m else header.strip()
        if SKIP_FILE.search(path) or not SOURCE_FILE.search(path):
            continue
        body = []
        for line in chunk.split("\n")[1:]:
            if line.startswith(("+++", "---", "index ", "new file", "deleted file", "similarity", "rename")):
                continue
            if line.startswith("@@"):
                body.append(re.sub(r"^@@[^@]*@@\s*", "@@ ", line))
            elif line.startswith(("+", "-")) and line[1:].strip():
                body.append(line)
        if body:
            block = f"### {path}\n" + "\n".join(body)
            kept.append((0 if path.endswith(".py") else 1, block[:1400]))
    out, used = [], 0
    for _, block in sorted(kept, key=lambda x: x[0]):
        if used + len(block) > budget:
            if budget - used > 300:
                out.append(block[:budget - used] + "\n…")
            break
        out.append(block)
        used += len(block)
    return "\n".join(out)


class TriggerStore:
    """Cached, overridable trigger specs."""

    def __init__(self, cache_dir: Path, overrides_dir: Path, http_cache: ResponseCache | None = None,
                 offline: bool = False, transport: httpx.BaseTransport | None = None, variant: str = "llm",
                 source=None, spec_llm=None):
        """variant "llm": specs from the advisory and the fix diff (cache/triggers/). A "+facts" variant also puts
        facts from the package's API index into the prompt and validates the symbols against it (source: a
        grounding.PackageSource); each variant has its own cache folder, so they can be compared."""
        self.variant = variant
        folder = "triggers" if variant == "llm" else "triggers__" + re.sub(r"[^A-Za-z0-9]+", "_", variant).strip("_")
        self.cache_dir = Path(cache_dir) / folder
        self.source = source
        self.spec_llm = spec_llm          # writes this variant's specs (e.g. the gemini profile); else the caller's
        self.overrides_dir = Path(overrides_dir) / "triggers"
        self.http_cache = http_cache
        self.offline = offline
        self.transport = transport
        self.log: list[str] = []

    @property
    def grounded(self) -> bool:
        return self.variant.endswith("+facts")

    @staticmethod
    def _safe(vuln_id: str) -> str:
        return re.sub(r"[^\w.-]", "_", vuln_id)

    def _ids(self, vuln: Vulnerability) -> list[str]:
        return [vuln.id, *vuln.aliases]

    def override(self, vuln: Vulnerability, package: str) -> TriggerSpec | None:
        for i in self._ids(vuln):
            path = self.overrides_dir / f"{self._safe(i)}.yaml"
            if path.exists():
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                if data.get("package") and data["package"].lower() != package:
                    continue
                data = {k: v for k, v in data.items() if k not in ("package", "vuln_id", "source")}
                return TriggerSpec(**TriggerSpecLLM.model_validate(data).model_dump(), vuln_id=vuln.id,
                                   package=package, source="human", created_at=datetime.now(timezone.utc))
        return None

    def cache_path(self, vuln: Vulnerability, package: str) -> Path:
        return self.cache_dir / f"{self._safe(vuln.id)}__{package}.json"

    def cached(self, vuln: Vulnerability, package: str) -> TriggerSpec | None:
        path = self.cache_path(vuln, package)
        if not path.exists():
            return None
        try:
            return TriggerSpec.model_validate_json(path.read_text(encoding="utf-8"))
        except ValidationError:
            return None

    def get(self, vuln: Vulnerability, package: str, llm=None,
            version: str | None = None) -> tuple[TriggerSpec | None, bool, str]:
        """(spec, generated_now, problem). The override wins, then the cache, then one LLM call (if llm given).
        version: the installed version, whose API index grounds a "+facts" spec."""
        spec = self.override(vuln, package) or self.cached(vuln, package)
        llm = self.spec_llm or llm
        if spec is not None or llm is None:
            return spec, False, "" if spec else "no trigger spec yet"
        try:
            spec = self.generate(vuln, package, llm, version)
        except DepscanError as e:
            return None, True, e.message
        return spec, True, ""

    def generate(self, vuln: Vulnerability, package: str, llm, version: str | None = None) -> TriggerSpec:
        diffs, used, raw = [], [], []
        for ref, url in fix_diff_urls(vuln):
            text = self.fetch_diff(url)
            raw.append(text or "")
            trimmed = trim_diff(text, DIFF_BUDGET - sum(len(d) for d in diffs)) if text else ""
            if trimmed:
                diffs.append(f"(from {ref})\n{trimmed}")
                used.append(ref)
            if sum(len(d) for d in diffs) > DIFF_BUDGET - 300:
                break
        facts, changed, idx = "", [], None
        if self.grounded and self.source is not None:
            from depscan.grounding import api_excerpt
            idx = self.source.index(package, version)
            if idx is not None:
                facts, changed = api_excerpt(idx, vuln, "\n".join(raw))
        parsed, meta = llm.complete_json("TriggerSpec", SPEC_SYSTEM,
                                         spec_prompt(vuln, package, "\n\n".join(diffs), facts),
                                         TriggerSpecLLM, max_tokens=1100)
        spec = TriggerSpec(**parsed.model_dump(), vuln_id=vuln.id, package=package, source="llm", model=llm.model,
                           provider=llm.cfg.profile,
                           diff_used=used, created_at=datetime.now(timezone.utc), variant=self.variant,
                           changed_functions=changed)
        if self.grounded:
            from depscan.grounding import validate_spec
            spec = validate_spec(spec, idx)
        path = self.cache_path(vuln, package)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(spec.model_dump_json(indent=2), encoding="utf-8")
        return spec

    def fetch_diff(self, url: str) -> str:
        key = f"diff:{url}"
        if self.http_cache is not None:
            hit = self.http_cache.get(key)
            if hit:
                return hit[0].get("text", "")
        if self.offline:
            self.log.append(f"offline: fix diff not cached ({url})")
            return ""
        try:
            with httpx.Client(follow_redirects=True, timeout=20, transport=self.transport,
                              headers={"User-Agent": f"depscan/{__version__}"}) as client:
                resp = client.get(url)
            if resp.status_code != 200:
                self.log.append(f"fix diff {url}: HTTP {resp.status_code}")
                return ""
            text = resp.text[:MAX_DIFF_BYTES]
        except httpx.HTTPError as e:
            self.log.append(f"fix diff {url}: {type(e).__name__}")
            return ""
        if self.http_cache is not None:
            self.http_cache.put(key, {"text": text})
        return text


def spec_as_yaml(spec: TriggerSpec) -> str:
    """The spec as an override file a human can edit (overrides/triggers/<id>.yaml)."""
    data = json.loads(spec.model_dump_json(include=set(TriggerSpecLLM.model_fields)))
    return yaml.safe_dump({"package": spec.package, **data}, sort_keys=False, allow_unicode=True)
