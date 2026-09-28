"""All pydantic models used by depscan's agents and saved in the result JSON."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "2"
Severity = Literal["critical", "high", "medium", "low", "none", "unknown"]
Verdict = Literal["likely_affected", "likely_not_affected", "uncertain"]
# Stepwise status: not_affected = a gate decided by CODE failed (proven); probably_not_affected = only gates decided
# by an LLM "no" failed; needs_review = something unknown and nothing failed.
Status = Literal["affected", "not_affected", "probably_not_affected", "needs_review"]


# ---------------------------------------------------------------- Step 1: RepoMapper

class Dependency(BaseModel):
    name: str                          # PEP 503 normalised
    version_spec: str | None = None    # as written: "==3.13", ">=2.0", "^1.2" (Poetry)
    resolved_version: str | None = None  # exact pin, constraint pin or lockfile version; never guessed
    unresolved_reason: str | None = None  # why resolved_version is None ("range >=2.0", "editable install ...")
    source_file: str                   # repo-relative manifest path
    direct: bool                       # declared in a manifest vs. only present in a lockfile
    scope: Literal["main", "dev", "unknown"] = "unknown"
    extras: list[str] = []             # pkg[extra1,extra2]
    marker: str | None = None          # environment marker, e.g. 'sys_platform == "win32"'
    required_by: list[str] = []        # packages that depend on this one (from lockfiles that record it)
    ecosystem: Literal["PyPI"] = "PyPI"
    project: str = ""                  # sub-project directory when the repo has several ("services/api"), else ""

    @property
    def key(self) -> str:
        """Unique id of this dependency in a result: the name, or "project:name" in multi-project repos."""
        return f"{self.project}:{self.name}" if self.project else self.name


class RepoMap(BaseModel):
    repo_url: str
    repo_name: str
    slug: str = ""                     # "<owner>__<repo>" (or the folder name for local paths)
    local_path: str
    commit: str | None = None
    source_files: list[str] = []
    manifest_files: list[str] = []
    dependencies: list[Dependency] = []
    warnings: list[str] = []


class RepoMapperInput(BaseModel):
    url: str                           # GitHub URL, or a local directory (used as-is, never modified)


# ---------------------------------------------------------------- Step 1: CVEMatcher

class Cvss(BaseModel):
    vector: str | None = None
    version: str | None = None         # "3.1" | "4.0"
    base_score: float | None = None    # None = no score (never 0 for "missing")
    severity: Severity = "unknown"


GateName = Literal["version_in_range", "trigger_spec", "present", "reachable", "dangerous_form", "attacker_input"]
GATE_ORDER: list[str] = ["version_in_range", "trigger_spec", "present", "reachable", "dangerous_form",
                         "attacker_input"]


class GateEvidence(BaseModel):
    text: str
    citation: str | None = None        # "app/routes.py:12", "advisory", "requirements.txt"
    snippet: str | None = None         # a few numbered source lines


class GateResult(BaseModel):
    """One step of the stepwise check. "fail" (= not affected) only on definite evidence."""
    gate: GateName
    result: Literal["pass", "fail", "unknown"]
    explanation: str                   # one plain-English sentence
    evidence: list[GateEvidence] = []
    decided_by: Literal["code", "llm"] = "code"
    skipped: bool = False              # not evaluated (an earlier gate already decided, or not needed)


class VerdictRecord(BaseModel):
    """One ExploitabilityAgent (holistic) or StepwiseAgent run. Stored append-only on the Vulnerability."""
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list["EvidenceItem"] = []
    inference: list[str] = []
    unknowns: list[str] = []
    recommendation: str = ""
    used_repo_context: bool
    model: str
    llm_called: bool = True            # False for fuzz crashes (fixed answer)
    prompt_tokens_estimate: int = 0
    duration_ms: int = 0
    timestamp: datetime
    dropped_citations: list[str] = []  # evidence citing file:line that is not a real usage site
    notes: list[str] = []              # e.g. "verdict downgraded to uncertain: no valid code citation"
    method: Literal["holistic", "stepwise"] = "holistic"
    gates: list[GateResult] = []       # stepwise only
    reason: str = ""                   # stepwise: the one-sentence reason for the verdict
    llm_calls: int = 1                 # holistic: 1 (0 for fuzz crashes); stepwise: narrow questions (+1 if the spec was generated now)
    spec_source: Literal["llm", "human", "none"] | None = None   # stepwise: where the trigger spec came from
    status: Status | None = None       # stepwise: the four-way status (verdict keeps the 3-way value)
    spec_variant: str | None = None    # stepwise: which trigger specs were used (llm, llm+facts, ...)
    provider: str | None = None        # the LLM profile that answered (local_qwen, gemini, ...)


class EvidenceItem(BaseModel):
    text: str
    citation: str | None = None        # "app/routes.py:12" or "advisory"


VulnKind = Literal["standard", "fuzz_crash", "bundled_native"]


class Vulnerability(BaseModel):
    """One vulnerability, merged from every OSV advisory that shares an alias (GHSA / PYSEC / CVE)."""
    id: str                            # display id: the CVE id if any, else GHSA, else PYSEC/other
    aliases: list[str] = []            # every other id (all merged OSV ids and their aliases)
    cve_ids: list[str] = []
    related_ids: list[str] = []        # not alias-linked, but share a reference URL (linked, not merged)
    kind: VulnKind = "standard"
    summary: str = ""
    details: str = ""
    cvss: Cvss = Cvss()
    affected_ranges: list[str] = []    # ">=0, <5.1"
    fixed_version: str | None = None   # smallest fixed version above the installed one
    references: list[str] = []
    fix_references: list[str] = []     # references OSV marks as type FIX (fix commits / pull requests)
    affected_functions: list[str] = []  # only when OSV provides them; usually empty for PyPI
    advisory_symbols: list[str] = []   # candidate symbols pulled from the advisory text (deterministic)
    match: Literal["affected", "possibly_affected"]
    match_reason: str
    verdicts: list[VerdictRecord] = []  # append-only history, with and without repo context


class DependencyVulns(BaseModel):
    dependency: Dependency
    vulnerabilities: list[Vulnerability]          # standard + bundled_native (the headline list)
    fuzz_crashes: list[Vulnerability] = []        # kind == fuzz_crash: kept separately, not counted by default

    def all_vulns(self) -> list[Vulnerability]:
        return self.vulnerabilities + self.fuzz_crashes


class CVEMatcherInput(BaseModel):
    dependencies: list[Dependency]


class CacheStats(BaseModel):
    hits: int = 0
    stale_hits: int = 0                # expired entries used because offline or the network failed
    misses: int = 0                    # offline mode: requests that could not be answered
    fetched: int = 0


class CVEMatcherOutput(BaseModel):
    results: list[DependencyVulns]     # only dependencies with at least one vulnerability
    log: list[str] = []                # withdrawn advisories, dropped range non-matches, errors, cache misses
    cache: CacheStats = CacheStats()
    offline: bool = False


# ---------------------------------------------------------------- Step 1: UsageLocator

SiteKind = Literal["import", "star_import", "dynamic_import", "call", "attribute", "regex"]


class UsageSite(BaseModel):
    id: str                            # "U0001", stable within a scan
    package: str
    file: str
    line: int
    kind: SiteKind
    symbol: str                        # fully qualified, resolved through aliases: "PIL.Image.open"
    snippet: str | None = None         # ±5 lines with line numbers; None beyond the per-dependency cap
    confidence: Literal["high", "low"] = "high"  # low: dynamic import or regex fallback
    in_test_path: bool = False         # path heuristic, used for ranking only
    matched_vulns: list[str] = []      # vulnerability ids whose advisory_symbols match this site
    via: str | None = None             # for indirect/native-reach sites: why this site is relevant


class DependencyUsage(BaseModel):
    package: str
    import_names: list[str]
    import_name_source: Literal["pypi_metadata", "installed_metadata", "builtin_table", "name_heuristic",
                                "name_heuristic_case"]
    usage_status: Literal["direct_usage", "no_direct_usage", "parse_incomplete"]
    required_by: list[str] = []
    sites: list[UsageSite] = []
    indirect_sites: list[UsageSite] = []       # usage of parent packages (required_by), for no_direct_usage
    native_reach_sites: list[UsageSite] = []   # wrapper APIs that plausibly reach a bundled native library
    note: str = ""


class UsageLocatorInput(BaseModel):
    repo_map: RepoMap
    vulnerable: list[DependencyVulns]


class UsageLocatorOutput(BaseModel):
    usages: dict[str, DependencyUsage]
    parse_failures: list[str] = []     # "file: error"
    files_scanned: int = 0


# ---------------------------------------------------------------- Step 2: RepoContext

class UsageRef(BaseModel):
    file: str
    line: int
    symbol: str                        # "request.get_json", "sys.argv"


class RepoContext(BaseModel):
    app_type: Literal["web_service", "cli", "library", "script", "unknown"]
    frameworks: list[str] = []
    entry_points: list[str] = []
    untrusted_input_sources: list[UsageRef] = []
    usage_contexts: dict[str, Literal["prod", "test", "example", "script"]] = {}  # usage_site_id -> context
    summary: str = ""                  # at most 3 sentences; the only LLM-generated field
    model: str | None = None
    created_at: datetime


# ---------------------------------------------------------------- Step 3: Exploitability (what the LLM must return)

class LLMEvidence(BaseModel):
    text: str
    citation: str | None = None


class ExploitabilityVerdict(BaseModel):
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[LLMEvidence] = []
    inference: list[str] = []
    unknowns: list[str] = []
    recommendation: str


# ---------------------------------------------------------------- Stepwise: trigger spec (what the LLM must return)

class ArgForm(BaseModel):
    """A simple argument pattern: yaml.load(..., Loader=X) is dangerous for X in `dangerous`, safe for X in `safe`."""
    call: str                          # fully qualified function, or a class to cover all its methods
    kwarg: str | None = None
    position: int | None = None        # 0-based positional index of the same argument (None: keyword only)
    dangerous: list[str] = []          # values, matched on the last dotted part: "FullLoader", "False"
    safe: list[str] = []
    when_absent: Literal["dangerous", "safe", "unknown"] = "unknown"


class ParentTrigger(BaseModel):
    """How a package that depends on the vulnerable one reaches (or does not reach) the vulnerable code."""
    parent: str                        # "requests"
    reachable: bool | None = None      # False: this parent never reaches the vulnerable code
    symbols: list[str] = []            # parent APIs that reach it: "requests.get", "requests.Session.request"
    condition: str = ""
    source: Literal["llm", "code"] = "llm"   # code: symbols found in the parent's own source (grounded specs)
    note: str = ""


class NativeFeature(BaseModel):
    library: str                       # "libwebp"
    wrapper_symbols: list[str] = []    # Python APIs that reach it: "PIL.Image.open"
    description: str = ""


class TriggerSpecLLM(BaseModel):
    """What the model returns for one advisory. Independent of any repository."""
    plain_summary: str
    trigger_symbols: list[str] = []
    dangerous_condition: str = ""      # the extra condition when call_is_enough is False
    arg_forms: list[ArgForm] = []
    needs_untrusted_input: bool = True
    untrusted_input: str = ""          # which argument must be attacker-controlled
    input_arg: str | None = None       # "0" (position) or a keyword name, for the attacker_input gate
    parent_triggers: list[ParentTrigger] = []
    native_feature: NativeFeature | None = None


class TriggerSpec(TriggerSpecLLM):
    vuln_id: str
    package: str
    source: Literal["llm", "human"] = "llm"
    model: str | None = None
    diff_used: list[str] = []          # fix URLs whose diff was shown to the model
    created_at: datetime | None = None
    variant: str = "llm"               # how it was made: llm | llm+facts | gemini | gemini+facts
    provider: str | None = None        # the LLM profile that wrote it
    api_index: str | None = None       # the package archive the API index came from
    changed_functions: list[str] = []  # functions the fix diff changes, from the API index
    validation_issues: list[str] = []  # symbols resolved, dropped or kept unverified by the validation


class NarrowAnswer(BaseModel):
    answer: Literal["yes", "no", "unknown"]
    line: str | None = None            # "file:line" that proves a "no"
    reason: str = ""


# ---------------------------------------------------------------- Result file

class StageTiming(BaseModel):
    stage: str
    seconds: float


class ScanResult(BaseModel):
    schema_version: str = SCHEMA_VERSION
    created_at: datetime
    updated_at: datetime | None = None
    result_file: str = ""              # results/<slug>_<timestamp>.json
    repo: RepoMap
    vulnerabilities: list[DependencyVulns] = []
    usages: dict[str, DependencyUsage] = {}
    parse_failures: list[str] = []
    repo_context: RepoContext | None = None
    timings: list[StageTiming] = []
    warnings: list[str] = []
    cache: CacheStats = CacheStats()
    config: dict = {}                  # model, endpoint, OSV settings used

    def find(self, vuln_id: str, dependency: str | None = None) -> list[tuple[DependencyVulns, Vulnerability]]:
        """Every (dependency, vulnerability) whose id or alias equals vuln_id."""
        hits = []
        for dv in self.vulnerabilities:
            if dependency and dependency not in (dv.dependency.key, dv.dependency.name):
                continue
            for v in dv.all_vulns():
                if vuln_id == v.id or vuln_id in v.aliases:
                    hits.append((dv, v))
        return hits


VerdictRecord.model_rebuild()
