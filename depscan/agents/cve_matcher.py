"""CVEMatcherAgent (deterministic): look up known vulnerabilities for each dependency in OSV.dev.

- Resolved versions: OSV decides whether the installed version is affected.
- Unresolved versions: query by name, then keep an advisory only if one of its affected versions
  satisfies the dependency's version spec ("possibly_affected").
- Advisories sharing any alias (GHSA / PYSEC / CVE) are merged into one Vulnerability.
"""

import re
from concurrent.futures import ThreadPoolExecutor

from cvss import CVSS3, CVSS4
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from depscan.cache import ResponseCache
from depscan.import_names import import_names
from depscan.native_reach import BUNDLED_PHRASES, native_libs_in
from depscan.symbols import extract_symbols
from depscan.models import (
    CVEMatcherInput, CVEMatcherOutput, Cvss, Dependency, DependencyVulns, Vulnerability,
)
from depscan.osv import OSVClient
from depscan.parsers import normalize_name

GHSA_LABELS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
Interval = tuple[str, str | None, str | None]  # (introduced, fixed, last_affected)


def _v(s: str | None) -> Version | None:
    try:
        return Version(s) if s else None
    except InvalidVersion:
        return None


def _pref(osv_id: str) -> int:
    """Order records so the richest source comes first: GHSA, then PYSEC, then others."""
    return 0 if osv_id.startswith("GHSA-") else 1 if osv_id.startswith("PYSEC-") else 2


# ---------------------------------------------------------------- grouping

def group_by_alias(records: list[dict]) -> list[list[dict]]:
    """Union-find over ids + aliases: records that share any id end up in one group."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for rec in records:
        for alias in rec.get("aliases", []):
            parent[find(alias)] = find(rec["id"])
    groups: dict[str, list[dict]] = {}
    for rec in records:
        groups.setdefault(find(rec["id"]), []).append(rec)
    return [sorted(g, key=lambda r: (_pref(r["id"]), r["id"])) for g in groups.values()]


# ---------------------------------------------------------------- field extraction

def parse_cvss(records: list[dict], log: list[str]) -> Cvss:
    """First v3 vector (preferred: most advisories have one, so scores stay comparable), else v4,
    else the GHSA severity label with no score (missing, not zero)."""
    vectors = [(s.get("type"), s.get("score", "")) for r in records for s in r.get("severity", []) or []]
    for wanted, cls in (("CVSS_V3", CVSS3), ("CVSS_V4", CVSS4)):
        for typ, vector in vectors:
            if typ != wanted:
                continue
            try:
                c = cls(vector)
            except Exception as e:
                log.append(f"could not parse CVSS vector {vector!r}: {e}")
                continue
            severity = (c.severities()[0] if wanted == "CVSS_V3" else c.severity).lower()
            return Cvss(vector=vector, version=vector.split("/")[0].split(":")[1], base_score=float(c.base_score),
                        severity=severity if severity in ("critical", "high", "medium", "low", "none") else "unknown")
    for r in records:
        label = str((r.get("database_specific") or {}).get("severity", "")).upper()
        if label in GHSA_LABELS:
            return Cvss(severity=GHSA_LABELS[label])
    return Cvss()


def intervals(records: list[dict], package: str) -> tuple[list[Interval], list[str]]:
    """Affected intervals and explicitly listed affected versions for this package."""
    out: list[Interval] = []
    versions: list[str] = []
    for rec in records:
        for aff in rec.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") != "PyPI" or normalize_name(pkg.get("name", "")) != package:
                continue
            versions += aff.get("versions", [])
            for rng in aff.get("ranges", []):
                if rng.get("type") != "ECOSYSTEM":
                    continue
                intro = None
                for ev in rng.get("events", []):
                    if "introduced" in ev:
                        intro = ev["introduced"]
                    elif "fixed" in ev and intro is not None:
                        out.append((intro, ev["fixed"], None))
                        intro = None
                    elif "last_affected" in ev and intro is not None:
                        out.append((intro, None, ev["last_affected"]))
                        intro = None
                if intro is not None:
                    out.append((intro, None, None))
    return list(dict.fromkeys(out)), list(dict.fromkeys(versions))


def fmt_interval(iv: Interval) -> str:
    intro, fixed, last = iv
    parts = [] if intro == "0" else [f">={intro}"]
    parts += [f"<{fixed}"] if fixed else []
    parts += [f"<={last}"] if last else []
    return ", ".join(parts) or "all versions"


def contains(iv: Interval, v: Version) -> bool:
    intro, fixed, last = iv
    lo = None if intro == "0" else _v(intro)
    if intro != "0" and lo is None:
        return False
    if lo is not None and v < lo:
        return False
    if fixed:
        return _v(fixed) is not None and v < _v(fixed)
    if last:
        return _v(last) is not None and v <= _v(last)
    return True


def lowest_fix_above(ivs: list[Interval], installed: Version) -> tuple[str | None, Interval | None]:
    """The lowest `fixed` event greater than the installed version, from the range(s) containing it."""
    matching = [iv for iv in ivs if contains(iv, installed)]
    candidates = [(_v(iv[1]), iv) for iv in matching if iv[1] and _v(iv[1]) and _v(iv[1]) > installed]
    if not candidates:
        return None, (matching[0] if matching else None)
    fix, iv = min(candidates, key=lambda c: c[0])
    return str(fix), iv


def affected_functions(records: list[dict]) -> list[str]:
    """Symbols from ecosystem_specific / database_specific when OSV provides them (rare for PyPI)."""
    found: list[str] = []

    def collect(d: dict | None) -> None:
        if not isinstance(d, dict):
            return
        for key in ("affected_functions", "functions", "symbols"):
            found.extend(x for x in d.get(key, []) or [] if isinstance(x, str))
        for imp in d.get("imports", []) or []:
            if isinstance(imp, dict):
                path = imp.get("path", "")
                found.extend(f"{path}.{s}" if path else s for s in imp.get("symbols", []) or [])

    for r in records:
        collect(r.get("database_specific"))
        for aff in r.get("affected", []):
            collect(aff.get("ecosystem_specific"))
            collect(aff.get("database_specific"))
    return list(dict.fromkeys(found))


def classify_kind(records: list[dict], summary: str, details: str) -> str:
    """fuzz_crash: OSS-Fuzz (OSV-*) records with only git ranges. bundled_native: about a native library
    shipped inside the wheel (a library keyword plus 'bundled'/'wheels'/..., or the library named in the summary)."""
    ids = [r["id"] for r in records]
    range_types = {rng.get("type") for r in records for a in r.get("affected", []) for rng in a.get("ranges", [])}
    if all(i.startswith("OSV-") for i in ids) and "ECOSYSTEM" not in range_types:
        return "fuzz_crash"
    text = f"{summary}\n{details}".lower()
    libs = native_libs_in(text)
    if libs and (any(p in text for p in BUNDLED_PHRASES) or any(lib in summary.lower() for lib in libs)):
        return "bundled_native"
    return "standard"


def link_related(vulns: list[Vulnerability], ref_urls: dict[int, set[str]], max_sharing: int = 3) -> None:
    """Link (don't merge) vulnerabilities that share a specific reference URL. URLs shared by more than
    `max_sharing` vulnerabilities (release notes, changelogs, advisory databases) are too generic to count."""
    owners: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        for url in ref_urls.get(id(v), ()):
            owners.setdefault(url, []).append(v)
    for url, vs in owners.items():
        if 1 < len({v.id for v in vs}) <= max_sharing:
            for v in vs:
                for other in vs:
                    if other.id != v.id and other.id not in v.related_ids and other.id not in v.aliases:
                        v.related_ids.append(other.id)
    for v in vulns:
        v.related_ids.sort()


def to_specifier_set(spec: str) -> SpecifierSet | None:
    """PEP 440 specifiers, plus Poetry's ^ and ~ shorthands. None if it cannot be interpreted."""
    s = spec.strip()
    if s in ("", "*"):
        return SpecifierSet("")
    caret = re.fullmatch(r"\^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", s)
    if caret:
        parts = [int(p) for p in caret.groups() if p is not None]
        i = next((k for k, p in enumerate(parts) if p != 0), len(parts) - 1)
        upper = parts[:i] + [parts[i] + 1]
        return SpecifierSet(f">={'.'.join(map(str, parts))},<{'.'.join(map(str, upper))}")
    tilde = re.fullmatch(r"~\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", s)
    if tilde:
        parts = [int(p) for p in tilde.groups() if p is not None]
        upper = [parts[0] + 1] if len(parts) == 1 else [parts[0], parts[1] + 1]
        return SpecifierSet(f">={'.'.join(map(str, parts))},<{'.'.join(map(str, upper))}")
    try:
        return SpecifierSet(s)
    except InvalidSpecifier:
        return None


# ---------------------------------------------------------------- the agent

class CVEMatcherAgent:
    def __init__(self, client: OSVClient, max_workers: int = 8):
        self.client = client
        self.max_workers = max(1, min(max_workers, 8))

    @classmethod
    def from_config(cls, cfg) -> "CVEMatcherAgent":
        cache = ResponseCache(cfg.cache_path, ttl_seconds=cfg.osv.cache_ttl_hours * 3600)
        client = OSVClient(cache, base_url=cfg.osv.base_url, offline=cfg.osv.offline,
                           timeout=cfg.osv.timeout_seconds, retries=cfg.osv.retries)
        return cls(client, cfg.osv.max_workers)

    def run(self, inp: CVEMatcherInput) -> CVEMatcherOutput:
        log: list[str] = []
        deps = inp.dependencies
        queries = []
        for d in deps:
            q = {"package": {"name": d.name, "ecosystem": "PyPI"}}
            if d.resolved_version and _v(d.resolved_version):
                q["version"] = d.resolved_version
            elif d.resolved_version:
                log.append(f"{d.name}: version {d.resolved_version!r} is not a valid PEP 440 version; "
                           "treated as unresolved")
            queries.append(q)
        ids_per_dep = self.client.query_ids(queries)

        all_ids = sorted({i for ids in ids_per_dep if ids for i in ids})
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            records = {i: r for i, r in zip(all_ids, pool.map(self.client.get_vuln, all_ids)) if r is not None}

        results: list[DependencyVulns] = []
        ref_urls: dict[int, set[str]] = {}
        for dep, q, ids in zip(deps, queries, ids_per_dep):
            if ids is None:
                continue  # cache miss / network failure, already logged by the client
            recs = []
            for i in ids:
                rec = records.get(i)
                if rec is None:
                    continue
                if rec.get("withdrawn"):
                    log.append(f"{dep.name}: skipped withdrawn advisory {i} (withdrawn {rec['withdrawn']})")
                    continue
                recs.append(rec)
            vulns = []
            for group in group_by_alias(recs):
                v = self._build(dep, "version" in q, group, log)
                if v:
                    vulns.append(v)
                    ref_urls[id(v)] = {ref["url"] for r in group for ref in r.get("references", [])
                                       if ref.get("url") and ref.get("type") != "PACKAGE"}
            if vulns:
                vulns.sort(key=lambda v: (v.cvss.base_score is None, -(v.cvss.base_score or 0), v.id))
                results.append(DependencyVulns(
                    dependency=dep, vulnerabilities=[v for v in vulns if v.kind != "fuzz_crash"],
                    fuzz_crashes=[v for v in vulns if v.kind == "fuzz_crash"]))

        link_related([v for r in results for v in r.all_vulns()], ref_urls)
        log += self.client.log
        return CVEMatcherOutput(results=results, log=log, cache=self.client.stats, offline=self.client.offline)

    def _build(self, dep: Dependency, resolved: bool, group: list[dict], log: list[str]) -> Vulnerability | None:
        osv_ids = [r["id"] for r in group]
        all_ids = sorted({*osv_ids, *(a for r in group for a in r.get("aliases", []))})
        cve_ids = [i for i in all_ids if i.startswith("CVE-")]
        ghsa = [i for i in all_ids if i.startswith("GHSA-")]
        display = (cve_ids or ghsa or sorted(osv_ids, key=lambda i: (_pref(i), i)))[0]
        ivs, versions = intervals(group, dep.name)

        if resolved:
            installed = Version(dep.resolved_version)
            fixed, iv = lowest_fix_above(ivs, installed)
            match = "affected"
            reason = (f"installed {installed} is in affected range {fmt_interval(iv)}" if iv
                      else f"OSV lists installed {installed} as affected")
        else:
            fixed = None
            match, reason = "possibly_affected", self._unresolved_reason(dep, versions, display, log)
            if reason is None:
                return None

        summary = next((r["summary"] for r in group if r.get("summary")), "")
        details = next((r["details"] for r in group if r.get("details")), "")
        if not summary and details:
            summary = re.split(r"(?<=\.)\s", details.strip(), maxsplit=1)[0][:240]
        references = list(dict.fromkeys(ref["url"] for r in group for ref in r.get("references", []) if ref.get("url")))
        fixes = list(dict.fromkeys(ref["url"] for r in group for ref in r.get("references", [])
                                   if ref.get("url") and ref.get("type") == "FIX"))
        names, _ = import_names(dep.name)
        return Vulnerability(
            id=display, aliases=[i for i in all_ids if i != display], cve_ids=cve_ids,
            kind=classify_kind(group, summary, details),
            summary=summary.strip(), details=details.strip(), cvss=parse_cvss(group, log),
            affected_ranges=[fmt_interval(iv) for iv in ivs], fixed_version=fixed, references=references,
            fix_references=fixes,
            affected_functions=affected_functions(group),
            advisory_symbols=extract_symbols(f"{summary}\n{details}", names, dep.name),
            match=match, match_reason=reason)

    @staticmethod
    def _unresolved_reason(dep: Dependency, versions: list[str], vuln_id: str, log: list[str]) -> str | None:
        """Why an unresolved dependency may be affected; None = provably not (dropped and logged)."""
        spec_text = dep.version_spec
        if not spec_text or (dep.unresolved_reason or "").startswith(("installed", "editable")):
            return f"version unknown ({dep.unresolved_reason or 'no version specified'}); any affected version could be installed"
        spec = to_specifier_set(spec_text)
        if spec is None:
            return f"version spec '{spec_text}' could not be interpreted; cannot rule this advisory out"
        valid = sorted({_v(x) for x in versions if _v(x)})
        if not valid:
            return f"advisory lists no explicit affected versions; could not check them against range {spec_text}"
        inside = [x for x in valid if spec.contains(x, prereleases=True)]
        if not inside:
            log.append(f"{dep.name}: dropped {vuln_id}: range {spec_text} excludes all affected versions "
                       f"({valid[0]}–{valid[-1]})")
            return None
        span = str(inside[0]) if len(inside) == 1 else f"{inside[0]}–{inside[-1]}"
        return f"range {spec_text} includes affected versions {span}"


if __name__ == "__main__":  # python -m depscan.agents.cve_matcher <repo-url-or-path>
    import sys

    from depscan.agents.repo_mapper import RepoMapperAgent
    from depscan.config import load_config
    from depscan.models import RepoMapperInput

    cfg = load_config()
    repo = RepoMapperAgent(cfg.workspace).run(RepoMapperInput(url=sys.argv[1]))
    out = CVEMatcherAgent.from_config(cfg).run(CVEMatcherInput(dependencies=repo.dependencies))
    by_name = {r.dependency.name: r for r in out.results}
    total = sum(len(r.vulnerabilities) for r in out.results)
    print(f"{repo.repo_name}: {len(repo.dependencies)} dependencies, {len(out.results)} vulnerable, "
          f"{total} vulnerabilities (merged)  | cache: {out.cache.model_dump()}  offline={out.offline}\n")
    print(f"{'dependency':<18}{'version':<13}{'scope':<8}{'direct':<8}{'vulns':>5}  {'max CVSS':>8}")
    for d in repo.dependencies:
        r = by_name.get(d.name)
        scores = [v.cvss.base_score for v in r.vulnerabilities if v.cvss.base_score is not None] if r else []
        print(f"{d.name:<18}{d.resolved_version or '(unresolved)':<13}{d.scope:<8}{str(d.direct):<8}"
              f"{len(r.vulnerabilities) if r else 0:>5}  {max(scores) if scores else '-':>8}")
        for v in (r.vulnerabilities if r else []):
            score = f"{v.cvss.base_score:.1f}" if v.cvss.base_score is not None else "n/a"
            print(f"    {v.id:<21} {v.cvss.severity:<9}{score:>5} v{v.cvss.version or '-':<4} "
                  f"fix {v.fixed_version or '-':<9} {v.match:<17} {v.summary[:60]}")
    if out.log:
        print("\nlog:")
        for line in out.log:
            print("  " + line)
