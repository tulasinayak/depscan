"""Read-only views over a ScanResult, shared by the CLI, the GUI and the exports."""

from packaging.version import InvalidVersion, Version

from depscan.models import DependencyVulns, ScanResult, VerdictRecord, Vulnerability

SEVERITY_ORDER = ["critical", "high", "medium", "low", "none", "unknown"]


def max_cvss(dv: DependencyVulns) -> tuple[float | None, str | None, str]:
    """(score, CVSS version, severity) of the highest-scored vulnerability; severity falls back to labels."""
    scored = [v for v in dv.vulnerabilities if v.cvss.base_score is not None]
    if scored:
        top = max(scored, key=lambda v: v.cvss.base_score)
        return top.cvss.base_score, top.cvss.version, top.cvss.severity
    return None, None, max_severity(dv)


def max_severity(dv: DependencyVulns) -> str:
    sev = [v.cvss.severity for v in dv.vulnerabilities] or ["unknown"]
    return min(sev, key=SEVERITY_ORDER.index)


def fixed_in_all(dv: DependencyVulns) -> tuple[str | None, int]:
    """(lowest version that fixes every vulnerability that has a fix, number of vulnerabilities without a fix)."""
    fixes, missing = [], 0
    for v in dv.vulnerabilities:
        if not v.fixed_version:
            missing += 1
            continue
        try:
            fixes.append(Version(v.fixed_version))
        except InvalidVersion:
            missing += 1
    return (str(max(fixes)) if fixes else None), missing


def fixed_in_label(dv: DependencyVulns) -> str:
    version, missing = fixed_in_all(dv)
    if version and missing:
        return f"{version} (+{missing} without fix)"
    return version or ("no fix listed" if missing else "-")


def stepwise_status(rec: VerdictRecord) -> str | None:
    """The four-way status of a stepwise verdict (also for records saved before the field existed)."""
    if rec.method != "stepwise":
        return None
    if rec.status:
        return rec.status
    from depscan.agents.stepwise import status_of
    return status_of(rec.gates) if rec.gates else {"likely_affected": "affected", "uncertain": "needs_review",
                                                   "likely_not_affected": "not_affected"}[rec.verdict]


def latest_verdict(v: Vulnerability, used_context: bool | None = None, method: str | None = None,
                   spec_variant: str | None = None) -> VerdictRecord | None:
    """Newest verdict, optionally only of one method ("holistic" / "stepwise"), context mode and (stepwise) trigger
    spec variant; records from before variants existed count as "llm"."""
    runs = [r for r in v.verdicts if (used_context is None or r.used_repo_context == used_context)
            and (method is None or r.method == method)
            and (spec_variant is None or r.method != "stepwise" or (r.spec_variant or "llm") == spec_variant)]
    return max(runs, key=lambda r: r.timestamp) if runs else None


def usage_label(result: ScanResult, name: str) -> str:
    u = result.usages.get(name)
    if u is None:
        return "not analysed"
    if u.usage_status == "direct_usage":
        return f"used directly ({len(u.sites)} site{'s' if len(u.sites) != 1 else ''})"
    if u.usage_status == "parse_incomplete":
        return "unknown: some files failed to parse"
    via = f" — reached via {', '.join(u.required_by)}" if u.required_by else ""
    return f"not imported directly{via}"


def counts(result: ScanResult) -> dict[str, int]:
    vulns = [v for dv in result.vulnerabilities for v in dv.vulnerabilities]
    out = {"dependencies": len(result.repo.dependencies), "vulnerable_dependencies": len(result.vulnerabilities),
           "vulnerabilities": len(vulns),
           "fuzz_crashes": sum(len(dv.fuzz_crashes) for dv in result.vulnerabilities),
           "analyzed": sum(1 for v in vulns if v.verdicts)}
    for sev in ("critical", "high", "medium", "low", "unknown"):
        out[sev] = sum(1 for v in vulns if v.cvss.severity == sev)
    return out


def all_vulns(result: ScanResult, include_fuzz: bool = False) -> list[tuple[DependencyVulns, Vulnerability]]:
    return [(dv, v) for dv in result.vulnerabilities
            for v in (dv.all_vulns() if include_fuzz else dv.vulnerabilities)]
