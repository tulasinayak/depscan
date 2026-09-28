"""Sidebar filters, applied to (dependency, vulnerability) pairs. Pure functions: easy to test."""

from dataclasses import dataclass, field

from depscan.models import DependencyVulns, ScanResult, Vulnerability

SEVERITIES = ["critical", "high", "medium", "low", "unknown"]
SCOPES = ["main", "dev", "unknown"]
KINDS = ["standard", "bundled_native", "fuzz_crash"]
USAGE = ["direct_usage", "no_direct_usage", "parse_incomplete"]


@dataclass
class Filters:
    severities: set[str] = field(default_factory=lambda: set(SEVERITIES))
    scopes: set[str] = field(default_factory=lambda: set(SCOPES))
    kinds: set[str] = field(default_factory=lambda: set(KINDS))
    hide_fuzz: bool = True
    usage: set[str] = field(default_factory=lambda: set(USAGE))
    only_unanalyzed: bool = False


def vuln_passes(f: Filters, result: ScanResult, dv: DependencyVulns, v: Vulnerability) -> bool:
    usage = result.usages.get(dv.dependency.key)
    status = usage.usage_status if usage else "no_direct_usage"
    severity = v.cvss.severity if v.cvss.severity in SEVERITIES else "unknown"
    return (severity in f.severities and dv.dependency.scope in f.scopes and v.kind in f.kinds
            and not (f.hide_fuzz and v.kind == "fuzz_crash") and status in f.usage
            and not (f.only_unanalyzed and v.verdicts))


def filtered_vulns(result: ScanResult, f: Filters, dependency: str | None = None) -> list[tuple[DependencyVulns, Vulnerability]]:
    out = []
    for dv in result.vulnerabilities:
        if dependency and dv.dependency.key != dependency:
            continue
        out += [(dv, v) for v in dv.all_vulns() if vuln_passes(f, result, dv, v)]
    return out


def filtered_deps(result: ScanResult, f: Filters) -> list[DependencyVulns]:
    keep = {dv.dependency.key for dv, _ in filtered_vulns(result, f)}
    return [dv for dv in result.vulnerabilities if dv.dependency.key in keep]
