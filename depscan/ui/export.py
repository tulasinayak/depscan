"""Exports: CSV (dependency x vulnerability x latest verdict) and a Markdown report."""

import csv
import io

from depscan.models import ScanResult, VerdictRecord
from depscan.report import counts, fixed_in_label, latest_verdict, max_cvss, usage_label

CSV_COLUMNS = ["dependency", "installed_version", "scope", "direct", "usage_status", "required_by", "vulnerability",
               "aliases", "kind", "cvss_score", "cvss_version", "severity", "fixed_version", "match",
               "latest_verdict", "confidence", "used_repo_context", "model", "analyzed_at"]


def to_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for dv in result.vulnerabilities:
        d = dv.dependency
        usage = result.usages.get(d.key)
        for v in dv.all_vulns():
            rec = latest_verdict(v)
            writer.writerow([d.key, d.resolved_version or "", d.scope, d.direct,
                             usage.usage_status if usage else "", ";".join(d.required_by), v.id, ";".join(v.aliases),
                             v.kind, "" if v.cvss.base_score is None else v.cvss.base_score, v.cvss.version or "",
                             v.cvss.severity, v.fixed_version or "", v.match,
                             rec.verdict if rec else "", f"{rec.confidence:.2f}" if rec else "",
                             rec.used_repo_context if rec else "", rec.model if rec else "",
                             rec.timestamp.isoformat() if rec else ""])
    return buf.getvalue()


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _verdict_md(rec: VerdictRecord) -> list[str]:
    lines = [f"**{rec.verdict}** (confidence {rec.confidence:.2f}, {'with' if rec.used_repo_context else 'without'} "
             f"repo context, {rec.model}, {rec.timestamp:%Y-%m-%d %H:%M} UTC)", "", "Evidence:"]
    lines += [f"- {e.text}" + (f" (`{e.citation}`)" if e.citation else "") for e in rec.evidence] or ["- (none)"]
    lines += ["", "Inference:"] + ([f"- {x}" for x in rec.inference] or ["- (none)"])
    lines += ["", "Unknowns:"] + ([f"- {x}" for x in rec.unknowns] or ["- (none)"])
    lines += ["", f"Recommendation: {rec.recommendation}"]
    if rec.dropped_citations or rec.notes:
        lines += [""] + [f"> {n}" for n in rec.notes + [f"dropped citation: {c}" for c in rec.dropped_citations]]
    return lines + [""]


def to_markdown(result: ScanResult) -> str:
    c = counts(result)
    repo = result.repo
    lines = [f"# depscan report: {repo.repo_name}", "",
             f"- Source: {repo.repo_url} @ `{(repo.commit or 'unknown')[:12]}`",
             f"- Scanned: {result.created_at:%Y-%m-%d %H:%M} UTC; model: {result.config.get('llm', {}).get('model', '-')}",
             f"- {c['dependencies']} dependencies, {c['vulnerable_dependencies']} vulnerable, "
             f"{c['vulnerabilities']} vulnerabilities (critical {c['critical']}, high {c['high']}, medium {c['medium']}, "
             f"low {c['low']}, no score {c['unknown']}); {c['fuzz_crashes']} fuzz-crash records not counted; "
             f"{c['analyzed']} analyzed", ""]
    if result.repo_context:
        ctx = result.repo_context
        lines += ["## Repo context (background)", "", f"- App type: {ctx.app_type}",
                  f"- Frameworks: {', '.join(ctx.frameworks) or '-'}", f"- Summary: {ctx.summary or '-'}", ""]
    lines += ["## Dependencies", "", "| Dependency | Installed | Scope | Usage | Vulns | Max CVSS | Fixed in |",
              "|---|---|---|---|---|---|---|"]
    for dv in result.vulnerabilities:
        score, version, sev = max_cvss(dv)
        cvss = f"{score} (v{version})" if score is not None else f"no score ({sev})"
        lines.append(f"| {dv.dependency.key} | {dv.dependency.resolved_version or 'unresolved'} | {dv.dependency.scope} | "
                     f"{_md_escape(usage_label(result, dv.dependency.key))} | {len(dv.vulnerabilities)} | {cvss} | "
                     f"{fixed_in_label(dv)} |")
    lines += ["", "## Analyzed vulnerabilities", ""]
    analyzed = [(dv, v) for dv in result.vulnerabilities for v in dv.all_vulns() if v.verdicts]
    if not analyzed:
        lines.append("None yet.")
    for dv, v in analyzed:
        score = v.cvss.base_score if v.cvss.base_score is not None else "no score"
        lines += [f"### {v.id} in {dv.dependency.key} {dv.dependency.resolved_version or ''}", "",
                  f"{_md_escape(v.summary)} (CVSS {score}, {v.cvss.severity}; fixed in {v.fixed_version or '-'}; "
                  f"kind {v.kind})", ""]
        for used in (False, True):
            rec = latest_verdict(v, used)
            if rec:
                lines += _verdict_md(rec)
    return "\n".join(lines) + "\n"
