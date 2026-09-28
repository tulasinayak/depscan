"""depscan command line.

  python -m depscan.cli scan <url-or-path>
  python -m depscan.cli show <result.json>
  python -m depscan.cli context <result.json>
  python -m depscan.cli analyze <result.json> <vuln_id> [--method stepwise|holistic] [--with-context] [--dependency NAME]
  python -m depscan.cli analyze-all <result.json> [--method stepwise|holistic] [--min-cvss 7] [--with-context]
  python -m depscan.cli evaluate <result.json> [--expected PATH]
  python -m depscan.cli evaluate-suite <suite.yaml> [--method stepwise|holistic|both] [--no-llm] [--only a,b]
                                       [--redo] [--no-reuse]
"""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from depscan import evaluate as ev
from depscan import suite as su
from depscan.errors import DepscanError, NotFound
from depscan.models import ScanResult, VerdictRecord
from depscan.orchestrator import Orchestrator, write_atomic
from depscan.report import all_vulns, counts, fixed_in_label, latest_verdict, max_cvss, usage_label

console = Console()
SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "unknown": "dim", "none": "dim"}
VERDICT_STYLE = {"likely_affected": "bold red", "likely_not_affected": "bold green", "uncertain": "bold white"}


def show(result: ScanResult) -> None:
    c = counts(result)
    console.print(f"[bold]{escape(result.repo.repo_name)}[/] @ {(result.repo.commit or '')[:10]}  ·  "
                  f"{c['dependencies']} dependencies, {c['vulnerable_dependencies']} vulnerable, "
                  f"{c['vulnerabilities']} vulnerabilities (+{c['fuzz_crashes']} fuzz crashes not counted)  ·  "
                  f"critical {c['critical']} / high {c['high']} / medium {c['medium']} / low {c['low']}  ·  "
                  f"analyzed {c['analyzed']}")
    if result.timings:
        console.print("timings: " + ", ".join(f"{t.stage} {t.seconds:.1f}s" for t in result.timings), style="dim")
    table = Table(show_lines=False)
    for col in ("dependency", "version", "scope", "direct", "usage", "vulns", "max CVSS", "fixed in", "analyzed"):
        table.add_column(col)
    by_key = {dv.dependency.key: dv for dv in result.vulnerabilities}
    for d in result.repo.dependencies:
        dv = by_key.get(d.key)
        if dv is None:
            table.add_row(escape(d.key), d.resolved_version or "[dim]unresolved[/]", d.scope, str(d.direct), "", "0", "", "", "")
            continue
        score, version, sev = max_cvss(dv)
        label = f"{score:.1f} (v{version})" if score is not None else f"no score ({sev})"
        n_analyzed = sum(1 for v in dv.vulnerabilities if v.verdicts)
        table.add_row(escape(d.key), d.resolved_version or "[dim]unresolved[/]", d.scope, str(d.direct),
                      escape(usage_label(result, d.key)), str(len(dv.vulnerabilities)),
                      f"[{SEV_STYLE.get(sev, '')}]{label}[/]", escape(fixed_in_label(dv)),
                      f"{n_analyzed}/{len(dv.vulnerabilities)}")
    console.print(table)
    for dv, v in all_vulns(result):
        rec = latest_verdict(v)
        if rec:
            console.print(f"  {v.id} ({dv.dependency.key}): [{VERDICT_STYLE[rec.verdict]}]{rec.verdict}[/] "
                          f"{rec.confidence:.2f} {'with' if rec.used_repo_context else 'without'} context")
    if result.warnings or result.parse_failures:
        console.print(f"[dim]{len(result.warnings)} warnings, {len(result.parse_failures)} parse failures "
                      f"(see the result JSON or the GUI)[/]")


GATE_MARK = {"pass": "[green]✓[/]", "fail": "[red]✗[/]", "unknown": "[yellow]?[/]"}
STEPWISE_TITLE = {"affected": "AFFECTED", "not_affected": "NOT AFFECTED",
                  "probably_not_affected": "PROBABLY NOT AFFECTED (AI judgement)", "needs_review": "NEEDS REVIEW"}


def print_stepwise(vuln_id: str, dependency: str, rec: VerdictRecord) -> None:
    from depscan.agents.stepwise import LABELS
    from depscan.report import stepwise_status
    lines = [f"[{VERDICT_STYLE[rec.verdict]}]{STEPWISE_TITLE[stepwise_status(rec)]}[/]  ·  {escape(rec.reason)}", ""]
    for g in rec.gates:
        mark = "[dim]–[/]" if g.skipped and g.result == "unknown" else GATE_MARK[g.result]
        by = " [dim](LLM)[/]" if g.decided_by == "llm" else ""
        lines.append(f" {mark} {LABELS[g.gate]}{by}: {escape(g.explanation)}")
    lines += ["", f"[bold]What to do[/]: {escape(rec.recommendation)}",
              f"[dim]{rec.model} · {rec.llm_calls} LLM call(s) · {rec.duration_ms / 1000:.0f}s · "
              f"trigger spec: {rec.spec_source}[/]"]
    console.print(Panel("\n".join(lines), title=f"{vuln_id} in {dependency} (stepwise)"))


def print_verdict(vuln_id: str, dependency: str, rec: VerdictRecord) -> None:
    if rec.method == "stepwise":
        return print_stepwise(vuln_id, dependency, rec)
    lines = [f"[{VERDICT_STYLE[rec.verdict]}]{rec.verdict}[/]  confidence {rec.confidence:.2f}  ·  "
             f"{'with' if rec.used_repo_context else 'without'} repo context  ·  {rec.model}  ·  {rec.duration_ms / 1000:.0f}s"]
    for title, items in (("Evidence", [f"{e.text}" + (f"  [dim]({e.citation})[/]" if e.citation else "")
                                       for e in rec.evidence]),
                         ("Inference", rec.inference), ("Unknowns", rec.unknowns)):
        lines.append(f"\n[bold]{title}[/]")
        lines += [f"  • {escape(x) if title != 'Evidence' else x}" for x in items] or ["  (none)"]
    lines.append(f"\n[bold]Recommendation[/]: {escape(rec.recommendation)}")
    for note in rec.notes + [f"dropped citation: {c}" for c in rec.dropped_citations]:
        lines.append(f"[dim]{escape(note)}[/]")
    console.print(Panel("\n".join(lines), title=f"{vuln_id} in {dependency}"))


def print_rows(title: str, rows: list[dict]) -> None:
    if not rows:
        return
    table = Table(title=title)
    for col in rows[0]:
        table.add_column(col)
    for row in rows:
        table.add_row(*(escape(str(v)) for v in row.values()))
    console.print(table)


def print_evaluation(rep: ev.EvalReport) -> None:
    table = Table(title=f"Evaluation: {escape(rep.repo)}")
    for col in ("id", "package", "scenario", "expected", "holistic w/o ctx", "", "holistic w/ ctx", "", "stepwise", ""):
        table.add_column(col)
    for r in rep.rows:
        cells = [r.id, r.package, r.scenario, r.expected]
        for verdict, ok in ((r.without_context, r.match_without_context), (r.with_context, r.match_with_context),
                            (r.stepwise, r.match_stepwise)):
            cells += [verdict, {True: "[green]✓[/]", False: "[red]✗[/]", None: "[dim]–[/]"}[ok]]
        table.add_row(*cells)
    console.print(table)
    print_rows("Methods compared", [ev.mode_row(ev.MODE_LABELS[m], s) for m, s in rep.modes.items()])
    for mode, s in rep.modes.items():
        m = Table(title=f"Confusion matrix ({mode.replace('_', ' ')})")
        m.add_column("expected → predicted")
        for p in ev.PREDICTED:
            m.add_column(p, justify="right")
        for exp in ev.VERDICTS:
            m.add_row(exp, *(str(s.matrix[exp].get(p, 0)) for p in ev.PREDICTED))
        console.print(m)
    print_rows("Per scenario (decided accuracy · coverage · missed affected)",
               [su.scenario_row(sc, m) for sc, m in rep.per_scenario.items()])
    console.print("[dim]decided accuracy: right answers among firm answers; coverage: share of labelled advisories "
                  "with a firm answer; missed affected: expected affected, answered not affected.[/]")
    if rep.missing_in_scan:
        console.print(f"[yellow]Labelled but not in the scan: {', '.join(rep.missing_in_scan)}[/]")
    if rep.unlabelled_in_scan:
        console.print(f"[yellow]In the scan but not labelled: {', '.join(rep.unlabelled_in_scan)}[/]")


def print_suite(rep: su.SuiteReport) -> None:
    if not rep.no_llm:
        print_rows("Suite: methods compared", su.method_rows(rep))
    print_rows(f"Suite: per repo{' (no LLM)' if rep.no_llm else ' (decided accuracy · coverage · missed affected)'}",
               [su.repo_row(o) for o in rep.repos])
    print_rows("Suite: per scenario (decided accuracy · coverage · missed affected)",
               [su.scenario_row(sc, m) for sc, m in rep.per_scenario.items()])
    for o in rep.repos:
        r = o.report
        if r and r.dependencies and r.dependencies.correct < r.dependencies.expected:
            console.print(f"[bold]{o.name}[/] dependency problems:")
            for x in r.dependencies.rows:
                if not x.ok:
                    console.print(f"  {(x.project + '/') if x.project else ''}{x.name}: {escape('; '.join(x.problems))}")
            if r.dependencies.unexpected:
                console.print(f"  reported but not expected: {', '.join(r.dependencies.unexpected)}")
        if r and r.sites and (r.sites.missed or r.sites.extra):
            console.print(f"[bold]{o.name}[/] usage sites: missed {len(r.sites.missed)}, extra {len(r.sites.extra)}")
            for m in r.sites.missed:
                console.print(f"  missed {m}")
            for m in r.sites.extra:
                console.print(f"  extra  {m}")
        if r and r.unlabelled_in_scan and o.analyze:
            console.print(f"[yellow]{o.name}: in the scan but not labelled: {', '.join(r.unlabelled_in_scan)}[/]")
    console.print(f"total LLM time: {rep.llm_seconds / 60:.1f} min")


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # Windows consoles/pipes default to a legacy code page
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(prog="depscan")
    ap.add_argument("--verbose", action="store_true", help="show underlying error details")
    ap.add_argument("--profile", help="LLM profile from config.toml (local_qwen, gemini, ...); default: default_profile")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan").add_argument("url")
    sub.add_parser("show").add_argument("result")
    sub.add_parser("context").add_argument("result")
    an = sub.add_parser("analyze")
    an.add_argument("result")
    an.add_argument("vuln_id")
    an.add_argument("--dependency")
    aa = sub.add_parser("analyze-all")
    aa.add_argument("result")
    aa.add_argument("--min-cvss", type=float)
    for p in (an, aa):
        p.add_argument("--method", choices=["stepwise", "holistic"], default="stepwise",
                       help="stepwise: six gates, mostly code (default); holistic: one LLM call (baseline)")
    sp = sub.add_parser("evaluate-suite")
    evp = sub.add_parser("evaluate")
    spc = sub.add_parser("specs", help="write the trigger specs of one variant for every advisory of a suite")
    spc.add_argument("suite")
    spc.add_argument("--only", help="comma-separated repo names from the suite file (default: all)")
    for p in (an, aa, sp, evp, spc):
        p.add_argument("--spec-variant", help="stepwise trigger specs: llm | llm+facts (default: [grounding] "
                       "spec_variant in config.toml)")
    sp.add_argument("suite")
    sp.add_argument("--method", choices=["stepwise", "holistic", "both"], default="stepwise",
                    help="which method to run where it has no verdict yet (default: stepwise)")
    sp.add_argument("--no-llm", action="store_true", help="score only the deterministic parts (fast, for CI)")
    sp.add_argument("--only", help="comma-separated repo names from the suite file to run (default: all)")
    sp.add_argument("--redo", action="store_true", help="re-run the chosen method even where a verdict exists")
    sp.add_argument("--no-reuse", action="store_true",
                    help="do not carry over verdicts from earlier result files of the same commit")
    evp.add_argument("result")
    evp.add_argument("--expected", help="default: <repo>/.depscan/expected.yaml of the scanned clone")
    for p in (an, aa):
        group = p.add_mutually_exclusive_group()
        group.add_argument("--with-context", dest="context", action="store_true")
        group.add_argument("--no-context", dest="context", action="store_false")
        p.set_defaults(context=False)
    args = ap.parse_args(argv)
    try:
        from depscan.config import load_config
        cfg = load_config()
        orch = Orchestrator(cfg.with_profile(args.profile) if args.profile else cfg)
        privacy_notice(args, orch)
        return run(args, orch)
    except DepscanError as e:
        console.print(f"[bold red]{escape(e.message)}[/]")
        if e.detail and args.verbose:
            console.print(escape(e.detail), style="dim")
        elif e.detail:
            console.print("(run with --verbose for details)", style="dim")
        return 1
    except KeyboardInterrupt:
        console.print("[yellow]Stopped. Everything finished so far is saved.[/]")
        return 130
    except (BrokenPipeError, OSError) as e:  # output piped into `head` etc.
        if isinstance(e, BrokenPipeError) or getattr(e, "errno", None) == 22:
            return 0
        raise


PRIVACY_NOTICE = ("Free-tier cloud APIs may use submitted code and prompts to improve their products, and humans may "
                  "review them. Don't use this for private code.")


def privacy_notice(args, orch: Orchestrator) -> None:
    """Printed before a cloud profile receives repository code (holistic prompts, narrow questions, context)."""
    sends_code = args.cmd in ("analyze", "analyze-all", "context") or (args.cmd == "evaluate-suite" and not args.no_llm)
    if orch.cfg.llm.cloud and sends_code:
        console.print(Panel(PRIVACY_NOTICE, title=f"{orch.cfg.llm.profile}: cloud model", style="yellow"))


def run(args, orch: Orchestrator) -> int:
    if args.cmd == "scan":
        with Progress(TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn(), console=console) as bar:
            task = bar.add_task("starting", total=1.0)
            result = orch.scan(args.url, lambda stage, msg, frac: bar.update(task, completed=frac,
                                                                             description=f"{stage}: {msg}"))
        show(result)
        console.print(f"\nSaved: {result.result_file}")
        return 0

    if args.cmd == "specs":
        spec = su.load_suite(args.suite)
        if args.only:
            wanted = {n.strip() for n in args.only.split(",") if n.strip()}
            spec.repos = [r for r in spec.repos if r.name in wanted]
        variant = args.spec_variant or orch.cfg.grounding.spec_variant
        counts = su.generate_specs(orch, spec, variant, lambda m: console.print(escape(m), style="dim"))
        console.print(f"Specs ({variant}): {counts['generated']} generated, {counts['cached']} already cached, "
                      f"{counts['failed']} failed. Folder: {orch.triggers(variant).cache_dir}")
        return 0 if not counts["failed"] else 1

    if args.cmd == "evaluate-suite":
        spec = su.load_suite(args.suite)
        if args.only:
            wanted = {n.strip() for n in args.only.split(",") if n.strip()}
            unknown = wanted - {r.name for r in spec.repos}
            if unknown:
                raise NotFound(f"Not in {args.suite}: {', '.join(sorted(unknown))}")
            spec.repos = [r for r in spec.repos if r.name in wanted]
        methods = su.METHODS if args.method == "both" else (args.method,)
        rep = su.run_suite(orch, spec, args.suite, args.no_llm, lambda m: console.print(escape(m), style="dim"),
                           methods=methods, reuse=not args.no_reuse, redo=args.redo,
                           spec_variant=args.spec_variant or orch.cfg.grounding.spec_variant)
        print_suite(rep)
        base = orch.cfg.results / f"suite_eval_{rep.created_at:%Y%m%d-%H%M%S}"
        write_atomic(base.with_suffix(".json"), rep.model_dump_json(indent=2))
        write_atomic(base.with_suffix(".md"), su.to_markdown(rep))
        console.print(f"Saved: {base.with_suffix('.json')} and .md")
        return 0 if all(o.error is None for o in rep.repos) else 1

    result = orch.load(args.result)
    if args.cmd == "show":
        show(result)
    elif args.cmd == "context":
        with console.status(f"Building repo context (one short {orch.cfg.llm.model} call)…"):
            result = orch.build_context(result)
        ctx = result.repo_context
        console.print(Panel(
            f"app type: [bold]{ctx.app_type}[/]\nframeworks: {', '.join(ctx.frameworks) or '-'}\n"
            f"entry points: {escape(', '.join(ctx.entry_points[:8])) or '-'}\n"
            f"untrusted inputs: {escape(', '.join(f'{u.symbol} ({u.file}:{u.line})' for u in ctx.untrusted_input_sources[:8])) or '-'}\n"
            f"\n{escape(ctx.summary)}", title="Repo context"))
    elif args.cmd == "analyze":
        with console.status(f"Checking {args.vuln_id} ({args.method}, {orch.cfg.llm.model}; can take minutes on CPU)…"):
            result = orch.analyze(result, args.vuln_id, args.context, args.dependency, method=args.method,
                                  spec_variant=args.spec_variant)
        for dv, v in result.find(args.vuln_id, args.dependency):
            print_verdict(v.id, dv.dependency.key, v.verdicts[-1])
    elif args.cmd == "analyze-all":
        todo = [(dv, v) for dv, v in all_vulns(result)
                if args.min_cvss is None or (v.cvss.base_score is not None and v.cvss.base_score >= args.min_cvss)]
        mode = args.method if args.method == "stepwise" else f"holistic, {'with' if args.context else 'without'} context"
        console.print(f"{len(todo)} vulnerabilities to check ({mode}). Ctrl+C stops after saving what is done.")
        with Progress(TextColumn("{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console) as bar:
            task = bar.add_task("", total=len(todo))
            for dv, v in todo:
                bar.update(task, description=f"{v.id} ({dv.dependency.key})")
                result = orch.analyze(result, v.id, args.context, dv.dependency.key, method=args.method,
                                      spec_variant=args.spec_variant)
                bar.advance(task)
        show(result)
    elif args.cmd == "evaluate":
        path = Path(args.expected) if args.expected else ev.default_expected_path(result)
        if not path.exists():
            raise NotFound(f"No expected answers at {path}. Pass --expected PATH.")
        rep = ev.evaluate(result, ev.load_expected_file(path), path,
                          args.spec_variant or orch.cfg.grounding.spec_variant)
        print_evaluation(rep)
        base = orch.cfg.results / f"{result.repo.slug or result.repo.repo_name}_eval_{rep.created_at:%Y%m%d-%H%M%S}"
        write_atomic(base.with_suffix(".json"), rep.model_dump_json(indent=2))
        write_atomic(base.with_suffix(".md"), ev.to_markdown(rep))
        console.print(f"Saved: {base.with_suffix('.json')} and .md")
    console.print(f"Result file: {result.result_file}", style="dim")
    return 0


if __name__ == "__main__":
    sys.exit(main())
