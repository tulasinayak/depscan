"""StepwiseAgent: decide ONE vulnerability by running six gates in order, most of them in code.

  1 version_in_range  (code) installed version inside the affected range?
  2 trigger_spec      (LLM, cached per advisory) which API / argument / input triggers it?
  3 present           (code) does the repository use a trigger (directly, through a parent package, or through
                      the wrapper APIs of a bundled native library)?
  4 reachable         (code) can that code run from an entry point (CodeIndex)?
  5 dangerous_form    (code first) is it called the dangerous way (argument patterns), else ONE narrow LLM question
  6 attacker_input    (code first) does attacker-controlled input reach it (taint), else ONE narrow LLM question

Gates 4-6 are evaluated per usage site. A gate returns "fail" (not affected) only on definite evidence; anything
unclear is "unknown". The verdict is computed in code: any fail -> not affected, all pass -> affected, otherwise
needs review. Missing a real vulnerability is worse than a false alarm.
"""

import ast
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from depscan.codeindex import CodeIndex, value_text
from depscan.errors import DepscanError
from depscan.import_names import import_names
from depscan.llm.prompts import NARROW_SYSTEM, form_prompt, input_prompt
from depscan.models import (
    ArgForm, DependencyUsage, DependencyVulns, EvidenceItem, GateEvidence, GateResult, NarrowAnswer, ParentTrigger,
    ScanResult, TriggerSpec, UsageSite, VerdictRecord, Vulnerability,
)
from depscan.parsers.python_manifests import normalize_name
from depscan.symbols import symbol_matches
from depscan.triggers import TriggerStore

MAX_QUESTIONS = 4             # narrow LLM questions per vulnerability
SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")
LOOKUP = re.compile(r"by_name|by_mimetype|for_filename|for_mimetype|guess|lookup|find_|get_class|load_class|"
                    r"from_name|by_alias|import_string", re.I)
LABELS = {
    "version_in_range": "The installed version is affected",
    "trigger_spec": "We know what triggers it",
    "present": "The vulnerable code is used",
    "reachable": "That code can run",
    "dangerous_form": "It is used the dangerous way",
    "attacker_input": "An attacker controls the input",
}
VERDICT = {"affected": "likely_affected", "not_affected": "likely_not_affected",
           "probably_not_affected": "likely_not_affected", "needs_review": "uncertain"}


def status_of(gates: list[GateResult]) -> str:
    """Four-way status from the gates: only a CODE-decided fail proves "not affected"."""
    fails = [g for g in gates if g.result == "fail"]
    if any(g.decided_by == "code" for g in fails):
        return "not_affected"
    if fails:
        return "probably_not_affected"
    if all(g.result == "pass" for g in gates):
        return "affected"
    return "needs_review"


@dataclass
class Cand:
    site: UsageSite
    route: str                          # direct | parent | native | any
    parent: ParentTrigger | None = None
    confirmed: bool = True              # False: a parent's use that the spec does not link to the vulnerable code

    @property
    def where(self) -> str:
        return f"{self.site.file}:{self.site.line}"


def public_form(symbol: str) -> str:
    """rsa.pkcs1.decrypt -> rsa.decrypt; jinja2.sandbox.SandboxedEnvironment.x -> jinja2.SandboxedEnvironment.x
    (packages re-export their API at the top level, so the defining submodule is dropped)."""
    parts = symbol.split(".")
    first_cls = next((i for i, p in enumerate(parts) if p[:1].isupper()), None)
    if first_cls is not None:
        return ".".join([parts[0], *parts[first_cls:]])
    return ".".join([parts[0], parts[-1]]) if len(parts) > 1 else symbol


def cited_line(line: str | None, shown: set[tuple[str, int]], default_file: str) -> str | None:
    """'file:line' when the cited line is one of the lines shown to the model, else None."""
    m = re.search(r"([\w./\\-]+\.py)?\s*[:#]?\s*L?(\d+)\s*$", (line or "").strip())
    if not m:
        return None
    file = (m.group(1) or default_file).replace("\\", "/").removeprefix("./")
    n = int(m.group(2))
    if (file, n) in shown:
        return f"{file}:{n}"
    same = [f for f, k in shown if k == n and (f.endswith("/" + file) or file.endswith("/" + f))]
    return f"{same[0]}:{n}" if same else None


def trigger_match(symbol: str, pattern: str) -> bool:
    pattern = re.sub(r"\(.*\)$", "", pattern.strip()).strip(".")
    if not pattern:
        return False
    if pattern.endswith((".__init__", ".__new__")):
        # SevenZipFile(path) calls SevenZipFile.__init__: the class call itself is the use
        cls = pattern.rsplit(".", 1)[0]
        return symbol_matches(symbol, cls) or public_form(symbol) == public_form(cls)
    if symbol_matches(symbol, pattern) or symbol.startswith(pattern + "."):
        return True
    ps, pp = public_form(symbol), public_form(pattern)
    return "." in pp and (ps == pp or ps.startswith(pp + "."))


def malformed(symbols: list[str]) -> list[str]:
    """Names that are not dotted identifiers ("jwt.PyJWKClient.get_signing, "): absence of those can't be proven."""
    return [s for s in symbols if not SYMBOL.fullmatch(re.sub(r"\(.*\)$", "", s.strip()).strip("."))]


def module_of(symbol: str) -> list[str]:
    parts = symbol.split(".")
    first_cls = next((i for i, p in enumerate(parts) if p[:1].isupper()), None)
    return parts[:first_cls] if first_cls is not None else parts[:-1]


def same_submodule(symbol: str, pattern: str) -> bool:
    """pkcs12.load_key_and_certificates ~ pkcs12.PKCS12_load: another API of the same submodule (not the package
    root: yaml.safe_load is not a sibling of yaml.full_load in this sense)."""
    mod = module_of(pattern)
    return len(mod) >= 2 and symbol.startswith(".".join(mod) + ".")


def normalize_symbols(symbols: list[str], package: str, names: list[str]) -> list[str]:
    """Specs sometimes use the distribution name as the root (Pillow.Image.open): map it to the import name (PIL)."""
    out = []
    for sym in symbols:
        parts = sym.strip().split(".")
        if parts and parts[0].lower() in {package.lower(), package.replace("-", "_").lower()} \
                and parts[0] not in names and names:
            parts = parts[1:] if len(parts) > 1 and parts[1] in names else [names[0], *parts[1:]]
        out.append(".".join(parts))
    return out


def normalize_spec(spec: TriggerSpec | None, package: str, names: list[str] | None = None) -> TriggerSpec | None:
    """names: the import names the usage locator resolved for this package (same casing as the code)."""
    if spec is None:
        return None
    names = names or import_names(package)[0]
    update = {"trigger_symbols": normalize_symbols(spec.trigger_symbols, package, names),
              "arg_forms": [f.model_copy(update={"call": normalize_symbols([f.call], package, names)[0]})
                            for f in spec.arg_forms],
              "parent_triggers": [pt.model_copy(update={"symbols": normalize_symbols(
                  pt.symbols, normalize_name(pt.parent), import_names(normalize_name(pt.parent))[0])})
                                  for pt in spec.parent_triggers]}
    if spec.native_feature:
        update["native_feature"] = spec.native_feature.model_copy(update={
            "wrapper_symbols": normalize_symbols(spec.native_feature.wrapper_symbols, package, names)})
    return spec.model_copy(update=update)


def subclass_like(symbol: str, pattern: str) -> bool:
    """SandboxedEnvironment.from_string ~ Environment: a class named like a trigger class may subclass it."""
    sp, pp = public_form(symbol).split("."), public_form(pattern).split(".")
    if sp[0] != pp[0] or len(pp) < 2 or not pp[1][:1].isupper() or len(sp) < 2:
        return False
    return sp[1] != pp[1] and sp[1].endswith(pp[1]) and (len(pp) == 2 or sp[2:3] == pp[2:3])


def gate(name: str, result: str, explanation: str, evidence=(), by: str = "code", skipped: bool = False) -> GateResult:
    return GateResult(gate=name, result=result, explanation=explanation, decided_by=by, skipped=skipped,
                      evidence=[e if isinstance(e, GateEvidence) else GateEvidence(text=e[0], citation=e[1])
                                for e in evidence])


def skip(name: str, why: str) -> GateResult:
    return gate(name, "unknown", why, skipped=True)


class StepwiseAgent:
    def __init__(self, store: TriggerStore, index: CodeIndex, llm=None, max_questions: int = MAX_QUESTIONS):
        self.store = store
        self.index = index
        self.llm = llm
        self.max_questions = max_questions
        self.calls = 0

    # ------------------------------------------------------------ entry point

    def run(self, result: ScanResult, dv: DependencyVulns, vuln: Vulnerability) -> VerdictRecord:
        start = time.perf_counter()
        self.calls, self.questions, self.rejected = 0, 0, []
        dep = dv.dependency
        g1 = self.version_gate(dv, vuln)
        if vuln.kind == "fuzz_crash":
            gates = [g1] + [skip(n, "Not checked: automated fuzzing crash reports name no API to look for.")
                            for n in LABELS if n != "version_in_range"]
            return self.record(dv, vuln, gates, None, "needs_review", "Needs review: this is an automated fuzzing "
                               "crash report that names no API, so it cannot be linked to the code.", start)

        spec, generated, problem = self.store.get(vuln, dep.name, self.llm, dep.resolved_version)
        self.calls += int(generated)
        usage = result.usages.get(dep.key)
        if spec is not None and self.store.grounded and spec.source == "llm":
            spec = self.code_parents(result, dep, usage, spec)
        spec = normalize_spec(spec, dep.name, usage.import_names if usage else None)
        g2 = self.spec_gate(spec, problem)
        g3, cands, fallback_ok = self.present_gate(result, dv, vuln, spec, usage)
        if g3.result == "fail":
            rest = [skip(n, "Not checked: the vulnerable code is not used.") for n in
                    ("reachable", "dangerous_form", "attacker_input")]
            return self.finish(dv, vuln, [g1, g2, g3, *rest], spec, start)
        if not cands and fallback_ok:
            # No trigger to look for: can any use of the package run at all?
            cands = [Cand(s, "any") for s in self.package_uses(usage)]
        if not cands:
            rest = [skip(n, "Not checked: there is no specific use of the vulnerable code to check.")
                    for n in ("reachable", "dangerous_form", "attacker_input")]
            return self.finish(dv, vuln, [g1, g2, g3, *rest], spec, start)
        return self.finish(dv, vuln, [g1, g2, g3, *self.site_gates(cands, spec, dep.name)], spec, start)

    def code_parents(self, result: ScanResult, dep, usage: DependencyUsage | None, spec: TriggerSpec) -> TriggerSpec:
        """Grounded specs: the parent triggers come from the parents' own code (their public APIs that lead to the
        trigger symbols); the LLM's parent entries only keep their condition in words."""
        from depscan.grounding import code_parent_triggers
        parents = (usage.required_by if usage else None) or dep.required_by
        versions = {d.name: d.resolved_version for d in result.repo.dependencies if d.project == dep.project}
        source = self.store.source
        indexes = {p: (source.index(p, versions.get(p)) if source is not None else None) for p in parents}
        return spec.model_copy(update={"parent_triggers": code_parent_triggers(spec, indexes, trigger_match)})

    # ------------------------------------------------------------ gates 1-3

    @staticmethod
    def version_gate(dv: DependencyVulns, vuln: Vulnerability) -> GateResult:
        dep = dv.dependency
        cite = dep.source_file
        if vuln.match == "affected" and dep.resolved_version:
            fixed = f"; fixed in {vuln.fixed_version}" if vuln.fixed_version else "; no fixed version is listed"
            return gate("version_in_range", "pass", f"{dep.name} {dep.resolved_version} is in the affected range{fixed}.",
                        [(vuln.match_reason, cite)])
        return gate("version_in_range", "unknown", f"The exact installed version of {dep.name} is not known "
                    f"({vuln.match_reason}).", [(vuln.match_reason, cite)])

    @staticmethod
    def spec_gate(spec: TriggerSpec | None, problem: str) -> GateResult:
        if spec is None:
            return gate("trigger_spec", "unknown", f"No trigger description is available ({problem}).", by="llm")
        what = spec.trigger_symbols[:4] or (spec.native_feature.wrapper_symbols[:3] if spec.native_feature else []) \
            or [p.parent for p in spec.parent_triggers]
        who = "reviewed by a human" if spec.source == "human" else f"generated by {spec.model or 'the LLM'}"
        ev = [(spec.plain_summary, "advisory")] + [(f"fix used: {u}", u) for u in spec.diff_used]
        by = "code" if spec.source == "human" else "llm"
        if not (spec.trigger_symbols or spec.native_feature or spec.parent_triggers):
            return gate("trigger_spec", "unknown", f"The advisory names no specific function or feature ({who}).", ev, by)
        return gate("trigger_spec", "pass", f"It is triggered through {', '.join(what)} ({who}).", ev, by)

    def package_uses(self, usage: DependencyUsage | None) -> list[UsageSite]:
        if usage is None:
            return []
        pool = usage.sites if usage.usage_status != "no_direct_usage" else usage.indirect_sites
        calls = [s for s in pool if s.kind == "call"]
        return calls or [s for s in pool if s.kind == "attribute"]

    def present_gate(self, result: ScanResult, dv: DependencyVulns, vuln: Vulnerability, spec: TriggerSpec | None,
                     usage: DependencyUsage | None) -> tuple[GateResult, list[Cand], bool]:
        """(gate, candidate sites, whether a reachability check over all package uses is meaningful)."""
        dep = dv.dependency
        status = usage.usage_status if usage else "no_direct_usage"
        uses = [s for s in (usage.sites if usage else []) if s.kind in ("call", "attribute", "regex")]
        found: list[Cand] = []
        if spec and spec.trigger_symbols:
            found += [Cand(s, "direct") for s in uses if any(trigger_match(s.symbol, t) for t in spec.trigger_symbols)]
        if spec and spec.trigger_symbols and not found:
            # Session.get calls Session.request internally: another method of a trigger's class is a possible use
            classes = {t.rsplit(".", 1)[0] for t in spec.trigger_symbols
                       if "." in t and t.rsplit(".", 1)[0].split(".")[-1][:1].isupper()}
            found += [Cand(s, "direct", confirmed=False) for s in uses
                      if s.kind == "call" and any(s.symbol.startswith(c + ".") or subclass_like(s.symbol, c)
                                                  for c in classes)]
            found += [Cand(s, "direct", confirmed=False) for s in uses if s.kind == "call"
                      and any(subclass_like(s.symbol, t) or same_submodule(s.symbol, t) for t in spec.trigger_symbols)]
        nf = spec.native_feature if spec else None
        if nf and nf.wrapper_symbols:
            pool = uses + [s for s in (usage.native_reach_sites if usage else []) if s.kind in ("call", "attribute")]
            found += [Cand(s, "native") for s in pool if any(trigger_match(s.symbol, t) for t in nf.wrapper_symbols)]
        elif vuln.kind == "bundled_native" and usage:
            # no feature in the spec: the built-in table of wrapper APIs is only a hint, never proof
            found += [Cand(s, "native", confirmed=False) for s in usage.native_reach_sites
                      if s.kind in ("call", "attribute")]

        notes: list[tuple[str, str]] = []            # (state, text) per parent package
        if status == "no_direct_usage" and usage and usage.required_by:
            by_parent: dict[str, list[UsageSite]] = {}
            for s in usage.indirect_sites:
                by_parent.setdefault(s.package, []).append(s)
            for parent in usage.required_by:
                psites = [s for s in by_parent.get(parent, []) if s.kind in ("call", "attribute")]
                pt = next((p for p in (spec.parent_triggers if spec else []) if normalize_name(p.parent) == parent), None)
                if not by_parent.get(parent):
                    notes.append(("unknown", f"{parent} (which requires {dep.name}) is not imported directly either; "
                                             "it may be used through another package"))
                elif pt is None or (pt.reachable is not False and not pt.symbols):
                    notes.append(("unknown", f"the trigger description does not say how {parent} reaches {dep.name}"))
                    found += [Cand(s, "parent", pt, confirmed=False) for s in psites]
                elif pt.reachable is not False and malformed(pt.symbols):
                    notes.append(("unknown", f"the trigger description names {parent} APIs that are not valid names "
                                             f"({malformed(pt.symbols)[0]!r})"))
                    found += [Cand(s, "parent", pt, confirmed=False) for s in psites]
                elif pt.reachable is False:
                    notes.append(("fail", f"{parent} does not reach the vulnerable code"
                                          + (f" ({pt.condition})" if pt.condition else "")))
                else:
                    hits = [s for s in psites if any(trigger_match(s.symbol, t) for t in pt.symbols)]
                    found += [Cand(s, "parent", pt) for s in hits]
                    if not hits:
                        used = ", ".join(sorted({s.symbol for s in psites})[:3]) or "only imports"
                        notes.append(("fail", f"the app uses {parent} ({used}) but not the {parent} APIs that reach "
                                              f"it ({', '.join(pt.symbols[:3])})"))
        found = self._dedupe(found)

        high = [c for c in found if c.site.confidence == "high" and c.confirmed]
        unconfirmed = [c for c in found if not c.confirmed]
        if unconfirmed and not high:
            unknown = next((t for st, t in notes if st == "unknown"), None)
            first = unconfirmed[0]
            if unknown:
                text = f"{dep.name} is only used through other packages, and {unknown}."
            elif first.route == "native":
                text = (f"{first.site.symbol} at {first.where} may reach the bundled native library, but the trigger "
                        "description does not say which feature is affected.")
            else:
                text = (f"{first.site.symbol} at {first.where} belongs to a class related to the vulnerable one (same "
                        "class or a likely subclass), so it may reach the vulnerable code.")
            return gate("present", "unknown", text, [(c.site.symbol, c.where) for c in unconfirmed[:4]]), found, False
        if high:
            first = high[0]
            more = f" (and {len(high) - 1} more place{'s' if len(high) > 2 else ''})" if len(high) > 1 else ""
            via = f" through {first.site.package}" if first.route == "parent" else \
                " (reaches the bundled native library)" if first.route == "native" else ""
            return gate("present", "pass", f"{first.site.symbol} is used at {first.where}{via}{more}.",
                        [(f"{c.site.symbol}" + (f" ({c.site.via})" if c.site.via else ""), c.where) for c in high[:6]]), \
                [c for c in found if c.confirmed], False
        if found:
            return gate("present", "unknown", f"Only a low-confidence match was found ({found[0].site.symbol} at "
                        f"{found[0].where}: {found[0].site.kind}).", [(c.site.symbol, c.where) for c in found[:4]]), \
                found, False
        # nothing found: say "fail" only when it is definite
        if result.parse_failures:
            return gate("present", "unknown", f"No use was found, but {len(result.parse_failures)} file(s) could not "
                        "be parsed.", [(f, f.split(":")[0]) for f in result.parse_failures[:3]]), [], False
        if self.index.dynamic_imports:
            d = self.index.dynamic_imports[0]
            return gate("present", "unknown", f"No use was found, but the code imports modules by computed name ({d}).",
                        [(d, d.split()[0])]), [], False
        lookups = [s for s in uses if LOOKUP.search(s.symbol.split(".")[-1]) and self._has_variable_arg(s)]
        if lookups and spec and spec.trigger_symbols:
            s = lookups[0]
            return gate("present", "unknown", f"{s.symbol} at {s.file}:{s.line} picks an implementation by a name "
                        "chosen at runtime, so the vulnerable one could be selected.", [(s.symbol, f"{s.file}:{s.line}")]), \
                [], False
        if status == "parse_incomplete":
            return gate("present", "unknown", "Usage could not be determined for every file."), [], False
        if status == "no_direct_usage":
            if not (usage and usage.required_by):
                mention = self._mentioned_in_config(dep.name)
                if mention:
                    return gate("present", "unknown", f"{dep.name} is never imported, but it is mentioned in a config "
                                "or deployment file, so it may be run as a command."), [], False
                return gate("present", "fail", f"{dep.name} is never imported by the code and no other dependency "
                            "requires it.", [(f"{dep.name} is declared but not imported", dep.source_file)]), [], False
            unknown = [t for s, t in notes if s == "unknown"]
            if unknown:
                return gate("present", "unknown", f"{dep.name} is only used through other packages, and "
                            f"{unknown[0]}."), [], True
            return gate("present", "fail", f"{dep.name} is only used through other packages, and "
                        + "; ".join(t for _, t in notes) + ".",
                        [(t, None) for _, t in notes]), [], False
        if spec is None:
            return gate("present", "unknown", f"{dep.name} is used, but without a trigger description it is unknown "
                        "which uses matter."), [], True
        if not (spec.trigger_symbols or (nf and nf.wrapper_symbols)):
            # an empty list is missing information, never proof of absence
            return gate("present", "unknown", f"{dep.name} is used, and the trigger description names no specific "
                        "function, so any use could trigger it."), [], True
        bad = malformed(spec.trigger_symbols + (nf.wrapper_symbols if nf else []))
        if bad:
            return gate("present", "unknown", f"{dep.name} is used, but the trigger description names {bad[0]!r}, "
                        "which is not a valid name, so it can't be shown that the vulnerable code is unused."), [], True
        used = sorted({s.symbol for s in uses})
        wanted = spec.trigger_symbols[:4] or (nf.wrapper_symbols[:4] if nf else [])
        return gate("present", "fail", f"{dep.name} is used ({', '.join(used[:3]) or 'imports only'}), but not "
                    f"{', '.join(wanted)}, which the vulnerability needs.",
                    [(f"uses {s.symbol}", f"{s.file}:{s.line}") for s in uses[:4]]), [], False

    def _has_variable_arg(self, s: UsageSite) -> bool:
        call = self.index.node_at(s.file, s.line, s.symbol)
        return isinstance(call, ast.Call) and any(not isinstance(a, ast.Constant) for a in call.args)

    def _mentioned_in_config(self, package: str) -> bool:
        return bool(re.search(rf"(?<![\w-]){re.escape(package)}(?![\w-])", self.index.config_text, re.I))

    @staticmethod
    def _dedupe(found: list[Cand]) -> list[Cand]:
        seen, out = set(), []
        for c in found:
            key = (c.site.file, c.site.line, c.site.symbol)
            if key not in seen:
                seen.add(key)
                out.append(c)
        # `_env = SandboxedEnvironment(...)` is covered by the method calls on it (`_env.from_string(...)`), and
        # `Loader=yaml.FullLoader` by the yaml.load(...) call on the same line
        calls = {(o.site.file, o.site.line) for o in out if o.site.kind == "call"}
        return [c for c in out if not (c.site.symbol.split(".")[-1][:1].isupper() and
                                       any(o.site.symbol.startswith(c.site.symbol + ".") and o.site.kind == "call"
                                           for o in out))
                and not (c.site.kind == "attribute" and (c.site.file, c.site.line) in calls)]

    # ------------------------------------------------------------ gates 4-6, per site

    def site_gates(self, cands: list[Cand], spec: TriggerSpec | None, package: str) -> list[GateResult]:
        reach = {id(c): self.index.reach(c.site.file, c.site.line, c.site.symbol) for c in cands}
        order = {"pass": 0, "unknown": 1, "fail": 2}
        cands = sorted(cands, key=lambda c: (order[reach[id(c)].result], c.site.in_test_path, c.site.file, c.site.line))
        chains: list[tuple[Cand, list[GateResult]]] = []
        for c in cands:
            r = reach[id(c)]
            g4 = gate("reachable", r.result, r.explanation, r.evidence)
            if g4.result == "fail":
                chains.append((c, [g4, skip("dangerous_form", "Not checked: this code never runs."),
                                   skip("attacker_input", "Not checked: this code never runs.")]))
                continue
            via = self.via(c, spec, package)
            g5 = self.form_gate(c, spec, package, via)
            if g5.result == "fail":
                chains.append((c, [g4, g5, skip("attacker_input", "Not checked: the call is made in a safe way.")]))
                continue
            g6 = self.input_gate(c, spec, package, via)
            chains.append((c, [g4, g5, g6]))
            if all(g.result == "pass" for g in (g4, g5, g6)):
                break                                     # one affected use is enough
        return self.aggregate(chains)

    @staticmethod
    def aggregate(chains: list[tuple[Cand, list[GateResult]]]) -> list[GateResult]:
        n = len(chains)
        passing = next((gs for _, gs in chains if all(g.result == "pass" for g in gs)), None)
        if passing:
            if n > 1:
                passing = [g.model_copy(update={"explanation": g.explanation + f" (1 of {n} uses checked)"})
                           if i == 0 else g for i, g in enumerate(passing)]
            return passing
        if all(any(g.result == "fail" for g in gs) for _, gs in chains):
            rows = []
            for i, name in enumerate(("reachable", "dangerous_form", "attacker_input")):
                died = [gs[i] for _, gs in chains if gs[i].result == "fail"]
                passed = [gs[i] for _, gs in chains if gs[i].result == "pass"]
                if died:
                    extra = f" (and {len(died) - 3} more)" if len(died) > 3 else ""
                    rows.append(GateResult(gate=name, result="fail", decided_by=died[0].decided_by,
                                           explanation=" ".join(g.explanation for g in died[:3]) + extra,
                                           evidence=[e for g in died[:6] for e in g.evidence]))
                elif passed:
                    rows.append(passed[0])
                else:
                    rows.append(skip(name, "Not checked: every use was already ruled out."))
            return rows
        open_chains = [gs for _, gs in chains if not any(g.result == "fail" for g in gs)]
        rep = max(open_chains, key=lambda gs: sum(g.result == "pass" for g in gs))
        ruled_out = n - len(open_chains)
        if ruled_out:
            rep = [rep[0].model_copy(update={"explanation": rep[0].explanation + f" ({ruled_out} other use"
                                             f"{'s were' if ruled_out > 1 else ' was'} ruled out)"})] + rep[1:]
        return rep

    @staticmethod
    def via(c: Cand, spec: TriggerSpec | None, package: str) -> str:
        """Tells the narrow questions that the vulnerable code runs inside another library."""
        if c.route == "parent":
            parent = c.parent.parent if c.parent else c.site.package
            condition = (c.parent.condition if c.parent else "") or "the operation described above"
            return (f"The marked call uses {parent}, which uses {package} internally. The vulnerable code runs inside "
                    f"{package} when {parent} does this: {condition}.")
        if c.route == "native":
            nf = spec.native_feature if spec else None
            library = nf.library if nf and nf.library else "native library"
            when = nf.description if nf and nf.description else "it processes the affected data"
            return (f"The marked call uses {package}, which runs its bundled native library {library} when "
                    f"{when}.")
        return ""

    def form_gate(self, c: Cand, spec: TriggerSpec | None, package: str = "", via: str = "") -> GateResult:
        if spec is None:
            return gate("dangerous_form", "unknown", "Without a trigger description the call cannot be checked.")
        s = c.site
        mod = self.index.modules.get(s.file)
        call = self.index.node_at(s.file, s.line, s.symbol)
        forms = [f for f in spec.arg_forms if trigger_match(s.symbol, f.call)] if c.route in ("direct", "any") else []
        if forms and isinstance(call, ast.Call) and mod is not None:
            outcomes = [self.eval_form(f, call, mod) for f in forms]
            bad = [t for o, t in outcomes if o == "dangerous"]
            if bad:
                return gate("dangerous_form", "pass", f"{s.symbol} at {c.where} is called with {bad[0]}, which is the "
                            "dangerous way.", [(bad[0], c.where)])
            if all(o == "safe" for o, _ in outcomes):
                return gate("dangerous_form", "fail", f"{s.symbol} at {c.where} is called with "
                            f"{outcomes[0][1]}, which is safe.", [(outcomes[0][1], c.where)])
        condition = (c.parent.condition if c.parent and c.parent.condition else "") or spec.dangerous_condition or \
            (spec.native_feature.description if c.route == "native" and spec.native_feature else "")
        if forms:
            condition = condition or "; ".join(f"{f.kwarg or 'argument ' + str(f.position)} is one of "
                                              f"{', '.join(f.dangerous)}" for f in forms)
        if not condition:
            return gate("dangerous_form", "pass", f"Any call of {s.symbol} is the dangerous way (no extra condition "
                        "is needed).", [(s.symbol, c.where)])
        code, shown = self.index.source_block(s.file, s.line)
        return self.ask("dangerous_form", c, form_prompt(spec, s.symbol, c.where, code, condition, package, via),
                        f"whether {s.symbol} at {c.where} is used the dangerous way ({condition})", shown)

    def eval_form(self, f: ArgForm, call: ast.Call, mod) -> tuple[str, str]:
        """('dangerous' | 'safe' | 'unknown', what was seen) for one argument pattern."""
        arg = next((k.value for k in call.keywords if f.kwarg and k.arg == f.kwarg), None)
        name = f.kwarg or f"argument {f.position}"
        if arg is None and f.position is not None and f.position < len(call.args) \
                and not any(isinstance(a, ast.Starred) for a in call.args[:f.position + 1]):
            arg = call.args[f.position]
        if arg is None:
            if any(k.arg is None for k in call.keywords) or any(isinstance(a, ast.Starred) for a in call.args):
                return "unknown", f"{name} passed through *args/**kwargs"
            return {"dangerous": "dangerous", "safe": "safe"}.get(f.when_absent, "unknown"), f"{name} not given"
        values = [v.lower() for v in value_text(arg, lambda e: self.index.resolve(mod, e))]
        shown = f"{name}={ast.unparse(arg)}"
        both = {x.lower() for x in f.safe} & {x.lower() for x in f.dangerous}
        if any(v in both for v in values):
            return "unknown", f"{shown} (listed as both safe and dangerous)"
        if any(v in (x.lower() for x in f.safe) for v in values):
            return "safe", shown
        if any(v in (x.lower() for x in f.dangerous) for v in values):
            return "dangerous", shown
        return "unknown", shown

    def input_gate(self, c: Cand, spec: TriggerSpec | None, package: str = "", via: str = "") -> GateResult:
        if spec is not None and not spec.needs_untrusted_input:
            return gate("attacker_input", "pass", "This vulnerability does not need attacker-supplied input"
                        + (f" ({spec.plain_summary.rstrip('.')})" if spec.plain_summary else "") + ".", skipped=True)
        s = c.site
        call = self.index.node_at(s.file, s.line, s.symbol)
        if isinstance(call, ast.Call):
            t = self.index.taint(s.file, call, spec.input_arg if spec and c.route in ("direct", "any") else None)
            if t.state == "tainted":
                return gate("attacker_input", "pass", f"The input of {s.symbol} at {c.where} can come from outside: "
                            f"{t.why}.", [(t.why, t.cite)])
            if t.state == "constant":
                return gate("attacker_input", "fail", f"The input of {s.symbol} at {c.where} is fixed in the code: "
                            f"{t.why}.", [(t.why, t.cite)])
            why = t.why
        else:
            why = "the use is not a direct call"
        if spec is None:
            return gate("attacker_input", "unknown", f"Could not tell where the input comes from ({why}).")
        scope = self.index.scope_of(self.index.modules[s.file], call) if s.file in self.index.modules and call else None
        code, shown = self.index.source_block(s.file, s.line)
        blocks = []
        if scope is not None:
            for m, k in self.index.callers(scope)[:2]:
                text, lines = self.index.source_block(m.rel, k.lineno, 30)
                blocks.append(f"# {m.rel}\n{text}")
                shown |= lines
        return self.ask("attacker_input", c, input_prompt(spec, s.symbol, c.where, code, "\n\n".join(blocks),
                                                          package, via),
                        f"whether an attacker controls the input of {s.symbol} at {c.where} ({why})", shown)

    def ask(self, name: str, c: Cand, prompt: str, what: str, shown: set | None = None) -> GateResult:
        if self.llm is None:
            return gate(name, "unknown", f"Could not decide in code {what}; no LLM is available to ask.")
        if self.questions >= self.max_questions:
            return gate(name, "unknown", f"Could not decide in code {what} (question limit reached).")
        self.questions += 1
        self.calls += 1
        try:
            ans, _ = self.llm.complete_json(f"Stepwise.{name}", NARROW_SYSTEM, prompt, NarrowAnswer, max_tokens=160)
        except DepscanError as e:
            return gate(name, "unknown", f"Could not decide {what}: {e.message}", by="llm")
        result = {"yes": "pass", "no": "fail", "unknown": "unknown"}[ans.answer]
        reason = ans.reason.strip().rstrip(".") or "no reason given"
        if ans.answer == "no":
            cited = cited_line(ans.line, shown or set(), c.site.file)
            if cited is None:
                self.rejected.append(f"{name} at {c.where}: {reason} (line: {ans.line or 'none'})")
                if hasattr(self.llm, "log_event"):
                    self.llm.log_event(f"Stepwise.{name}", {"rejected_no": True, "site": c.where, "line": ans.line,
                                                            "reason": reason})
                return gate(name, "unknown", f"{c.site.symbol} at {c.where}: the AI answered no ({reason}), but did not "
                            "point to a shown line that proves it, so this stays open.", [(reason, c.where)], by="llm")
            return gate(name, "fail", f"{c.site.symbol} at {c.where}: {reason}.", [(reason, cited)], by="llm")
        return gate(name, result, f"{c.site.symbol} at {c.where}: {reason}.", [(reason, c.where)], by="llm")

    # ------------------------------------------------------------ verdict

    def finish(self, dv: DependencyVulns, vuln: Vulnerability, gates: list[GateResult], spec: TriggerSpec | None,
               start: float) -> VerdictRecord:
        outcome = status_of(gates)
        fails = [g for g in gates if g.result == "fail"]
        if outcome == "not_affected":
            reason = f"Not affected: {next(g for g in fails if g.decided_by == 'code').explanation}"
        elif outcome == "probably_not_affected":
            reason = f"Probably not affected (AI judgement, not proven by code): {fails[0].explanation}"
        elif outcome == "affected":
            reason = "Affected: " + self._affected_reason(gates)
        else:
            unknown = [g for g in gates if g.result == "unknown"]
            labels = ", ".join(LABELS[g.gate].lower() for g in unknown)
            first = next((g for g in unknown if not g.skipped), unknown[0])
            reason = f"Needs review: could not confirm that {labels}. {first.explanation}"
        return self.record(dv, vuln, gates, spec, outcome, reason, start)

    @staticmethod
    def _affected_reason(gates: list[GateResult]) -> str:
        g3 = next(g for g in gates if g.gate == "present")
        g6 = next(g for g in gates if g.gate == "attacker_input")
        tail = "" if g6.skipped else " and it can receive attacker-controlled input"
        return g3.explanation.rstrip(".") + f", that code runs, it is used the dangerous way{tail}."

    def record(self, dv: DependencyVulns, vuln: Vulnerability, gates: list[GateResult], spec: TriggerSpec | None,
               outcome: str, reason: str, start: float) -> VerdictRecord:
        dep = dv.dependency
        llm_decided = any(g.decided_by == "llm" and g.result != "unknown" for g in gates[2:])
        confidence = {"affected": 0.9, "not_affected": 0.9, "probably_not_affected": 0.6,
                      "needs_review": 0.3}[outcome] - (0.2 if llm_decided and outcome == "affected" else 0)
        if outcome in ("not_affected", "probably_not_affected"):
            rec = "No action needed now" + (f"; upgrading to {vuln.fixed_version} or later still removes the risk."
                                            if vuln.fixed_version else ".")
        elif vuln.fixed_version:
            rec = f"Upgrade {dep.name} to {vuln.fixed_version} or later."
        else:
            rec = f"No fixed version of {dep.name} is listed; review the use and consider a replacement."
        evidence = [EvidenceItem(text=f"{LABELS[g.gate]}: {g.explanation}",
                                 citation=next((e.citation for e in g.evidence if e.citation), None))
                    for g in gates if not g.skipped]
        notes = [f"rejected_no: {r}" for r in self.rejected]
        if spec is not None:
            notes.append(f"trigger spec: {'human-reviewed' if spec.source == 'human' else 'LLM-generated'}"
                         + (f" ({spec.model})" if spec.model else ""))
        return VerdictRecord(
            verdict=VERDICT[outcome], confidence=round(confidence, 2), evidence=evidence, recommendation=rec,
            unknowns=[g.explanation for g in gates if g.result == "unknown" and not g.skipped],
            used_repo_context=False, model=(self.llm.model if self.llm is not None and self.calls else
                                            "none (decided in code)"),
            llm_called=self.calls > 0, duration_ms=int((time.perf_counter() - start) * 1000),
            timestamp=datetime.now(timezone.utc), notes=notes, method="stepwise", gates=gates, reason=reason,
            llm_calls=self.calls, spec_source=spec.source if spec else "none", status=outcome,
            spec_variant=self.store.variant,
            provider=self.llm.cfg.profile if self.llm is not None and self.calls else None)
