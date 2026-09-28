"""UsageLocatorAgent (deterministic): where does the repository use each vulnerable dependency?

An AST pass per .py file records every reference that goes back to an import: import statements,
star imports, dynamic imports, and every Name / Attribute / Call chain on an imported name
(`Img.open(...)` -> `PIL.Image.open`, `pm = urllib3.PoolManager(); pm.request()` ->
`urllib3.PoolManager.request`, `f = getattr(idna, "encode"); f(x)` -> `idna.encode`).
A first pass collects what each repository module binds at import time, so re-exports through the
repo's own modules resolve too (`from yaml import full_load as parse_cfg` in app/utils, then
`utils.parse_cfg(...)` elsewhere -> `yaml.full_load`). Files that do not parse fall back to a regex scan
(low confidence).

Repository code is parsed, never imported or executed.
"""

import ast
import builtins
import re
import warnings
from dataclasses import dataclass
from pathlib import Path

from depscan.import_names import resolve_import_names
from depscan.models import (
    DependencyUsage, DependencyVulns, UsageLocatorInput, UsageLocatorOutput, UsageSite, Vulnerability,
)
from depscan.native_reach import native_libs_in, reaches
from depscan.symbols import symbol_matches

SNIPPET_CONTEXT = 5
MAX_SNIPPETS_PER_DEP = 30
MAX_INDIRECT_SITES = 10
MAX_NATIVE_SITES = 15
DYNAMIC_IMPORTERS = {("importlib", "import_module"), ("import_module",), ("__import__",)}
MAX_REEXPORT_HOPS = 5
_BUILTINS = set(dir(builtins))


@dataclass(frozen=True)
class Ref:
    file: str
    line: int
    kind: str          # import | star_import | dynamic_import | call | attribute | regex
    symbol: str        # fully qualified
    confidence: str = "high"


def is_test_path(rel: str) -> bool:
    parts = rel.lower().split("/")
    name = parts[-1]
    return (any(p in ("tests", "test", "testing") for p in parts[:-1]) or name.startswith("test_")
            or name.endswith("_test.py") or name == "conftest.py")


def _dotted(node: ast.AST) -> list[str] | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return parts[::-1]
    return None


def module_name(rel: str) -> str:
    """'app/utils/__init__.py' -> 'app.utils'; 'src/pkg/mod.py' -> 'pkg.mod'."""
    parts = rel.removesuffix(".py").split("/")
    if parts[0] == "src" and len(parts) > 1:
        parts = parts[1:]
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _relative_base(rel: str, level: int, module: str | None) -> str:
    """The absolute module a relative import (`from ..x import y`) refers to."""
    pkg = module_name(rel).split(".")
    if not rel.endswith("__init__.py"):
        pkg = pkg[:-1]
    pkg = pkg[:len(pkg) - (level - 1)] if level > 1 else pkg
    return ".".join([*pkg, *([module] if module else [])])


def _defined_names(tree: ast.AST) -> set[str]:
    """Every name the module itself defines anywhere (assignments, defs, args, imports, handlers, ...)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update((a.asname or a.name).split(".")[0] for a in node.names if a.name != "*")
    return names


def scan_source(source: str, rel: str, reexports: dict[str, dict[str, str]] | None = None) -> list[Ref]:
    """All references to imported names in one file. Raises SyntaxError/ValueError if it does not parse.
    reexports: {repo module: {name it binds: what that name really is}} from module_bindings()."""
    return _analyze(source, rel, reexports or {})[0]


def module_bindings(source: str, rel: str) -> dict[str, str]:
    """What a module binds to imported things (its re-exports): {'parse_cfg': 'yaml.full_load', ...}."""
    return _analyze(source, rel, {})[1]


def _analyze(source: str, rel: str, reexports: dict[str, dict[str, str]]) -> tuple[list[Ref], dict[str, str]]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tree = ast.parse(source, filename=rel)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    bindings: dict[str, str] = {}
    low: set[str] = set()              # bindings that are a guess (star import from several modules)
    stars: list[str] = []
    refs: list[Ref] = []

    def translate(symbol: str) -> str:
        """Follow re-exports through repo modules: app.utils.parse_cfg -> yaml.full_load."""
        for _ in range(MAX_REEXPORT_HOPS):
            parts = symbol.split(".")
            hit = next(((i, reexports[".".join(parts[:i])][parts[i]]) for i in range(len(parts) - 1, 0, -1)
                        if parts[i] in reexports.get(".".join(parts[:i]), {})), None)
            if hit is None or hit[1] == symbol:
                return symbol
            symbol = ".".join([hit[1], *parts[hit[0] + 1:]])
        return symbol

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    bindings[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    bindings[top] = top            # `import a.b.c` binds `a`; a.b.c.x resolves through it
                refs.append(Ref(rel, node.lineno, "import", a.name))
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for a in node.names:
                if a.name == "*":
                    stars.append(node.module)
                    refs.append(Ref(rel, node.lineno, "star_import", f"{node.module}.*"))
                else:
                    symbol = translate(f"{node.module}.{a.name}")
                    bindings[a.asname or a.name] = symbol
                    refs.append(Ref(rel, node.lineno, "import", symbol))
        elif isinstance(node, ast.ImportFrom) and node.level > 0:   # the repo's own modules
            base = _relative_base(rel, node.level, node.module)
            for a in node.names:
                if a.name != "*":
                    bindings[a.asname or a.name] = translate(f"{base}.{a.name}")

    # `from pkg import *`: a name the module loads but never defines (and is no builtin) must come from it.
    external_stars = [m for m in stars if m not in reexports]
    if external_stars:
        defined = _defined_names(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id not in defined \
                    and node.id not in _BUILTINS and node.id not in bindings:
                bindings[node.id] = f"{external_stars[0]}.{node.id}"
                if len(external_stars) > 1:
                    low.add(node.id)

    def resolve(expr: ast.AST) -> str | None:
        chain = _dotted(expr)
        if chain and chain[0] in bindings:
            return translate(".".join([bindings[chain[0]], *chain[1:]]))
        return None

    def getattr_target(node: ast.AST) -> str | None:
        """getattr(<imported thing>, "name") -> '<imported thing>.name'."""
        if isinstance(node, ast.Call) and _dotted(node.func) == ["getattr"] and len(node.args) >= 2 \
                and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
            base = resolve(node.args[0])
            return f"{base}.{node.args[1].value}" if base else None
        return None

    # Dynamic imports and simple instance/alias assignments: m = importlib.import_module("x"); pm = urllib3.PoolManager()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = _dotted(node.func)
            if fn and tuple(fn) in DYNAMIC_IMPORTERS and node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str):
                refs.append(Ref(rel, node.lineno, "dynamic_import", node.args[0].value, "low"))
                target = parents.get(node)
                if isinstance(target, ast.Assign) and len(target.targets) == 1 and isinstance(target.targets[0], ast.Name):
                    bindings.setdefault(target.targets[0].id, node.args[0].value)
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            fetched = getattr_target(node.value)
            if fetched and node.targets[0].id not in bindings:       # f = getattr(idna, "encode")
                bindings[node.targets[0].id] = fetched
                continue
            is_call = isinstance(node.value, ast.Call)
            value = node.value.func if is_call else node.value
            resolved = resolve(value) if isinstance(value, (ast.Name, ast.Attribute)) else None
            # `pm = urllib3.PoolManager()` -> pm is a PoolManager; `im = Img.open(p)` is not tracked
            # (a function's return type is unknown). `load = yaml.load` is a plain alias.
            if resolved and (not is_call or resolved.split(".")[-1][:1].isupper()) \
                    and node.targets[0].id not in bindings:
                bindings[node.targets[0].id] = resolved

    for node in ast.walk(tree):
        fetched = getattr_target(node)
        if fetched:
            parent = parents.get(node)
            kind = "call" if isinstance(parent, ast.Call) and parent.func is node else "attribute"
            refs.append(Ref(rel, node.lineno, kind, fetched))
            continue
        if not isinstance(node, (ast.Attribute, ast.Name)):
            continue
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.Attribute) and parent.value is node:
            continue  # only the outermost node of an attribute chain
        symbol = resolve(node)
        if symbol is None:
            continue
        kind = "call" if isinstance(parent, ast.Call) and parent.func is node else "attribute"
        chain = _dotted(node)
        refs.append(Ref(rel, node.lineno, kind, symbol, "low" if chain and chain[0] in low else "high"))
    return sorted(set(refs), key=lambda r: (r.line, r.symbol, r.kind)), bindings


_RE_IMPORT = re.compile(r"^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?", re.M)
_RE_FROM = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+\(?([\w\s,*]+)", re.M)


def regex_scan(source: str, rel: str) -> list[Ref]:
    """Fallback for files that do not parse: import lines and `alias.attr` uses. All low confidence."""
    refs: list[Ref] = []
    bindings: dict[str, str] = {}

    def line_of(pos: int) -> int:
        return source.count("\n", 0, pos) + 1

    for m in _RE_IMPORT.finditer(source):
        bindings[m.group(2) or m.group(1).split(".")[0]] = m.group(1) if m.group(2) else m.group(1).split(".")[0]
        refs.append(Ref(rel, line_of(m.start()), "regex", m.group(1), "low"))
    for m in _RE_FROM.finditer(source):
        for name in (n.strip() for n in m.group(2).split(",")):
            parts = name.split()
            if not parts:
                continue
            local = parts[-1] if len(parts) == 3 and parts[1] == "as" else parts[0]
            symbol = f"{m.group(1)}.{parts[0]}" if parts[0] != "*" else f"{m.group(1)}.*"
            bindings[local] = symbol
            refs.append(Ref(rel, line_of(m.start()), "regex", symbol, "low"))
    for local, target in bindings.items():
        if local == "*" or not local.isidentifier():
            continue
        for m in re.finditer(rf"(?<![\w.]){re.escape(local)}((?:\.\w+)+)", source):
            refs.append(Ref(rel, line_of(m.start()), "regex", target + m.group(1), "low"))
    return sorted(set(refs), key=lambda r: (r.line, r.symbol))


def belongs_to(symbol: str, names: list[str]) -> bool:
    return any(symbol == n or symbol.startswith(n + ".") for n in names)


class UsageLocatorAgent:
    def __init__(self, pypi=None):
        self.pypi = pypi            # grounding.PackageSource: import names from the release's own metadata

    def run(self, inp: UsageLocatorInput) -> UsageLocatorOutput:
        root = Path(inp.repo_map.local_path)
        sources: dict[str, list[str]] = {}
        texts: dict[str, str] = {}
        refs: list[Ref] = []
        failures: list[str] = []
        for rel in inp.repo_map.source_files:
            raw = (root / rel).read_bytes()
            try:
                texts[rel] = raw.decode("utf-8")
            except UnicodeDecodeError:
                texts[rel] = raw.decode("latin-1")
            sources[rel] = texts[rel].splitlines()
        # pass 1: what each repo module binds (its re-exports); pass 2: every reference, through re-exports
        reexports: dict[str, dict[str, str]] = {}
        for rel, text in texts.items():
            try:
                reexports[module_name(rel)] = module_bindings(text, rel)
            except (SyntaxError, ValueError, RecursionError):
                pass
        for rel, text in texts.items():
            try:
                refs += scan_source(text, rel, reexports)
            except (SyntaxError, ValueError, RecursionError) as e:
                failures.append(f"{rel}: {type(e).__name__}: {e}")
                refs += regex_scan(text, rel)

        ids = {ref: f"U{i:04d}" for i, ref in enumerate(sorted(set(refs), key=lambda r: (r.file, r.line, r.symbol, r.kind)), 1)}
        # Multi-project repos: a dependency of services/api is only used by files under services/api.
        roots = sorted({d.project for d in inp.repo_map.dependencies if d.project}, key=len, reverse=True)

        def owner(file: str) -> str:
            return next((p for p in roots if file.startswith(p + "/")), "")

        def in_project(ref: Ref, project: str) -> bool:
            return not roots or owner(ref.file) == project

        def site(ref: Ref, package: str, with_snippet: bool, matched: list[str] | None = None,
                 via: str | None = None) -> UsageSite:
            return UsageSite(id=ids[ref], package=package, file=ref.file, line=ref.line, kind=ref.kind,
                             symbol=ref.symbol, confidence=ref.confidence, in_test_path=is_test_path(ref.file),
                             snippet=snippet(sources[ref.file], ref.line) if with_snippet else None,
                             matched_vulns=matched or [], via=via)

        usages: dict[str, DependencyUsage] = {}
        imported = {r.symbol.split(".")[0] for r in refs}
        for dv in inp.vulnerable:
            dep = dv.dependency
            names, source = resolve_import_names(dep.name, dep.resolved_version, imported, self.pypi)
            vulns = dv.all_vulns()
            mine = [r for r in refs if belongs_to(r.symbol, names) and in_project(r, dep.project)]
            # Only uses (calls / attribute access) count as matching an advisory symbol; an import statement
            # alone (`from PIL import Image` vs. an advisory naming "PIL.Image") is too weak a signal.
            matched = {r: ([v.id for v in vulns if any(symbol_matches(r.symbol, s)
                                                       for s in v.advisory_symbols + v.affected_functions)]
                           if r.kind in ("call", "attribute", "regex") else [])
                       for r in mine}
            ranked = sorted(mine, key=lambda r: (not matched[r], is_test_path(r.file), r.file, r.line))
            with_snip = set(ranked[:MAX_SNIPPETS_PER_DEP])
            sites = [site(r, dep.name, r in with_snip, matched[r]) for r in mine]

            required_by = list(dep.required_by)
            indirect: list[UsageSite] = []
            if not mine:
                for parent in required_by:
                    pver = next((d.resolved_version for d in inp.repo_map.dependencies
                                 if d.name == parent and d.project == dep.project), None)
                    pnames, _ = resolve_import_names(parent, pver, imported, self.pypi)
                    prefs = sorted((r for r in refs if belongs_to(r.symbol, pnames) and in_project(r, dep.project)),
                                   key=lambda r: (is_test_path(r.file), r.kind == "import", r.file, r.line))
                    indirect += [site(r, parent, True, via=f"{parent} requires {dep.name}")
                                 for r in prefs[:MAX_INDIRECT_SITES - len(indirect)]]

            native: list[UsageSite] = []
            libs = sorted({lib for v in vulns if v.kind == "bundled_native"
                           for lib in native_libs_in(f"{v.summary}\n{v.details}")})
            if libs:
                reach = [(r, reaches(r.symbol, libs)) for r in refs if in_project(r, dep.project)]
                reach = sorted([(r, lib) for r, lib in reach if lib],
                               key=lambda x: (is_test_path(x[0].file), x[0].kind == "import", x[0].file, x[0].line))
                native = [site(r, dep.name, True, via=f"may reach bundled {lib} ({r.symbol})")
                          for r, lib in reach[:MAX_NATIVE_SITES]]

            if mine:
                status, note = "direct_usage", f"{len(mine)} usage site(s) in repository code"
            elif failures:
                status = "parse_incomplete"
                note = (f"No usage found, but {len(failures)} file(s) could not be parsed; "
                        "usage cannot be ruled out.")
            else:
                status = "no_direct_usage"
                note = ("Not imported directly by repository code"
                        + (f" — reached via {', '.join(required_by)}" if required_by else
                           " (it may still run as a server/CLI, a plugin, or through another dependency)")
                        + ". This does NOT mean the vulnerability does not affect the repo.")
            usages[dep.key] = DependencyUsage(
                package=dep.name, import_names=names, import_name_source=source, usage_status=status,
                required_by=required_by, sites=sites, indirect_sites=indirect, native_reach_sites=native, note=note)
        return UsageLocatorOutput(usages=usages, parse_failures=failures, files_scanned=len(inp.repo_map.source_files))


def snippet(lines: list[str], line: int, context: int = SNIPPET_CONTEXT) -> str:
    start, end = max(1, line - context), min(len(lines), line + context)
    return "\n".join(f"{n:>5}{'>' if n == line else ' '}| {lines[n - 1]}" for n in range(start, end + 1))


def site_matches_vuln(site: UsageSite, vuln: Vulnerability) -> bool:
    return vuln.id in site.matched_vulns


if __name__ == "__main__":  # python -m depscan.agents.usage_locator <repo-url-or-path>
    import sys

    from depscan.agents.cve_matcher import CVEMatcherAgent
    from depscan.agents.repo_mapper import RepoMapperAgent
    from depscan.config import load_config
    from depscan.models import CVEMatcherInput, RepoMapperInput

    cfg = load_config()
    repo = RepoMapperAgent(cfg.workspace).run(RepoMapperInput(url=sys.argv[1]))
    matched = CVEMatcherAgent.from_config(cfg).run(CVEMatcherInput(dependencies=repo.dependencies))
    out = UsageLocatorAgent().run(UsageLocatorInput(repo_map=repo, vulnerable=matched.results))
    print(f"{repo.repo_name}: {out.files_scanned} files scanned, {len(out.parse_failures)} parse failures\n")
    for name, u in out.usages.items():
        print(f"{name:<16} {u.usage_status:<17} import names {u.import_names} ({u.import_name_source})"
              + (f"  required_by={u.required_by}" if u.required_by else ""))
        for s in u.sites[:8]:
            flag = " *matches " + ",".join(s.matched_vulns) if s.matched_vulns else ""
            print(f"    {s.id} {s.file}:{s.line:<5} {s.kind:<14} {s.symbol}{' (test)' if s.in_test_path else ''}{flag}")
        for s in u.indirect_sites[:3] + u.native_reach_sites[:3]:
            print(f"    {s.id} {s.file}:{s.line:<5} {s.symbol}  [{s.via}]")
    for f in out.parse_failures:
        print("parse failure:", f)
