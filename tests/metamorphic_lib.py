"""Metamorphic testing of depscan's code-decided checks (T6).

A transformation rewrites a copy of a development test repo with libcst. Meaning-preserving ones must leave every
code-decided gate and status unchanged; meaning-changing ones must change one specific site in a known way.
No LLM is used (the stepwise agent runs with llm=None, so only code decides); OSV answers come from the cache.
The held-out repos (depscan-heldout-3/4/5) are never touched, and `.depscan/` (the answers) is never copied.
"""

import ast
import difflib
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import libcst as cst
from libcst.metadata import (Assignment, FunctionScope, GlobalScope, ImportAssignment, MetadataWrapper,
                             ScopeProvider)

from depscan.agents.stepwise import StepwiseAgent
from depscan.codeindex import CodeIndex
from depscan.config import Config
from depscan.orchestrator import Orchestrator

ROOT = Path(__file__).parent.parent
WORKSPACE = ROOT / "workspace"
FORBIDDEN = ("depscan-heldout-3", "depscan-heldout-4", "depscan-heldout-5")
SKIP_REPOS = {"depscan-test-suite", "depscan-test-manifests", "depscan-test-clean"}   # no code or no advisories
SUFFIX = "_mm"


def dev_repos() -> list[Path]:
    repos = []
    for p in sorted(WORKSPACE.glob("tulasinayak__depscan-*")):
        name = p.name.split("__", 1)[1]
        assert not any(f in name for f in FORBIDDEN), f"held-out repo {name} must never be used"
        if name not in SKIP_REPOS and p.is_dir():
            repos.append(p)
    return repos


def copy_repo(src: Path, dst: Path) -> Path:
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git", ".depscan", "__pycache__"))
    return dst


def py_files(repo: Path, tests: bool = False) -> list[Path]:
    out = []
    for p in sorted(repo.rglob("*.py")):
        rel = p.relative_to(repo).as_posix()
        if not tests and ("tests/" in rel or rel.startswith("test") or "/test_" in rel):
            continue
        out.append(p)
    return out


# ---------------------------------------------------------------- evaluation (no LLM)

@dataclass
class Outcome:
    status: str
    gates: dict[str, tuple[str, str]]          # gate -> (result, decided_by)
    record: object = None
    vuln: object = None
    dv: object = None

    def code_view(self) -> dict:
        return {"status": self.status, **{g: r for g, (r, by) in self.gates.items() if by == "code"}}


class Harness:
    """Scans a folder offline with the cached OSV answers and runs the stepwise gates without an LLM."""

    def __init__(self, tmp: Path):
        ws = tmp / "ws"
        ws.mkdir(parents=True, exist_ok=True)
        if not (ws / "cache.sqlite").exists():
            shutil.copy(WORKSPACE / "cache.sqlite", ws / "cache.sqlite")
        cfg = Config(workspace=ws, results=tmp / "results", logs=tmp / "logs", cache=ROOT / "cache",
                     overrides=tmp / "overrides")
        cfg.osv.offline = True
        self.orch = Orchestrator(cfg)
        self.store = self.orch.triggers("llm")

    def run(self, repo: Path) -> tuple[dict[str, Outcome], object, CodeIndex]:
        result = self.orch.scan(str(repo))
        index = CodeIndex(repo, result.repo.source_files, result.repo_context.app_type)
        agent = StepwiseAgent(self.store, index, None)
        out = {}
        for dv in result.vulnerabilities:
            for v in dv.vulnerabilities:
                rec = agent.run(result, dv, v)
                out[f"{dv.dependency.key}:{v.id}"] = Outcome(rec.status or "", {g.gate: (g.result, g.decided_by)
                                                                                for g in rec.gates}, rec, v, dv)
        return out, result, index


def diff_outcomes(before: dict[str, Outcome], after: dict[str, Outcome]) -> list[str]:
    lines = []
    for key in sorted(set(before) | set(after)):
        b, a = before.get(key), after.get(key)
        if b is None or a is None:
            lines.append(f"{key}: {'missing after' if a is None else 'new after'}")
            continue
        bv, av = b.code_view(), a.code_view()
        if bv != av:
            changed = {k: (bv.get(k), av.get(k)) for k in set(bv) | set(av) if bv.get(k) != av.get(k)}
            lines.append(f"{key}: " + ", ".join(f"{k} {x} -> {y}" for k, (x, y) in sorted(changed.items())))
    return lines


def file_diff(before: dict[str, str], repo: Path) -> str:
    out = []
    for rel, old in sorted(before.items()):
        path = repo / rel
        new = path.read_text(encoding="utf-8") if path.exists() else ""
        if new != old:
            out += difflib.unified_diff(old.splitlines(), new.splitlines(), f"a/{rel}", f"b/{rel}", lineterm="", n=1)
    for path in sorted(repo.rglob("*.py")):
        rel = path.relative_to(repo).as_posix()
        if rel not in before:
            out += [f"+++ new file {rel}"] + [f"+{x}" for x in path.read_text(encoding="utf-8").splitlines()[:20]]
    return "\n".join(out)


def snapshot(repo: Path) -> dict[str, str]:
    return {p.relative_to(repo).as_posix(): p.read_text(encoding="utf-8") for p in repo.rglob("*.py")}


# ---------------------------------------------------------------- helpers

def parse(path: Path) -> cst.Module:
    return cst.parse_module(path.read_text(encoding="utf-8"))


def save(path: Path, module: cst.Module) -> None:
    path.write_text(module.code, encoding="utf-8", newline="")


def keyword_names(repo: Path) -> set[str]:
    """Names used as keyword arguments anywhere (renaming such a parameter would break a call)."""
    names = set()
    for p in repo.rglob("*.py"):
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        names |= {k.arg for n in ast.walk(tree) if isinstance(n, ast.Call) for k in n.keywords if k.arg}
    return names


def strings_in(repo: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in repo.rglob("*.py"))


class _Rename(cst.CSTTransformer):
    def __init__(self, ids: set[int]):
        self.ids = ids

    def leave_Name(self, original: cst.Name, updated: cst.Name) -> cst.Name:
        return updated.with_changes(value=original.value + SUFFIX) if id(original) in self.ids else updated


def _uses_dynamic_locals(node: cst.CSTNode) -> bool:
    code = cst.Module(body=[]).code_for_node(node)
    return any(w in code for w in ("locals()", "vars()", "eval(", "exec("))


# ---------------------------------------------------------------- meaning-preserving transformations

@dataclass
class Change:
    name: str
    files: list[str] = field(default_factory=list)


def rename_locals(repo: Path) -> Change | None:
    """Rename local variables and parameters (not of decorated functions, not ones passed by keyword)."""
    kw = keyword_names(repo)
    changed = []
    for path in py_files(repo):
        wrapper = MetadataWrapper(parse(path))
        ids: set[int] = set()
        for scope in set(wrapper.resolve(ScopeProvider).values()):
            if not isinstance(scope, FunctionScope) or not isinstance(scope.node, cst.FunctionDef):
                continue
            fn = scope.node
            if _uses_dynamic_locals(fn):
                continue
            params = {p.name.value for p in [*fn.params.params, *fn.params.kwonly_params, *fn.params.posonly_params]}
            by_name: dict[str, list] = {}
            for a in scope.assignments:
                by_name.setdefault(a.name, []).append(a)
            for name, assigns in by_name.items():
                if name in ("self", "cls") or name.startswith("__") or name in kw or \
                        (name in params and fn.decorators):
                    continue
                nodes, ok = [], True
                for a in assigns:
                    if not isinstance(a, Assignment) or isinstance(a, ImportAssignment):
                        ok = False
                        break
                    n = a.node.name if isinstance(a.node, cst.Param) else a.node
                    if not isinstance(n, cst.Name):
                        ok = False
                        break
                    nodes.append(n)
                    for ref in a.references:
                        if not isinstance(ref.node, cst.Name):
                            ok = False
                        nodes.append(ref.node)
                if ok and nodes:
                    ids |= {id(n) for n in nodes}
        if ids:
            save(path, wrapper.visit(_Rename(ids)))
            changed.append(path.relative_to(repo).as_posix())
    return Change("rename locals and parameters", changed) if changed else None


def rename_private_functions(repo: Path) -> Change | None:
    """Rename module-level functions whose name starts with _ (only when no other file or string mentions them)."""
    everything = strings_in(repo)
    changed = []
    for path in py_files(repo):
        text = path.read_text(encoding="utf-8")
        wrapper = MetadataWrapper(parse(path))
        ids: set[int] = set()
        for scope in set(wrapper.resolve(ScopeProvider).values()):
            if not isinstance(scope, GlobalScope):
                continue
            for a in scope.assignments:
                if not (isinstance(a, Assignment) and isinstance(a.node, cst.FunctionDef)):
                    continue
                name = a.name
                if not name.startswith("_") or name.startswith("__"):
                    continue
                if everything.count(name) != text.count(name) or f"'{name}'" in text or f'"{name}"' in text:
                    continue
                if not all(isinstance(r.node, cst.Name) for r in a.references):
                    continue
                ids |= {id(a.node.name)} | {id(r.node) for r in a.references}
        if ids:
            save(path, wrapper.visit(_Rename(ids)))
            changed.append(path.relative_to(repo).as_posix())
    return Change("rename private functions", changed) if changed else None


def _top_imports(module: cst.Module) -> list[cst.SimpleStatementLine]:
    return [s for s in module.body if isinstance(s, cst.SimpleStatementLine)
            and any(isinstance(x, (cst.Import, cst.ImportFrom)) for x in s.body)]


def _insert_after_imports(module: cst.Module, stmt: cst.BaseStatement) -> cst.Module:
    body = list(module.body)
    idx = max((i for i, s in enumerate(body) if s in _top_imports(module)), default=-1)
    if idx < 0 and body and isinstance(body[0], cst.SimpleStatementLine) and \
            isinstance(body[0].body[0], cst.Expr) and isinstance(body[0].body[0].value, cst.SimpleString):
        idx = 0                                     # after the module docstring
    body.insert(idx + 1, stmt)
    return module.with_changes(body=body)


def move_function(repo: Path, pick: int = 0) -> Change | None:
    """Move an undecorated module-level function that only uses imports, builtins and its own names to a new
    module in the same folder, and import it back."""
    cands = []
    for path in py_files(repo):
        wrapper = MetadataWrapper(parse(path))
        scopes = wrapper.resolve(ScopeProvider)
        module = wrapper.module
        glob = scopes[module]
        own = {a.name for a in glob.assignments if not isinstance(a, ImportAssignment)}
        for stmt in module.body:
            if not isinstance(stmt, cst.FunctionDef) or stmt.decorators or stmt.name.value.startswith("__"):
                continue
            free = set()
            for sc in set(scopes.values()):
                if sc is not None and sc is not glob and _within(sc, stmt):
                    for acc in sc.accesses:
                        for ref in acc.referents:
                            if ref.scope is glob and not isinstance(ref, ImportAssignment):
                                free.add(acc.node.value if isinstance(acc.node, cst.Name) else "?")
            if free <= {stmt.name.value} and stmt.name.value in own:
                cands.append((path, stmt.name.value))
    if not cands:
        return None
    path, name = cands[pick % len(cands)]
    module = parse(path)
    fn = next(s for s in module.body if isinstance(s, cst.FunctionDef) and s.name.value == name)
    new_rel = f"_moved_{name}{SUFFIX}"
    header = [s for s in _top_imports(module)]
    (path.parent / f"{new_rel}.py").write_text(cst.Module(body=[*header, fn]).code, encoding="utf-8", newline="")
    in_pkg = (path.parent / "__init__.py").exists()
    imp = cst.parse_statement(f"from {'.' if in_pkg else ''}{new_rel} import {name}\n")
    module = module.with_changes(body=[s for s in module.body if s is not fn])
    save(path, _insert_after_imports(module, imp))
    rel = path.relative_to(repo).as_posix()
    return Change(f"move {name} from {rel} to {new_rel}.py", [rel, (path.parent / f"{new_rel}.py").relative_to(repo).as_posix()])


def _within(scope, node: cst.CSTNode) -> bool:
    cur = scope
    while cur is not None and not isinstance(cur, GlobalScope):
        if getattr(cur, "node", None) is node:
            return True
        cur = cur.parent
    return False


def add_unused_code(repo: Path) -> Change | None:
    """An unused import and an unused wrapper around an existing function in each module, plus a dead helper
    module that nothing imports."""
    changed = []
    for i, path in enumerate(py_files(repo)):
        module = parse(path)
        fns = [s.name.value for s in module.body if isinstance(s, cst.FunctionDef) and not s.name.value.startswith("__")]
        module = _insert_after_imports(module, cst.parse_statement(f"import json as _unused_json{SUFFIX}\n"))
        if fns:
            wrapper = cst.parse_statement(f"def _unused_wrapper{SUFFIX}(*args, **kwargs):\n"
                                          f"    return {fns[0]}(*args, **kwargs)\n")
            module = module.with_changes(body=[*module.body, wrapper])
        save(path, module)
        changed.append(path.relative_to(repo).as_posix())
    pkg = next((p.parent for p in py_files(repo) if p.name == "__init__.py"), repo)
    (pkg / f"_dead_helper{SUFFIX}.py").write_text("def helper(value):\n    return value\n", encoding="utf-8")
    return Change("add an unused import, an unused wrapper and a dead helper module", changed)


def reorder_definitions(repo: Path) -> Change | None:
    """Reverse each run of consecutive module-level function and class definitions."""
    changed = []
    for path in py_files(repo):
        module = parse(path)
        body, out, run = list(module.body), [], []
        for s in body + [None]:
            if isinstance(s, (cst.FunctionDef, cst.ClassDef)):
                run.append(s)
                continue
            out += list(reversed(run)) if len(run) > 1 else run
            run = []
            if s is not None:
                out.append(s)
        if [id(x) for x in out] != [id(x) for x in body]:
            save(path, module.with_changes(body=out))
            changed.append(path.relative_to(repo).as_posix())
    return Change("reorder functions and classes", changed) if changed else None


class _AddNoise(cst.CSTTransformer):
    def leave_FunctionDef(self, original, updated):
        body = updated.body
        if isinstance(body, cst.IndentedBlock) and not _has_docstring(body.body):
            doc = cst.SimpleStatementLine([cst.Expr(cst.SimpleString('"""Added description."""'))])
            body = body.with_changes(body=[doc, *body.body])
        return updated.with_changes(body=body, leading_lines=[*updated.leading_lines, cst.EmptyLine(),
                                                              cst.EmptyLine(comment=cst.Comment("# added comment"))])

    def leave_SimpleStatementLine(self, original, updated):
        return updated.with_changes(leading_lines=[*updated.leading_lines, cst.EmptyLine(
            comment=cst.Comment("# another comment"))])


class _StripNoise(cst.CSTTransformer):
    def leave_EmptyLine(self, original, updated):
        return cst.RemoveFromParent() if updated.comment is not None else updated

    def leave_TrailingWhitespace(self, original, updated):
        return updated.with_changes(comment=None, whitespace=cst.SimpleWhitespace(""))

    def leave_IndentedBlock(self, original, updated):
        body = [s for i, s in enumerate(updated.body) if not (i == 0 and _is_doc(s))]
        return updated.with_changes(body=body or [cst.SimpleStatementLine([cst.Pass()])])

    def leave_Module(self, original, updated):
        body = [s for i, s in enumerate(updated.body) if not (i == 0 and _is_doc(s))]
        return updated.with_changes(body=body, header=[h for h in updated.header if h.comment is None])


def _is_doc(s) -> bool:
    return isinstance(s, cst.SimpleStatementLine) and len(s.body) == 1 and isinstance(s.body[0], cst.Expr) \
        and isinstance(s.body[0].value, (cst.SimpleString, cst.ConcatenatedString))


def _has_docstring(stmts) -> bool:
    return bool(stmts) and _is_doc(stmts[0])


def add_comments_and_docstrings(repo: Path) -> Change | None:
    changed = []
    for path in py_files(repo):
        save(path, parse(path).visit(_AddNoise()))
        changed.append(path.relative_to(repo).as_posix())
    return Change("add comments, docstrings and blank lines", changed)


def strip_comments_and_docstrings(repo: Path) -> Change | None:
    changed = []
    for path in py_files(repo):
        before = path.read_text(encoding="utf-8")
        save(path, parse(path).visit(_StripNoise()))
        if path.read_text(encoding="utf-8") != before:
            changed.append(path.relative_to(repo).as_posix())
    return Change("remove comments, docstrings and blank lines", changed) if changed else None


class _Names(ast.NodeVisitor):
    def __init__(self):
        self.stores, self.loads, self.bad = set(), set(), False

    def visit_Name(self, n):
        (self.stores if isinstance(n.ctx, (ast.Store, ast.Del)) else self.loads).add(n.id)

    def visit_arg(self, n):
        self.stores.add(n.arg)

    def generic_visit(self, n):
        if isinstance(n, (ast.Return, ast.Yield, ast.YieldFrom, ast.Global, ast.Nonlocal, ast.Await)):
            self.bad = True
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            self.stores |= {(a.asname or a.name).split(".")[0] for a in n.names}
        super().generic_visit(n)


def split_function(repo: Path, pick: int = 0) -> Change | None:
    """Split a module-level function: its second half moves into a new function that the first half calls."""
    cands = []
    for path in py_files(repo):
        module = parse(path)
        for stmt in module.body:
            if not isinstance(stmt, cst.FunctionDef) or stmt.asynchronous or not isinstance(stmt.body, cst.IndentedBlock):
                continue
            ps = stmt.params
            if ps.star_arg not in (None, cst.MaybeSentinel.DEFAULT) or ps.star_kwarg or ps.kwonly_params \
                    or ps.posonly_params:
                continue
            body = list(stmt.body.body)
            for k in range(len(body) - 1, 0, -1):
                head_src = cst.Module(body=body[:k]).code
                tail_src = cst.Module(body=body[k:]).code
                try:
                    h, t = ast.parse(head_src), ast.parse(tail_src)
                except SyntaxError:
                    continue
                hv, tv = _Names(), _Names()
                hv.visit(h)
                tv.visit(t)
                tv_yield = any(isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await, ast.Global, ast.Nonlocal))
                               for n in ast.walk(t))
                if hv.bad or tv_yield or hv.stores & tv.loads:
                    continue
                cands.append((path, stmt.name.value, k))
                break
    if not cands:
        return None
    path, name, k = cands[pick % len(cands)]
    module = parse(path)
    fn = next(s for s in module.body if isinstance(s, cst.FunctionDef) and s.name.value == name)
    params = [p.name.value for p in fn.params.params]
    helper_name = f"{name}_part2{SUFFIX}"
    body = list(fn.body.body)
    call = cst.parse_statement(f"return {helper_name}({', '.join(params)})\n")
    new_fn = fn.with_changes(body=fn.body.with_changes(body=[*body[:k], call]))
    helper = cst.FunctionDef(name=cst.Name(helper_name),
                             params=cst.Parameters(params=[cst.Param(cst.Name(p)) for p in params]),
                             body=cst.IndentedBlock(body=body[k:]))
    out = []
    for s in module.body:
        out += [new_fn, helper] if s is fn else [s]
    save(path, module.with_changes(body=out))
    return Change(f"split {name} after statement {k}", [path.relative_to(repo).as_posix()])


PRESERVING = {
    "rename_locals": rename_locals,
    "rename_private_functions": rename_private_functions,
    "move_function": move_function,
    "move_function_2": lambda r: move_function(r, 1),
    "add_unused_code": add_unused_code,
    "reorder_definitions": reorder_definitions,
    "add_comments_and_docstrings": add_comments_and_docstrings,
    "strip_comments_and_docstrings": strip_comments_and_docstrings,
    "split_function": split_function,
    "split_function_2": lambda r: split_function(r, 1),
}


# ---------------------------------------------------------------- meaning-changing transformations

@dataclass
class Site:
    file: str
    line: int
    symbol: str
    input_arg: str | None = None


def _call_at(module_src: str, line: int, symbol: str) -> ast.Call | None:
    tree = ast.parse(module_src)
    last = symbol.split(".")[-1]
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == line]
    named = [c for c in calls if ast.unparse(c.func).split(".")[-1] == last]
    return (named or calls or [None])[0]


def constant_argument(repo: Path, site: Site) -> bool:
    """Replace the input argument(s) of the call at the site with a string constant."""
    path = repo / site.file
    src = path.read_text(encoding="utf-8")
    call = _call_at(src, site.line, site.symbol)
    if call is None or not (call.args or call.keywords):
        return False
    key = str(site.input_arg).strip() if site.input_arg is not None else None
    targets = []
    if key and key.isdigit() and int(key) < len(call.args):
        targets = [call.args[int(key)]]
    elif key:
        targets = [k.value for k in call.keywords if k.arg == key]
    if not targets:
        targets = [*call.args, *[k.value for k in call.keywords]]
    if any(isinstance(t, ast.Starred) for t in targets):
        return False
    lines = src.splitlines(keepends=True)
    offsets = [0]
    for ln in lines:
        offsets.append(offsets[-1] + len(ln))
    for t in sorted(targets, key=lambda t: (t.lineno, t.col_offset), reverse=True):
        a = offsets[t.lineno - 1] + _col(lines[t.lineno - 1], t.col_offset)
        b = offsets[t.end_lineno - 1] + _col(lines[t.end_lineno - 1], t.end_col_offset)
        src = src[:a] + '"fixed-value"' + src[b:]
    path.write_text(src, encoding="utf-8", newline="")
    return True


def _col(line: str, byte_col: int) -> int:
    return len(line.encode("utf-8")[:byte_col].decode("utf-8", errors="ignore"))


def insert_return(repo: Path, site: Site) -> bool:
    """Put `return None` right before the statement holding the call (inside a function only)."""
    path = repo / site.file
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    target = None
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(fn):
                for attr in ("body", "orelse", "finalbody", "handlers"):
                    block = getattr(node, attr, None)
                    if isinstance(block, list):
                        for stmt in block:
                            if isinstance(stmt, ast.stmt) and stmt.lineno <= site.line <= stmt.end_lineno and \
                                    not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If,
                                                          ast.For, ast.While, ast.With, ast.Try, ast.AsyncWith,
                                                          ast.AsyncFor)):
                                target = stmt
    if target is None:
        return False
    lines = src.splitlines(keepends=True)
    line = lines[target.lineno - 1]
    indent = line[:len(line) - len(line.lstrip())]
    lines.insert(target.lineno - 1, f"{indent}return None\n")
    path.write_text("".join(lines), encoding="utf-8", newline="")
    return True


def remove_only_import(repo: Path, index: CodeIndex, site: Site) -> bool:
    """Remove the import statements of the one module that imports the site's module."""
    mod = index.modules.get(site.file)
    if mod is None or mod.entry:
        return False
    importers = [m for m in index.modules.values() if site.file in m.imports]
    if len(importers) != 1:
        return False
    imp = importers[0]
    dotted = next((n for n, rel in index.by_name.items() if rel == site.file), None)
    if dotted is None:
        return False
    src = (repo / imp.rel).read_text(encoding="utf-8")
    if f'"{dotted}"' in src or f"'{dotted}'" in src:
        return False
    tree = ast.parse(src)
    drop = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if _imports_module(node, imp.rel, dotted, index):
                drop.append(node)
    if not drop:
        return False
    lines = src.splitlines(keepends=True)
    for node in sorted(drop, key=lambda n: n.lineno, reverse=True):
        del lines[node.lineno - 1:node.end_lineno]
        lines.insert(node.lineno - 1, "\n" * (node.end_lineno - node.lineno + 1))   # keep line numbers stable
    (repo / imp.rel).write_text("".join(lines), encoding="utf-8", newline="")
    return True


def _imports_module(node, rel: str, dotted: str, index: CodeIndex) -> bool:
    from depscan.codeindex import _relative_base
    if isinstance(node, ast.Import):
        return any(a.name == dotted or a.name.startswith(dotted + ".") for a in node.names)
    base = node.module if node.level == 0 else _relative_base(rel, node.level, node.module)
    if not base:
        return False
    return base == dotted or base.startswith(dotted + ".") or any(f"{base}.{a.name}" == dotted for a in node.names)
