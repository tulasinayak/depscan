"""CodeIndex (deterministic): which code can run, and where do the values it uses come from?

Built once per scan from the repository's .py files (parsed with ast, never imported or executed) and used by
the stepwise check's `reachable`, `dangerous_form` and `attacker_input` gates.

- Module graph: entry modules (app factories, route handlers, app instances, __main__ blocks, console scripts,
  modules named in Procfile/Dockerfile/...) and everything they import. Test modules are separate roots.
- Function graph (by name, so it over-approximates): a function is reachable when code that runs refers to it
  (call, callback, decorator registration, __all__). References are weighted by the statement they sit in:
  dead (after return/raise, under `if False:`), conditional (under a config/env check) or live.
- Taint: request.* / sys.argv / input() / route and CLI parameters, followed through assignments, simple calls
  and up to two levels of callers.

Every answer errs towards "can run" and "may be attacker-controlled": the gates may only say "fail" (not
affected) on definite evidence, so anything dynamic (getattr with a computed name, import_module(variable),
globals()) turns a would-be "fail" into "unknown".
"""

import ast
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from depscan.agents.repo_context import APP_CLASSES, FACTORY_NAMES, REQUEST_INPUTS, ROUTE_METHODS, console_scripts
from depscan.agents.repo_mapper import SKIP_DIRS
from depscan.safety import read_text
from depscan.agents.usage_locator import (
    MAX_REEXPORT_HOPS, _analyze, _dotted, _relative_base, is_test_path, module_bindings, module_name,
)

LIVE, COND, TEST, NONE = 3, 2, 1, 0
ENTRY_FILES = {"wsgi.py", "asgi.py", "manage.py", "__main__.py", "main.py", "app.py", "run.py", "server.py"}
CONFIG_FILE = re.compile(r"^(Procfile|Dockerfile.*|docker-compose.*\.ya?ml|Makefile|.*\.sh|.*\.ini|.*\.cfg|"
                         r".*\.toml|.*\.service|.*\.conf)$", re.I)
NON_REGISTERING = {"staticmethod", "classmethod", "property", "cached_property", "wraps", "lru_cache", "cache",
                   "abstractmethod", "override", "overload", "setter", "getter", "deleter", "contextmanager",
                   "asynccontextmanager", "total_ordering", "singledispatch", "singledispatchmethod", "deprecated"}
SUPPRESSING_CM = re.compile(r"suppress|ExitStack|raises|assertRaises|ignore", re.I)
CONFIG_WORDS = re.compile(r"environ|getenv|config|settings|\bconf\b|options|flags?\b|feature", re.I)
FLAG_WORDS = re.compile(r"ENABLE|FLAG|FEATURE|ALLOW|DEBUG|^USE_|_MODE$|TOGGLE", re.I)
UPPER = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
CLI_DECORATORS = {"command", "group", "argument", "option", "callback"}
DYNAMIC_IMPORT_FNS = {"import_module", "__import__", "spec_from_file_location", "run_module", "run_path",
                      "walk_packages", "iter_modules", "load_entry_point", "entry_points"}


@dataclass
class Func:
    key: str                     # "app/tokens.py::TokenBox.open"
    name: str                    # "open"
    file: str
    node: ast.AST                # FunctionDef / AsyncFunctionDef / Lambda
    params: list[str]
    decorators: list[list[str]]  # dotted decorator chains
    cls: str | None = None       # class key for methods
    static: bool = False

    @property
    def line(self) -> int:
        return self.node.lineno

    @property
    def label(self) -> str:
        return f"{self.key.split('::', 1)[1]}()"


@dataclass
class Klass:
    key: str
    name: str
    file: str
    node: ast.ClassDef
    external_base: bool          # extends something not defined in this repository (a framework may call it)
    methods: list[str] = field(default_factory=list)


@dataclass
class Module:
    rel: str
    name: str
    source: str
    tree: ast.Module
    lines: list[str]
    parents: dict
    is_test: bool
    bindings: dict[str, str] = field(default_factory=dict)
    imports: set[str] = field(default_factory=set)       # repo modules this one imports (anywhere in the file)
    entry: str = ""                                       # why this module is an entry module ("" = it is not)
    config_names: set[str] = field(default_factory=set)  # module globals read from env/config


@dataclass
class Status:
    """Where a statement stands inside its function: live, conditional (config flag) or dead."""
    state: str = "live"          # live | conditional | dead
    why: str = ""
    flag: str = ""


@dataclass
class Reach:
    result: str                  # pass | fail | unknown
    explanation: str
    evidence: list[tuple[str, str]] = field(default_factory=list)   # (text, "file:line")


@dataclass
class Taint:
    state: str                   # tainted | constant | partial | unknown
    why: str = ""
    cite: str = ""               # file:line of the source / constant

    def __iter__(self):
        return iter((self.state, self.why, self.cite))


# ---------------------------------------------------------------- small AST helpers

def const_truth(test: ast.AST) -> bool | None:
    """True/False when a condition is constant at runtime, else None."""
    if isinstance(test, ast.Constant):
        return bool(test.value)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = const_truth(test.operand)
        return None if inner is None else not inner
    if isinstance(test, ast.BoolOp):
        values = [const_truth(v) for v in test.values]
        if isinstance(test.op, ast.And) and False in values:
            return False
        if isinstance(test.op, ast.Or) and True in values:
            return True
    chain = _dotted(test)
    if chain and chain[-1] == "TYPE_CHECKING":
        return False
    return None


def _exit_call(stmt: ast.stmt) -> bool:
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        return _dotted(stmt.value.func) in (["sys", "exit"], ["os", "_exit"], ["exit"], ["quit"])
    return False


def terminates(stmts: list[ast.stmt]) -> ast.stmt | None:
    """The statement after which nothing more in this block can run, or None."""
    for s in stmts:
        if _terminates(s):
            return s
    return None


def _terminates(s: ast.stmt) -> bool:
    if isinstance(s, (ast.Return, ast.Raise, ast.Continue, ast.Break)) or _exit_call(s):
        return True
    if isinstance(s, ast.If):
        truth = const_truth(s.test)
        if truth is True:
            return terminates(s.body) is not None
        if truth is False:
            return terminates(s.orelse) is not None
        return bool(s.orelse) and terminates(s.body) is not None and terminates(s.orelse) is not None
    if isinstance(s, (ast.With, ast.AsyncWith)):
        managers = " ".join(ast.unparse(i.context_expr) for i in s.items)
        return not SUPPRESSING_CM.search(managers) and terminates(s.body) is not None
    if isinstance(s, ast.Try):
        if s.finalbody and terminates(s.finalbody):
            return True
        return terminates(s.body) is not None and all(terminates(h.body) is not None for h in s.handlers)
    if isinstance(s, ast.While) and const_truth(s.test) is True:
        return not any(isinstance(n, ast.Break) for n in _walk_loop_body(s.body))
    return False


def _walk_loop_body(stmts: list[ast.stmt]):
    """Nodes of a loop body, not descending into nested loops or functions (their break is their own)."""
    todo = list(stmts)
    while todo:
        n = todo.pop()
        yield n
        if isinstance(n, (ast.For, ast.AsyncFor, ast.While, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        todo.extend(ast.iter_child_nodes(n))


def _segment(node: ast.AST, limit: int = 70) -> str:
    text = " ".join(ast.unparse(node).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _is_docstring(node: ast.AST, parents: dict) -> bool:
    p = parents.get(node)
    return isinstance(p, ast.Expr) and isinstance(parents.get(p), (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                                                     ast.ClassDef))


def value_text(node: ast.AST | None, resolve) -> list[str]:
    """How an argument value compares against a spec: ['False'], ['FullLoader', 'yaml.FullLoader']."""
    if node is None:
        return []
    if isinstance(node, ast.Constant):
        return [str(node.value)]
    sym = resolve(node)
    chain = _dotted(node)
    out = []
    for s in ([sym] if sym else []) + ([".".join(chain)] if chain else []):
        out += [s, s.split(".")[-1]]
    return list(dict.fromkeys(out))


# ---------------------------------------------------------------- the index

class CodeIndex:
    def __init__(self, root: Path, files: list[str], app_type: str = "unknown"):
        self.root = Path(root)
        self.app_type = app_type
        self.modules: dict[str, Module] = {}
        self.by_name: dict[str, str] = {}             # dotted module name -> rel
        self.funcs: dict[str, Func] = {}
        self.func_by_node: dict[int, Func] = {}
        self.classes: dict[str, Klass] = {}
        self.parse_failures: list[str] = []
        self.dynamic: list[str] = []                  # "file:line what" - dynamic dispatch / imports seen in prod code
        self.dynamic_imports: list[str] = []
        self.strings: dict[str, list[str]] = {}       # string constants (prod code, no docstrings) -> file:line
        self.config_text = self._config_text()
        self._reexports: dict[str, dict[str, str]] = {}
        self._load(files)
        self._index_defs()
        self._module_levels()
        self._refs()
        self._function_levels()

    # ------------------------------------------------------------ building

    def _config_text(self) -> str:
        """Procfile, Dockerfile, *.ini, ... (never .depscan): modules or functions named there are entry points."""
        chunks = []
        for path in sorted(self.root.rglob("*")) if self.root.exists() else []:
            rel = path.relative_to(self.root).parts
            if any(p in SKIP_DIRS or p.endswith(".egg-info") for p in rel[:-1]):
                continue
            if CONFIG_FILE.match(path.name):
                text = read_text(self.root, path, 200_000)     # never through a link, never outside the repo
                if text is not None:
                    chunks.append(text)
        return "\n".join(chunks)

    def _load(self, files: list[str]) -> None:
        texts = {}
        for rel in files:
            raw = (self.root / rel).read_bytes()
            try:
                texts[rel] = raw.decode("utf-8")
            except UnicodeDecodeError:
                texts[rel] = raw.decode("latin-1")
        for rel, text in texts.items():
            try:
                self._reexports[module_name(rel)] = module_bindings(text, rel)
            except (SyntaxError, ValueError, RecursionError):
                pass
        for rel, text in texts.items():
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    tree = ast.parse(text, filename=rel)
                bindings = _analyze(text, rel, self._reexports)[1]
            except (SyntaxError, ValueError, RecursionError) as e:
                self.parse_failures.append(f"{rel}: {type(e).__name__}")
                continue
            parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
            mod = Module(rel=rel, name=module_name(rel), source=text, tree=tree, lines=text.splitlines(),
                         parents=parents, is_test=is_test_path(rel), bindings=bindings)
            self.modules[rel] = mod
            self.by_name[mod.name] = rel

    def translate(self, symbol: str) -> str:
        for _ in range(MAX_REEXPORT_HOPS):
            parts = symbol.split(".")
            hit = next(((i, self._reexports[".".join(parts[:i])][parts[i]]) for i in range(len(parts) - 1, 0, -1)
                        if parts[i] in self._reexports.get(".".join(parts[:i]), {})), None)
            if hit is None or hit[1] == symbol:
                return symbol
            symbol = ".".join([hit[1], *parts[hit[0] + 1:]])
        return symbol

    def resolve(self, mod: Module, expr: ast.AST) -> str | None:
        """Fully qualified symbol of a Name/Attribute chain, through imports, aliases and re-exports."""
        chain = _dotted(expr)
        if chain and chain[0] in mod.bindings:
            return self.translate(".".join([mod.bindings[chain[0]], *chain[1:]]))
        return None

    def _index_defs(self) -> None:
        local_classes = {n.name for m in self.modules.values() for n in ast.walk(m.tree) if isinstance(n, ast.ClassDef)}
        for mod in self.modules.values():
            self._defs(mod, mod.tree.body, prefix="", cls=None, local_classes=local_classes)
            for node in ast.walk(mod.tree):
                # lambdas assigned to a name behave like functions: list_members = lambda stream: ...
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda) and len(node.targets) == 1 \
                        and isinstance(node.targets[0], ast.Name):
                    name = node.targets[0].id
                    f = Func(key=f"{mod.rel}::{name}", name=name, file=mod.rel, node=node.value,
                             params=[a.arg for a in node.value.args.args], decorators=[])
                    self.funcs.setdefault(f.key, f)
                    self.func_by_node[id(node.value)] = self.funcs[f.key]
                self._scan_module_facts(mod, node)
            self._imports(mod)
            mod.entry = self._entry_reason(mod)

    def _defs(self, mod: Module, body: list, prefix: str, cls: str | None, local_classes: set[str]) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}{node.name}"
                decorators = [(_dotted(d.func if isinstance(d, ast.Call) else d) or ["?"]) for d in node.decorator_list]
                params = [a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
                f = Func(key=f"{mod.rel}::{qual}", name=node.name, file=mod.rel, node=node, params=params,
                         decorators=decorators, cls=cls, static=any(d[-1] == "staticmethod" for d in decorators))
                self.funcs[f.key] = f
                self.func_by_node[id(node)] = f
                if cls:
                    self.classes[cls].methods.append(f.key)
                self._defs(mod, node.body, prefix=f"{qual}.", cls=None, local_classes=local_classes)
            elif isinstance(node, ast.ClassDef):
                qual = f"{prefix}{node.name}"
                bases = [_dotted(b) for b in node.bases]
                external = any(b is None or (b[-1] not in local_classes and b != ["object"]) for b in bases)
                key = f"{mod.rel}::{qual}"
                self.classes[key] = Klass(key=key, name=node.name, file=mod.rel, node=node, external_base=external)
                self._defs(mod, node.body, prefix=f"{qual}.", cls=key, local_classes=local_classes)
            elif isinstance(node, (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For, ast.While)):
                for block in ("body", "orelse", "finalbody"):
                    self._defs(mod, getattr(node, block, []) or [], prefix, cls, local_classes)
                for h in getattr(node, "handlers", []) or []:
                    self._defs(mod, h.body, prefix, cls, local_classes)

    def _scan_module_facts(self, mod: Module, node: ast.AST) -> None:
        where = f"{mod.rel}:{getattr(node, 'lineno', 0)}"
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and not mod.is_test \
                and not _is_docstring(node, mod.parents) and len(node.value) < 200:
            self.strings.setdefault(node.value, []).append(where)
        if isinstance(node, ast.Call) and not mod.is_test:
            fn = _dotted(node.func) or []
            computed = node.args and not isinstance(node.args[0], ast.Constant)
            if fn and fn[-1] in DYNAMIC_IMPORT_FNS and (computed or fn[-1] not in ("import_module", "__import__")):
                self.dynamic_imports.append(f"{where} {_segment(node, 60)}")
            if fn == ["getattr"] and len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
                self.dynamic.append(f"{where} {_segment(node, 60)}")
            if fn in (["globals"], ["locals"], ["vars"]) and isinstance(mod.parents.get(node), ast.Subscript):
                self.dynamic.append(f"{where} {_segment(mod.parents[node], 60)}")
        if isinstance(node, ast.Assign) and mod.parents.get(node) is mod.tree:
            if CONFIG_WORDS.search(ast.unparse(node.value)):
                mod.config_names |= {t.id for t in node.targets if isinstance(t, ast.Name)}

    def _imports(self, mod: Module) -> None:
        def add(name: str) -> None:
            parts = name.split(".")
            for i in range(1, len(parts) + 1):       # importing a.b.c also runs a/__init__ and a/b/__init__
                target = self.by_name.get(".".join(parts[:i]))
                if target and target != mod.rel:
                    mod.imports.add(target)

        for node in ast.walk(mod.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    add(a.name)
            elif isinstance(node, ast.ImportFrom):
                base = node.module if node.level == 0 else _relative_base(mod.rel, node.level, node.module)
                if not base:
                    continue
                add(base)
                for a in node.names:
                    if a.name != "*":
                        add(f"{base}.{a.name}")        # `from app import routes` imports the module app.routes
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in self.by_name:
                add(node.value)                        # import_module("app.x"), celery include=["app.tasks"], ...

    def _entry_reason(self, mod: Module) -> str:
        if mod.is_test:
            return ""
        base = mod.rel.rsplit("/", 1)[-1]
        for node in ast.walk(mod.tree):
            if isinstance(node, ast.If):
                t = node.test
                if isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "__name__" \
                        and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in t.comparators):
                    return f"__main__ block (line {node.lineno})"
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in FACTORY_NAMES:
                    return f"app factory {node.name}() (line {node.lineno})"
                if any(self._is_route(d) for d in node.decorator_list):
                    return f"route handler {node.name}() (line {node.lineno})"
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) \
                    and mod.parents.get(node) is mod.tree:
                fn = _dotted(node.value.func) or []
                if fn and fn[-1] in APP_CLASSES:
                    return f"app instance {fn[-1]}(...) (line {node.lineno})"
        if base in ENTRY_FILES:
            return f"{base} is a conventional entry file"
        for script in console_scripts(self.root):
            if re.search(rf"[=\s]{re.escape(mod.name)}(:|\s*$)", script):
                return script
        if mod.name and re.search(rf"(?<![\w.]){re.escape(mod.name)}(?![\w])|{re.escape(mod.rel)}", self.config_text):
            return "named in a Procfile / Dockerfile / config file"
        return ""

    @staticmethod
    def _is_route(dec: ast.AST) -> bool:
        chain = _dotted(dec.func if isinstance(dec, ast.Call) else dec) or []
        return len(chain) >= 2 and chain[-1] in ROUTE_METHODS

    @staticmethod
    def _is_cli(dec_chain: list[str]) -> bool:
        return len(dec_chain) >= 2 and dec_chain[-1] in CLI_DECORATORS

    # ------------------------------------------------------------ scopes and statements

    def scope_of(self, mod: Module, node: ast.AST) -> Func | None:
        """The innermost function (or assigned lambda) whose body contains node; None = module level."""
        child, cur = node, mod.parents.get(node)
        while cur is not None:
            f = self.func_by_node.get(id(cur))
            if f is not None:
                body = cur.body if isinstance(cur.body, list) else [cur.body]
                if any(child is b for b in body):
                    return f
            child, cur = cur, mod.parents.get(cur)
        return None

    def config_flag(self, mod: Module, test: ast.AST) -> str:
        """The setting a condition depends on ("ENABLE_CUSTOM_TEMPLATES"), or "" if it is not a config check."""
        text = ast.unparse(test)
        names = [n.id for n in ast.walk(test) if isinstance(n, ast.Name)]
        keys = [n.value for n in ast.walk(test) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        flag_like = [k for k in keys + names if UPPER.match(k) and (FLAG_WORDS.search(k) or k in mod.config_names)]
        if CONFIG_WORDS.search(text) or flag_like or any(n in mod.config_names for n in names):
            return next(iter(flag_like), None) or next((k for k in keys if UPPER.match(k)), None) or _segment(test, 50)
        return ""

    def stmt_status(self, mod: Module, node: ast.AST, scope: Func | None) -> Status:
        stop = scope.node if scope else mod.tree
        cur, cond = node, None
        while cur is not stop and cur in mod.parents:
            parent = mod.parents[cur]
            for fname in ("body", "orelse", "finalbody"):
                block = getattr(parent, fname, None)
                if not isinstance(block, list) or not any(cur is s for s in block):
                    continue
                idx = next(i for i, s in enumerate(block) if s is cur)
                for prev in block[:idx]:
                    if _terminates(prev):
                        what = type(prev).__name__.lower()
                        what = {"with": "`with` block", "asyncwith": "`with` block", "if": "`if` block",
                                "try": "`try` block", "expr": "exit call"}.get(what, what)
                        return Status("dead", f"it comes after the {what} on line {prev.lineno}, which always "
                                              "returns or raises first")
                    if isinstance(prev, ast.If) and not prev.orelse and terminates(prev.body) is not None:
                        if const_truth(prev.test) is True:
                            return Status("dead", f"`if {_segment(prev.test, 40)}:` on line {prev.lineno} always "
                                                  "returns first")
                        flag = self.config_flag(mod, prev.test)
                        if flag and cond is None:
                            cond = Status("conditional", f"line {prev.lineno} returns early unless {flag} is set",
                                          flag)
                if isinstance(parent, (ast.If, ast.While)):
                    truth = const_truth(parent.test)
                    if (fname == "body" and truth is False) or (fname == "orelse" and truth is True):
                        return Status("dead", f"it sits under `{'if' if isinstance(parent, ast.If) else 'while'} "
                                              f"{_segment(parent.test, 40)}:` (line {parent.lineno}), which is never "
                                              "true" if fname == "body" else "always true")
                    if isinstance(parent, ast.If) and truth is None and cond is None:
                        flag = self.config_flag(mod, parent.test)
                        if flag:
                            cond = Status("conditional", f"it only runs when {flag} is set (line {parent.lineno})",
                                          flag)
                break
            cur = parent
        return cond or Status()

    # ------------------------------------------------------------ module and function reachability

    def _module_levels(self) -> None:
        self.library_mode = not any(m.entry for m in self.modules.values()) or self.app_type == "library"
        level: dict[str, int] = {}
        self.module_via: dict[str, str] = {}
        todo = []
        for rel, m in self.modules.items():
            if m.is_test:
                level[rel] = TEST
            elif m.entry or self.library_mode:
                level[rel] = LIVE
                self.module_via[rel] = m.entry or "library module"
            else:
                continue
            todo.append(rel)
        while todo:
            rel = todo.pop()
            for target in self.modules[rel].imports:
                if level.get(target, NONE) < level[rel]:
                    level[target] = level[rel]
                    self.module_via[target] = f"imported by {rel}"
                    todo.append(target)
        self.module_level = level

    def _refs(self) -> None:
        """Every Name/Attribute reference, by scope, with the status of the statement it is in."""
        self.out: dict[str, list[tuple[str, str, Status, str, int]]] = {}   # scope key -> (name, kind, status, file, line)
        for mod in self.modules.values():
            for node in ast.walk(mod.tree):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    name, kind = node.id, "name"
                elif isinstance(node, ast.Attribute):
                    name, kind = node.attr, "attr"
                else:
                    continue
                scope = self.scope_of(mod, node)
                status = self.stmt_status(mod, node, scope)
                if status.state == "dead":
                    continue
                key = scope.key if scope else f"{mod.rel}::<module>"
                self.out.setdefault(key, []).append((name, kind, status, mod.rel, node.lineno))
            names = self._all_names(mod)
            for n in names:
                self.out.setdefault(f"{mod.rel}::<module>", []).append((n, "name", Status(), mod.rel, 1))

    @staticmethod
    def _all_names(mod: Module) -> list[str]:
        for node in mod.tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets) \
                    and isinstance(node.value, (ast.List, ast.Tuple)):
                return [e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        return []

    def _targets(self, name: str, kind: str) -> list[str]:
        """Functions/classes a reference by this name may mean (over-approximation)."""
        if not hasattr(self, "_names"):
            self._names: dict[str, list[tuple[str, bool]]] = {}
            for f in self.funcs.values():
                self._names.setdefault(f.name, []).append((f.key, f.cls is not None))
            for c in self.classes.values():
                self._names.setdefault(c.name, []).append((c.key, False))
        return [key for key, method in self._names.get(name, []) if kind == "attr" or not method]

    def _function_levels(self) -> None:
        level: dict[str, int] = {}
        via: dict[str, tuple[str, str]] = {}          # key -> (from key, "file:line" or reason)
        todo: list[str] = []

        def raise_to(key: str, lv: int, frm: str, why: str) -> None:
            file = key.split("::", 1)[0]
            lv = min(lv, self.module_level.get(file, NONE))
            if lv > level.get(key, NONE):
                level[key] = lv
                via[key] = (frm, why)
                todo.append(key)

        for rel, lv in self.module_level.items():
            raise_to(f"{rel}::<module>", lv, "", self.module_via.get(rel, "test module"))
        for f in self.funcs.values():
            mod = self.modules[f.file]
            registering = [d for d in f.decorators if d[-1] not in NON_REGISTERING]
            if registering:
                why = ("route " + ".".join(registering[0])) if any(self._is_route_chain(d) for d in registering) \
                    else "decorated with @" + ".".join(registering[0])
                raise_to(f.key, LIVE, "", why)
            if f.cls is None and f.name in FACTORY_NAMES:
                raise_to(f.key, LIVE, "", f"app factory {f.name}()")
            if mod.is_test:
                raise_to(f.key, TEST, "", "test code")
            if self.library_mode and not f.name.startswith("_") and not mod.is_test:
                raise_to(f.key, LIVE, "", "public function of a library")
            if re.search(rf"{re.escape(mod.name)}:{re.escape(f.name)}\b", self.config_text + "\n".join(
                    console_scripts(self.root))):
                raise_to(f.key, LIVE, "", "console script / config entry")
        while todo:
            key = todo.pop(0)                         # breadth first: the shortest path is kept as the explanation
            lv = level[key]
            if key in self.classes:
                k = self.classes[key]
                for m in k.methods:
                    f = self.funcs[m]
                    if (f.name.startswith("__") and f.name.endswith("__")) or k.external_base:
                        raise_to(m, lv, key, f"method of {k.name}")
            for name, kind, status, file, line in self.out.get(key, []):
                edge = COND if status.state == "conditional" else LIVE
                for target in self._targets(name, kind):
                    if target == key:
                        continue
                    raise_to(target, min(lv, edge), key, f"{file}:{line}")
        self.level = level
        self.via = via
        self.cond_why = {}
        for key, refs in self.out.items():
            for name, kind, status, file, line in refs:
                if status.state == "conditional":
                    for target in self._targets(name, kind):
                        self.cond_why.setdefault(target, status)

    @staticmethod
    def _is_route_chain(chain: list[str]) -> bool:
        return len(chain) >= 2 and chain[-1] in ROUTE_METHODS

    def path_to(self, key: str, limit: int = 5) -> str:
        """'route bp.post -> update_settings() -> parse_settings()' for a reachable function."""
        names, seen = [], set()
        while key and key not in seen and len(names) < limit:
            seen.add(key)
            frm, why = self.via.get(key, ("", ""))
            if key.endswith("::<module>"):
                names.append(f"{key.split('::')[0]} ({why})" if not frm else key.split("::")[0])
            elif key in self.funcs:
                names.append(self.funcs[key].label + (f" ({why})" if not frm else ""))
            elif key in self.classes:
                names.append(self.classes[key].name)
            key = frm
        return " -> ".join(reversed(names))

    # ------------------------------------------------------------ queries

    def node_at(self, file: str, line: int, symbol: str | None = None) -> ast.AST | None:
        mod = self.modules.get(file)
        if mod is None:
            return None
        calls = [n for n in ast.walk(mod.tree) if isinstance(n, ast.Call) and n.lineno == line]
        if symbol:
            for c in calls:
                sym = self.resolve(mod, c.func) or ""
                if sym == symbol or sym.endswith("." + symbol.split(".")[-1]) and sym.split(".")[0] == symbol.split(".")[0]:
                    return c
            getattr_call = next((c for c in calls if _dotted(c.func) == ["getattr"]), None)
            if getattr_call is not None:
                return getattr_call
        nodes = calls or [n for n in ast.walk(mod.tree) if isinstance(n, (ast.Attribute, ast.Name))
                          and getattr(n, "lineno", None) == line]
        return nodes[0] if nodes else None

    def reach(self, file: str, line: int, symbol: str | None = None) -> Reach:
        mod = self.modules.get(file)
        if mod is None:
            return Reach("unknown", f"{file} could not be parsed, so it is unknown whether line {line} runs")
        node = self.node_at(file, line, symbol)
        if node is None:
            return Reach("unknown", f"could not find the code at {file}:{line}")
        scope = self.scope_of(mod, node)
        where = f"{file}:{line}"
        st = self.stmt_status(mod, node, scope)
        if st.state == "dead":
            return Reach("fail", f"{where} can never run: {st.why}.", [(st.why, where)])

        mlevel = self.module_level.get(file, NONE)
        if mlevel == NONE:
            if self.dynamic_imports:
                return Reach("unknown", f"{file} is not imported by the application's code, but modules are also "
                                        f"loaded dynamically ({self.dynamic_imports[0]}).",
                             [(f"dynamic import: {self.dynamic_imports[0]}", self.dynamic_imports[0].split()[0])])
            if scope is None and mod.tree.body and any(isinstance(s, ast.Expr) for s in mod.tree.body):
                return Reach("unknown", f"{file} is never imported, but it runs code at module level, so it may be "
                                        "run directly as a script.")
            return Reach("fail", f"{file} is never imported by the application, so {where} never runs.",
                         [("no import of this module from any entry point or other module", file)])
        if mlevel == TEST and not mod.is_test:
            return Reach("fail", f"{file} is only imported by tests, so {where} only runs in tests.",
                         [(self.module_via.get(file, "imported by tests"), file)])
        if mod.is_test:
            return Reach("fail", f"{where} is test code: it is only used in tests.", [("test file", where)])

        key = scope.key if scope else f"{file}::<module>"
        lv = self.level.get(key, NONE)
        label = scope.label if scope else f"module-level code of {file}"
        if lv == LIVE and st.state == "live":
            return Reach("pass", f"{where} runs: {self.path_to(key)}.", [(self.path_to(key), where)])
        if lv >= COND:
            why = st.why if st.state == "conditional" else self.cond_why.get(key, Status(why="a config check")).why
            flag = st.flag or self.cond_why.get(key, Status()).flag
            return Reach("unknown", f"{where} only runs when a setting is on: {why}"
                                    + (f" (setting {flag})" if flag and flag not in why else "") + ".",
                         [(why, where)])
        if lv == TEST:
            return Reach("fail", f"{label} is only used in tests.", [(f"only reached from tests: {self.path_to(key)}",
                                                                      where)])
        # never referenced from running code
        mentions = self.strings.get(scope.name if scope else "", [])
        if mentions:
            return Reach("unknown", f"{label} is never called directly, but its name appears as a string at "
                                    f"{mentions[0]}, so it may be called dynamically.", [("name as a string", mentions[0])])
        if self.dynamic and scope is not None:
            return Reach("unknown", f"{label} is never called directly, but the code also calls functions by computed "
                                    f"name ({self.dynamic[0]}).", [("dynamic call", self.dynamic[0].split()[0])])
        if scope is not None and scope.cls and self.classes[scope.cls].external_base:
            return Reach("unknown", f"{label} is a method of a class that extends a framework class, which may call "
                                    "it.")
        return Reach("fail", f"{label} is never called or referenced anywhere in the code, so {where} never runs.",
                     [(f"no reference to {label}", f"{scope.file}:{scope.line}" if scope else where)])

    def function_source(self, file: str, line: int, max_lines: int = 60) -> str:
        """Numbered source of the function containing file:line (or ±8 lines at module level)."""
        return self.source_block(file, line, max_lines)[0]

    def source_block(self, file: str, line: int, max_lines: int = 60) -> tuple[str, set[tuple[str, int]]]:
        """(numbered source of the function containing file:line, the (file, line) pairs it shows)."""
        mod = self.modules.get(file)
        if mod is None:
            return "", set()
        node = self.node_at(file, line)
        scope = self.scope_of(mod, node) if node is not None else None
        if scope is not None and not isinstance(scope.node, ast.Lambda):
            start = min([scope.node.lineno] + [d.lineno for d in scope.node.decorator_list])
            end = scope.node.end_lineno or start
        else:
            start, end = max(1, line - 8), min(len(mod.lines), line + 8)
        end = min(end, start + max_lines - 1, len(mod.lines))
        text = "\n".join(f"{n:>5}{'>' if n == line else ' '}| {mod.lines[n - 1]}" for n in range(start, end + 1))
        return text, {(file, n) for n in range(start, end + 1)}

    # ------------------------------------------------------------ taint

    def callers(self, f: Func) -> list[tuple[Module, ast.Call]]:
        """Calls that may call f: `f(...)` for plain functions, `x.f(...)` for both (by name)."""
        if not hasattr(self, "_calls"):
            self._calls: dict[str, list[tuple[Module, ast.Call, bool]]] = {}
            for mod in self.modules.values():
                for node in ast.walk(mod.tree):
                    if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
                        name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
                        self._calls.setdefault(name, []).append((mod, node, isinstance(node.func, ast.Attribute)))
        return [(mod, call) for mod, call, attr in self._calls.get(f.name, [])
                if (attr or f.cls is None) and self.scope_of(mod, call) is not f]

    def taint(self, file: str, call: ast.AST, input_arg: str | None) -> Taint:
        """Is the relevant argument of this call attacker-controlled? (tainted / constant / partial / unknown)"""
        mod = self.modules[file]
        scope = self.scope_of(mod, call)
        if not isinstance(call, ast.Call):
            return Taint("unknown", "the use is not a call, so its input cannot be followed")
        args = self._select_args(call, input_arg)
        if not args:
            # missing input is never proof: a method's data may come from its object, a function's from defaults
            return Taint("unknown", "the call passes no arguments, so the data may come from the object it is "
                                    "called on or from defaults", f"{file}:{call.lineno}")
        t = self._combine([self._expr(mod, scope, a, 0, set()) for a in args])
        if t.state == "constant" and input_arg is not None and not self._has_arg(call, input_arg):
            return Taint("unknown", f"the input argument {input_arg!r} was not found in the call; the other "
                                    f"arguments are fixed ({t.why})", t.cite)
        return t

    @staticmethod
    def _has_arg(call: ast.Call, input_arg: str) -> bool:
        key = str(input_arg).strip()
        return any(k.arg == key for k in call.keywords) or (key.isdigit() and int(key) < len(call.args))

    @staticmethod
    def _select_args(call: ast.Call, input_arg: str | None) -> list[ast.AST]:
        if input_arg is not None:
            key = str(input_arg).strip()
            if key.isdigit() and int(key) < len(call.args) and not any(isinstance(a, ast.Starred)
                                                                       for a in call.args[:int(key) + 1]):
                return [call.args[int(key)]]
            kw = next((k.value for k in call.keywords if k.arg == key), None)
            if kw is not None:
                return [kw]
        return list(call.args) + [k.value for k in call.keywords]

    @staticmethod
    def _combine(parts: list[Taint]) -> Taint:
        for state in ("tainted", "partial", "unknown"):
            hit = next((p for p in parts if p.state == state), None)
            if hit:
                return hit
        return parts[0] if parts else Taint("unknown", "nothing to follow")

    def _concat(self, parts: list[Taint], has_const_text: bool) -> Taint:
        t = next((p for p in parts if p.state == "tainted"), None)
        if t and (has_const_text or any(p.state == "constant" for p in parts)):
            return Taint("partial", f"only part of the value is attacker-controlled ({t.why})", t.cite)
        return self._combine(parts)

    def _expr(self, mod: Module, scope: Func | None, e: ast.AST, depth: int, seen: set) -> Taint:
        here = f"{mod.rel}:{getattr(e, 'lineno', 0)}"
        if (mod.rel, id(e)) in seen:
            return Taint("unknown", "circular data flow")
        seen = seen | {(mod.rel, id(e))}
        if isinstance(e, ast.Constant):
            return Taint("constant", f"the value is the literal {_segment(e, 40)}", here)
        if isinstance(e, ast.JoinedStr):
            parts = [self._expr(mod, scope, v.value, depth, seen) for v in e.values if isinstance(v, ast.FormattedValue)]
            const_text = any(isinstance(v, ast.Constant) and str(v.value).strip() for v in e.values)
            return self._concat(parts, const_text) if parts else Taint("constant", "a fixed string", here)
        if isinstance(e, ast.BinOp):
            parts = [self._expr(mod, scope, e.left, depth, seen), self._expr(mod, scope, e.right, depth, seen)]
            return self._concat(parts, False)
        if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            return self._combine([self._expr(mod, scope, x, depth, seen) for x in e.elts]) if e.elts \
                else Taint("constant", "an empty literal", here)
        if isinstance(e, ast.Dict):
            vals = [v for v in e.values if v is not None]
            return self._combine([self._expr(mod, scope, x, depth, seen) for x in vals]) if vals \
                else Taint("constant", "an empty literal", here)
        if isinstance(e, ast.IfExp):
            return self._combine([self._expr(mod, scope, e.body, depth, seen), self._expr(mod, scope, e.orelse, depth, seen)])
        if isinstance(e, (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
            parts = [self._expr(mod, scope, g.iter, depth, seen) for g in e.generators]
            tainted = next((p for p in parts if p.state == "tainted"), None)
            return tainted or Taint("unknown", f"built by a comprehension: {_segment(e, 50)}", here)
        chain = _dotted(e.func if isinstance(e, ast.Call) else e) or []
        if chain[:1] in (["request"], ["req"]) and len(chain) >= 2 and chain[1] in REQUEST_INPUTS:
            return Taint("tainted", f"{'.'.join(chain[:2])} is data from the HTTP request", here)
        if chain[:2] in (["sys", "argv"], ["sys", "stdin"]) or chain == ["input"]:
            return Taint("tainted", f"{'.'.join(chain[:2])} is user input", here)
        if isinstance(e, ast.Call):
            if chain and chain[-1] == "parse_args":
                return Taint("tainted", "command-line arguments (parse_args)", here)
            if isinstance(e.func, ast.Attribute) and not self.resolve(mod, e.func):
                base = self._expr(mod, scope, e.func.value, depth, seen)       # x.strip(), upload.read(), body.get()
                if base.state == "tainted":
                    return base
            args = [self._expr(mod, scope, a, depth, seen) for a in list(e.args) + [k.value for k in e.keywords]]
            tainted = next((a for a in args if a.state == "tainted"), None)
            if tainted:
                return tainted
            if isinstance(e.func, ast.Attribute) and not self.resolve(mod, e.func):
                base = self._expr(mod, scope, e.func.value, depth, seen)
                if base.state == "constant" and all(a.state == "constant" for a in args):
                    return Taint("constant", f"derived from fixed values: {_segment(e, 60)}", here)
                return Taint("unknown", f"the result of {_segment(e, 60)}", here)
            repo_fn = chain and any(f.name == chain[-1] for f in self.funcs.values())
            if not repo_fn and all(a.state == "constant" for a in args):
                return Taint("constant", f"derived only from fixed values: {_segment(e, 60)}", here)
            return Taint("unknown", f"the result of {_segment(e, 60)}", here)
        if isinstance(e, (ast.Attribute, ast.Subscript)):
            base = self._expr(mod, scope, e.value, depth, seen)
            if base.state in ("tainted", "constant"):
                return base
            return Taint("unknown", f"{_segment(e, 50)}", here)
        if isinstance(e, ast.Name):
            return self._name(mod, scope, e, depth, seen)
        return Taint("unknown", f"{_segment(e, 50)}", here)

    def _name(self, mod: Module, scope: Func | None, e: ast.Name, depth: int, seen: set) -> Taint:
        here = f"{mod.rel}:{e.lineno}"
        name = e.id
        if name == "__file__":
            return Taint("constant", "a path inside the repository (__file__)", here)
        if name in ("self", "cls"):
            return Taint("unknown", "an attribute of the object", here)
        if scope is not None:
            values = self._assigned(scope.node, name)
            if values:
                return self._combine([self._expr(mod, scope, v, depth, seen) for v in values])
            if name in scope.params:
                return self._param(mod, scope, name, depth, seen)
            parent = self.scope_of(mod, scope.node)          # closure variable of an enclosing function
            if parent is not None and (self._assigned(parent.node, name) or name in parent.params):
                return self._name(mod, parent, e, depth, seen)
        values = self._assigned(mod.tree, name, module_level=True)
        if values:
            return self._combine([self._expr(mod, None, v, depth, seen) for v in values])
        return Taint("unknown", f"{name} is defined elsewhere", here)

    @staticmethod
    def _assigned(scope_node: ast.AST, name: str, module_level: bool = False) -> list[ast.AST]:
        """Values assigned to `name` in this scope (not in nested functions)."""
        out = []
        body = scope_node.body if isinstance(getattr(scope_node, "body", None), list) else []
        todo = list(body)
        while todo:
            n = todo.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name) and t.id == name:
                        out.append(n.value)
                    elif isinstance(t, (ast.Tuple, ast.List)) and any(isinstance(x, ast.Name) and x.id == name
                                                                      for x in t.elts):
                        out.append(n.value)
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and isinstance(n.target, ast.Name) \
                    and n.target.id == name and n.value is not None:
                out.append(n.value)
            elif isinstance(n, (ast.For, ast.AsyncFor)) and any(isinstance(x, ast.Name) and x.id == name
                                                                for x in ast.walk(n.target)):
                out.append(n.iter)
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                for item in n.items:
                    if item.optional_vars is not None and any(isinstance(x, ast.Name) and x.id == name
                                                              for x in ast.walk(item.optional_vars)):
                        out.append(item.context_expr)
            elif isinstance(n, ast.NamedExpr) and n.target.id == name:
                out.append(n.value)
            todo.extend(ast.iter_child_nodes(n))
        return out

    def _param(self, mod: Module, scope: Func, name: str, depth: int, seen: set) -> Taint:
        here = f"{scope.file}:{scope.line}"
        if any(self._is_route_chain(d) for d in scope.decorators):
            return Taint("tainted", f"{name} is a parameter of the route {scope.label}, taken from the URL", here)
        if any(self._is_cli(d) for d in scope.decorators):
            return Taint("tainted", f"{name} is a command-line parameter of {scope.label}", here)
        if depth >= 2:
            return Taint("unknown", f"{name} is a parameter of {scope.label} (not followed further)", here)
        idx = scope.params.index(name)
        method = scope.cls is not None and not scope.static and scope.params[:1] in (["self"], ["cls"])
        pos = idx - 1 if method else idx
        results = []
        for cmod, call in self.callers(scope):
            value = next((k.value for k in call.keywords if k.arg == name), None)
            if value is None and 0 <= pos < len(call.args) and not any(isinstance(a, ast.Starred)
                                                                          for a in call.args[:pos + 1]):
                value = call.args[pos]
            if value is None:
                continue
            t = self._expr(cmod, self.scope_of(cmod, call), value, depth + 1, seen)
            if t.state == "tainted":
                return Taint("tainted", f"{name} comes from {cmod.rel}:{call.lineno}, where {t.why}", t.cite)
            results.append(t)
        if not results:
            return Taint("unknown", f"{name} is a parameter of {scope.label} and no caller passing it was found", here)
        return self._combine(results)
