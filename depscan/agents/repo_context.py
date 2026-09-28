"""RepoContextAgent (optional step 2): what kind of application is this, and where does untrusted input enter?

Everything is deterministic (AST + manifests) except `summary`, which comes from ONE short LLM call that
sees only the deterministic fields and the first 50 lines of the README. The context is "background",
never evidence: the ExploitabilityAgent may use it to adjust confidence, not to decide a verdict.
"""

import ast
import configparser
import re
import tomllib
import warnings
from datetime import datetime, timezone
from pathlib import Path

from depscan.agents.usage_locator import _dotted, is_test_path
from depscan.errors import DepscanError
from depscan.llm.prompts import CONTEXT_SYSTEM, context_prompt
from depscan.models import RepoContext, ScanResult, UsageRef

WEB_FRAMEWORKS = {"flask", "django", "fastapi", "starlette", "tornado", "aiohttp", "sanic", "bottle", "pyramid",
                  "falcon", "quart", "litestar", "cherrypy", "web2py"}
CLI_FRAMEWORKS = {"click", "typer", "fire", "docopt", "argparse"}
OTHER_FRAMEWORKS = {"celery", "sqlalchemy", "streamlit", "gradio", "scrapy", "dash", "pytest", "rq", "dramatiq"}
KNOWN = WEB_FRAMEWORKS | CLI_FRAMEWORKS | OTHER_FRAMEWORKS
ROUTE_METHODS = {"route", "get", "post", "put", "delete", "patch", "websocket", "api_route", "add_url_rule"}
APP_CLASSES = {"Flask", "FastAPI", "Starlette", "Sanic", "Quart", "Bottle", "Litestar", "Application", "Celery", "Typer"}
FACTORY_NAMES = {"create_app", "make_app", "app_factory", "get_app", "build_app", "application_factory"}
REQUEST_INPUTS = {"get_json", "json", "files", "args", "form", "data", "values", "cookies", "headers", "get_data",
                  "stream", "GET", "POST", "FILES", "body", "query_params", "path_params", "query_string"}
CLI_INPUTS = {("click", "argument"), ("click", "option"), ("typer", "Argument"), ("typer", "Option")}
MAX_ITEMS = 50


def path_context(rel: str) -> str:
    parts = rel.lower().split("/")
    if is_test_path(rel):
        return "test"
    if any(p in ("examples", "example", "docs", "doc", "demo", "demos", "samples") for p in parts[:-1]):
        return "example"
    if any(p in ("scripts", "script", "tools", "bin", "dev") for p in parts[:-1]):
        return "script"
    return "prod"


def _segment(source: str, node: ast.AST) -> str:
    return (ast.get_source_segment(source, node) or "").replace("\n", " ")[:120]


def analyze_file(source: str, rel: str) -> dict:
    """Deterministic facts from one file (never executed)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tree = ast.parse(source, filename=rel)
    facts = {"imports": set(), "entry_points": [], "inputs": [], "main_block": False}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            facts["imports"].update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            facts["imports"].add(node.module.split(".")[0])
        elif isinstance(node, ast.If):
            t = node.test
            if isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "__name__" \
                    and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in t.comparators):
                facts["main_block"] = True
                facts["entry_points"].append(f"{rel}:{node.lineno} __main__ block")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in FACTORY_NAMES:
                facts["entry_points"].append(f"{rel}:{node.lineno} app factory {node.name}()")
            for dec in node.decorator_list:
                call = dec if isinstance(dec, ast.Call) else None
                chain = _dotted(call.func if call else dec) or []
                if len(chain) >= 2 and chain[-1] in ROUTE_METHODS:
                    route = next((a.value for a in (call.args if call else []) if isinstance(a, ast.Constant)), "")
                    method = "" if chain[-1] in ("route", "add_url_rule") else chain[-1].upper() + " "
                    facts["entry_points"].append(f"{rel}:{dec.lineno} route {method}'{route}' -> {node.name}()")
                if len(chain) >= 2 and (chain[0], chain[-1]) in CLI_INPUTS:
                    facts["inputs"].append(UsageRef(file=rel, line=dec.lineno, symbol=f"{chain[0]}.{chain[-1]}"))
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            fn = _dotted(node.value.func) or []
            if fn and fn[-1] in APP_CLASSES and node.col_offset == 0:
                target = node.targets[0].id if isinstance(node.targets[0], ast.Name) else "?"
                facts["entry_points"].append(f"{rel}:{node.lineno} app instance {target} = {fn[-1]}(...)")
        if isinstance(node, ast.Attribute):
            base = node.value
            if isinstance(base, ast.Name) and base.id in ("request", "req") and node.attr in REQUEST_INPUTS:
                facts["inputs"].append(UsageRef(file=rel, line=node.lineno, symbol=f"request.{node.attr}"))
            elif isinstance(base, ast.Name) and base.id == "sys" and node.attr == "argv":
                facts["inputs"].append(UsageRef(file=rel, line=node.lineno, symbol="sys.argv"))
        if isinstance(node, ast.Call):
            fn = _dotted(node.func) or []
            if fn == ["input"]:
                facts["inputs"].append(UsageRef(file=rel, line=node.lineno, symbol="input()"))
            elif fn[-1:] in (["add_argument"], ["parse_args"]):
                facts["inputs"].append(UsageRef(file=rel, line=node.lineno, symbol=f"argparse.{fn[-1]}"))
            elif fn == ["open"] and node.args and not isinstance(node.args[0], ast.Constant):
                arg = _segment(source, node.args[0])
                if re.search(r"request|argv|\bargs\.|input\(", arg):
                    facts["inputs"].append(UsageRef(file=rel, line=node.lineno, symbol=f"open({arg}) on a user-supplied path"))
    return facts


def console_scripts(repo: Path) -> list[str]:
    out = []
    pyproject = repo / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            scripts = {**data.get("project", {}).get("scripts", {}), **data.get("tool", {}).get("poetry", {}).get("scripts", {})}
            out += [f"console_script {k} = {v}" for k, v in scripts.items()]
        except tomllib.TOMLDecodeError:
            pass
    setup_cfg = repo / "setup.cfg"
    if setup_cfg.exists():
        cp = configparser.ConfigParser()
        try:
            cp.read(setup_cfg, encoding="utf-8")
            raw = cp.get("options.entry_points", "console_scripts", fallback="")
            out += [f"console_script {line.strip()}" for line in raw.splitlines() if "=" in line]
        except configparser.Error:
            pass
    setup_py = repo / "setup.py"
    if setup_py.exists():  # read as text only, never executed
        text = setup_py.read_text(encoding="utf-8", errors="replace")
        block = re.search(r"console_scripts['\"]\s*:\s*\[(.*?)\]", text, re.S)
        if block:
            out += [f"console_script {s}" for s in re.findall(r"['\"]([^'\"]+=[^'\"]+)['\"]", block.group(1))]
    return out


def readme_head(repo: Path, lines: int = 50) -> str:
    for name in ("README.md", "README.rst", "README.txt", "README", "readme.md"):
        p = repo / name
        if p.exists():
            return "\n".join(p.read_text(encoding="utf-8", errors="replace").splitlines()[:lines])
    return ""


def first_sentences(text: str, n: int = 3) -> str:
    parts = re.split(r"(?<=[.!?])\s+", " ".join(text.split()))
    return " ".join(parts[:n]).strip()


class RepoContextAgent:
    def __init__(self, llm=None):
        self.llm = llm

    def deterministic(self, result: ScanResult) -> RepoContext:
        repo = Path(result.repo.local_path)
        imports: set[str] = set()        # all files: for the frameworks list
        prod_imports: set[str] = set()   # production paths only: for app_type (a test importing click is no CLI)
        entry_points: list[str] = []
        inputs: list[UsageRef] = []
        main_blocks = False
        for rel in result.repo.source_files:
            try:
                facts = analyze_file((repo / rel).read_text(encoding="utf-8", errors="replace"), rel)
            except (SyntaxError, ValueError, RecursionError):
                continue
            prod = path_context(rel) == "prod"
            imports |= facts["imports"]
            prod_imports |= {i.lower() for i in facts["imports"]} if prod else set()
            entry_points += facts["entry_points"] if path_context(rel) != "test" else []
            inputs += facts["inputs"] if path_context(rel) != "test" else []
            main_blocks = main_blocks or (facts["main_block"] and prod)
        scripts = console_scripts(repo)
        dep_names = {d.name for d in result.repo.dependencies}
        frameworks = sorted((KNOWN & dep_names) | (KNOWN & {i.lower() for i in imports}))
        routes = any(" route " in e for e in entry_points)

        if routes or WEB_FRAMEWORKS & prod_imports:
            app_type = "web_service"
        elif scripts or CLI_FRAMEWORKS & prod_imports - {"argparse"} or ("argparse" in prod_imports and main_blocks):
            app_type = "cli"
        elif (repo / "setup.py").exists() or (repo / "setup.cfg").exists() or \
                "[project]" in ((repo / "pyproject.toml").read_text(encoding="utf-8") if (repo / "pyproject.toml").exists() else ""):
            app_type = "library" if not main_blocks else "script"
        elif main_blocks:
            app_type = "script"
        else:
            app_type = "unknown"

        contexts = {}
        for usage in result.usages.values():
            for s in usage.sites + usage.indirect_sites + usage.native_reach_sites:
                contexts[s.id] = path_context(s.file)
        return RepoContext(app_type=app_type, frameworks=frameworks, entry_points=(scripts + entry_points)[:MAX_ITEMS],
                           untrusted_input_sources=list({(u.file, u.line, u.symbol): u for u in inputs}.values())[:MAX_ITEMS], usage_contexts=contexts,
                           created_at=datetime.now(timezone.utc))

    def run(self, result: ScanResult) -> RepoContext:
        ctx = self.deterministic(result)
        if self.llm is None:
            return ctx
        try:
            text, _ = self.llm.complete_text("RepoContextAgent", CONTEXT_SYSTEM,
                                             context_prompt(ctx, readme_head(Path(result.repo.local_path))),
                                             max_tokens=160)
            ctx.summary, ctx.model = first_sentences(text), self.llm.model
        except DepscanError as e:
            ctx.summary = f"(summary unavailable: {e.message})"
        return ctx
