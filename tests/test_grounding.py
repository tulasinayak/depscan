"""Grounding specs in the package's own code: PyPI metadata, the API index, retrieval, validation, parent triggers.

All packages are made up (quuxarc, zorbanet, nativo) and served from an in-memory PyPI; nothing leaves the machine.
"""

import hashlib
import io
import json
import textwrap
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from depscan.agents.stepwise import StepwiseAgent, trigger_match
from depscan.cache import ResponseCache
from depscan.codeindex import CodeIndex
from depscan.grounding import (MAX_FILE_BYTES, PackageSource, api_excerpt, changed_functions, code_parent_triggers,
                               index_sources, read_members, validate_spec)
from depscan.import_names import resolve_import_names
from depscan.models import ParentTrigger, TriggerSpec, Vulnerability
from depscan.triggers import TriggerStore
from fake_llm import FakeOpenAI

QUUXARC = {
    "quuxarc/__init__.py": """
        from .archive import QuuxFile, open_archive
        from .util import *
    """,
    "quuxarc/archive.py": """
        import os


        class QuuxFile:
            def __init__(self, source, mode="r"):
                self.source = source
                self.mode = mode

            def namelist(self):
                return []

            def extractall(self, path="."):
                for name in self.namelist():
                    os.makedirs(os.path.join(path, name))
                return path

            def _members(self):
                return []


        def open_archive(source):
            return QuuxFile(source)
    """,
    "quuxarc/util.py": """
        __all__ = ["checksum"]


        def checksum(data):
            return sum(data)


        def _private():
            return 1
    """,
    "quuxarc-2.0.0.dist-info/top_level.txt": "quuxarc\n",
}
ZORBANET = {
    "zorbanet/__init__.py": "from .api import get\n",
    "zorbanet/api.py": """
        from zorbanet.sessions import Session


        def get(url):
            return Session().fetch(url)


        def ping():
            return 1
    """,
    "zorbanet/sessions.py": """
        import quuxarc


        class Session:
            def fetch(self, url):
                return self._open(url)

            def _open(self, url):
                return quuxarc.QuuxFile(url)
    """,
    "zorbanet-1.0.0.dist-info/top_level.txt": "zorbanet\n",
}
NATIVO = {
    "nativo/__init__.py": "from ._core import *\n",
    "nativo/_core.cpython-312-x86_64-linux-gnu.so": "\x7fELF not really",
    "nativo-3.0.dist-info/RECORD": "nativo/__init__.py,,\nnativo/_core.cpython-312-x86_64-linux-gnu.so,,\n",
}


def wheel(files: dict[str, str], extra: list[tuple[zipfile.ZipInfo, bytes]] = ()) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in files.items():
            zf.writestr(name, textwrap.dedent(text).lstrip())
        for info, data in extra:
            zf.writestr(info, data)
    return buf.getvalue()


def evil_members() -> list[tuple[zipfile.ZipInfo, bytes]]:
    link = zipfile.ZipInfo("quuxarc/link.py")
    link.external_attr = (0o120777 << 16)
    return [(zipfile.ZipInfo("../escape.py"), b"x = 1"), (zipfile.ZipInfo("/abs.py"), b"x = 1"),
            (link, b"/etc/passwd"), (zipfile.ZipInfo("quuxarc/huge.py"), b"#" * (MAX_FILE_BYTES + 1))]


class FakePyPI:
    def __init__(self):
        self.packages = {("quuxarc", "2.0.0"): ("quuxarc-2.0.0-py3-none-any.whl", wheel(QUUXARC, evil_members())),
                         ("zorbanet", "1.0.0"): ("zorbanet-1.0.0-py3-none-any.whl", wheel(ZORBANET)),
                         ("nativo", "3.0"): ("nativo-3.0-cp312-cp312-manylinux_x86_64.whl", wheel(NATIVO))}
        self.bad_hash: set[str] = set()
        self.requests: list[str] = []

    def transport(self) -> httpx.MockTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            self.requests.append(str(request.url))
            parts = request.url.path.strip("/").split("/")
            if request.url.host == "pypi.example" and len(parts) == 4:
                hit = self.packages.get((parts[1], parts[2]))
                if hit is None:
                    return httpx.Response(404)
                name, data = hit
                sha = "0" * 64 if parts[1] in self.bad_hash else hashlib.sha256(data).hexdigest()
                return httpx.Response(200, json={"urls": [
                    {"filename": name, "url": f"https://files.example/{name}", "packagetype": "bdist_wheel",
                     "size": len(data), "python_version": "py3", "digests": {"sha256": sha}},
                    {"filename": "huge-1.0.tar.gz", "url": "https://files.example/huge", "packagetype": "sdist",
                     "size": 10 ** 9, "python_version": "source", "digests": {}}]})
            if request.url.host == "files.example":
                name = parts[-1]
                data = next((d for n, d in self.packages.values() if n == name), None)
                return httpx.Response(200, content=data) if data else httpx.Response(404)
            return httpx.Response(404)
        return httpx.MockTransport(handle)


@pytest.fixture
def pypi():
    return FakePyPI()


def source(tmp_path, pypi, offline=False) -> PackageSource:
    http = ResponseCache(tmp_path / "http.sqlite", 3600)
    return PackageSource(tmp_path / "cache", http, offline=offline, transport=pypi.transport(),
                         base_url="https://pypi.example/pypi")


def spec(**kw) -> TriggerSpec:
    return TriggerSpec(vuln_id="CVE-Q", package=kw.pop("package", "quuxarc"), plain_summary="x",
                       created_at=datetime.now(timezone.utc), **kw)


# ---------------------------------------------------------------- 1: import names from PyPI metadata

def test_import_names_come_from_the_release_metadata_and_are_cached(tmp_path, pypi):
    src = source(tmp_path, pypi)
    assert src.top_level("quuxarc", "2.0.0") == ["quuxarc"]
    assert src.top_level("nativo", "3.0") == ["nativo"]                      # from RECORD (no top_level.txt)
    assert resolve_import_names("quuxarc", "2.0.0", set(), src) == (["quuxarc"], "pypi_metadata")
    offline = source(tmp_path, pypi, offline=True)                           # same cache, no network
    before = len(pypi.requests)
    assert offline.top_level("quuxarc", "2.0.0") == ["quuxarc"] and len(pypi.requests) == before
    assert offline.top_level("zorbanet", "1.0.0") is None                    # never fetched: cache only


def test_import_name_fallbacks_without_pypi(monkeypatch):
    from depscan import import_names
    monkeypatch.setitem(import_names.BUILTIN, "pyzorba", ["zorba"])
    assert resolve_import_names("zorba-kit", None, {"zorba_kit"}, None) == (["zorba_kit"], "name_heuristic")
    assert resolve_import_names("zorbakit", None, {"zorbaKit"}, None) == (["zorbaKit"], "name_heuristic_case")
    assert resolve_import_names("pyzorba", None, {"zorba"}, None) == (["zorba"], "builtin_table")
    assert resolve_import_names("unheard-of", None, set(), None) == (["unheard_of"], "name_heuristic")


# ---------------------------------------------------------------- archives are read safely

def test_unsafe_and_oversized_members_are_skipped(tmp_path, pypi):
    src = source(tmp_path, pypi)
    path = src.archive("quuxarc", "2.0.0")
    names = [rel for rel, _ in read_members(path, lambda r: True)]
    assert "quuxarc/archive.py" in names
    assert not [n for n in names if "escape" in n or n.startswith("/") or n.endswith(("link.py", "huge.py"))]
    assert not (tmp_path / "escape.py").exists() and not (tmp_path / "cache" / "escape.py").exists()


def test_hash_mismatch_and_size_cap(tmp_path, pypi):
    pypi.bad_hash.add("zorbanet")
    src = source(tmp_path, pypi)
    assert src.archive("zorbanet", "1.0.0") is None and any("sha256 mismatch" in m for m in src.log)
    assert not any(r.endswith("/huge") for r in pypi.requests)              # over the cap: never downloaded


# ---------------------------------------------------------------- 2: the API index

def test_api_index_has_public_api_reexports_and_star_imports(tmp_path, pypi):
    idx = source(tmp_path, pypi).index("quuxarc", "2.0.0")
    assert idx.symbols["quuxarc.archive.QuuxFile"] == "class"
    assert idx.symbols["quuxarc.archive.QuuxFile.extractall"] == "method"
    assert idx.canonical("quuxarc.QuuxFile.extractall") == "quuxarc.archive.QuuxFile.extractall"
    assert idx.canonical("quuxarc.checksum") == "quuxarc.util.checksum"      # from .util import * with __all__
    assert idx.canonical("quuxarc._private") is None
    assert idx.public_name("quuxarc.archive.QuuxFile.extractall") == "quuxarc.QuuxFile.extractall"
    assert (tmp_path / "cache" / "api_index" / "quuxarc-2.0.0.json").exists()


def test_resolve_by_distribution_name_casing_and_unique_name(tmp_path, pypi):
    idx = source(tmp_path, pypi).index("quuxarc", "2.0.0")
    assert idx.resolve("QuuxArc.QuuxFile")[0] == "quuxarc.archive.QuuxFile"
    assert idx.resolve("quuxarc.somewhere.QuuxFile.extractall")[0] == "quuxarc.archive.QuuxFile.extractall"
    assert idx.resolve("quuxarc.QuuxFile.extract_everything")[0] is None



def test_definitions_inside_module_level_if_and_try_are_indexed():
    # certifi/core.py defines where() only inside `if sys.version_info >= (3, 11): ... else: ...`
    core = textwrap.dedent("""
        import sys
        if sys.version_info >= (3, 11):
            def where():
                return "a"
        else:
            def where():
                return "b"
        try:
            from ._speed import fast
        except ImportError:
            def fast():
                return 0
        class Box:
            if sys.platform == "win32":
                def open(self):
                    pass
    """).encode()
    idx = index_sources("certa", "1.0", "certa-1.0.tar.gz", ["certa"],
                        {"certa": ("certa/__init__.py", b"from .core import where, Box\n"),
                         "certa.core": ("certa/core.py", core)})
    assert idx.resolve("certa.where")[0] == "certa.core.where"
    assert idx.symbols["certa.core.fast"] == "function"
    assert idx.symbols["certa.core.Box.open"] == "method"


def test_inherited_members_and_class_attributes_resolve():
    base = textwrap.dedent("""
        class Conn:
            def __init__(self, scope):
                self.scope = scope
                self._private = 1
            @property
            def headers(self):
                return {}
    """).encode()
    filters = textwrap.dedent("""
        from .base import Conn
        class RankFilter:
            def filter(self, image):
                return image
        class MedianFilter(RankFilter):
            pass
        class Request(Conn[str]):
            def joinpath(self, other):
                return other
            __truediv__ = joinpath
            timeout: float = 5.0
    """).encode()
    idx = index_sources("filta", "1.0", "filta-1.0.tar.gz", ["filta"],
                        {"filta": ("filta/__init__.py", b"from .filters import MedianFilter, Request\n"),
                         "filta.base": ("filta/base.py", base),
                         "filta.filters": ("filta/filters.py", filters)})
    assert idx.resolve("filta.MedianFilter.filter")[0] == "filta.filters.RankFilter.filter"
    assert idx.resolve("filta.Request.headers")[0] == "filta.base.Conn.headers"      # base from another module
    assert idx.resolve("filta.Request.scope")[0] == "filta.base.Conn.scope"          # self.scope = ... in a method
    assert idx.resolve("filta.Request.__truediv__")[0] == "filta.filters.Request.__truediv__"
    assert idx.resolve("filta.Request.timeout")[0] == "filta.filters.Request.timeout"
    assert idx.resolve("filta.Request._private")[0] is None
    assert idx.resolve("filta.MedianFilter.render")[0] is None
    idx.symbols["filta.filters.JOINPATH"] = "variable"                           # like PIL.Image.SAVE
    assert idx.resolve("filta.filters.joinpath")[0] == "filta.filters.Request.joinpath"   # unique name, not casing
    excerpt = "\n".join(f"{s} {k}" for s, k in idx.symbols.items())
    assert "filta.base.Conn.scope attribute" in excerpt
    v = Vulnerability(id="CVE-F", summary="Request scope timeout headers filter", match="affected", match_reason="r")
    facts, _ = api_excerpt(idx, v, "")
    assert "RankFilter.filter (method)" in facts
    assert "scope" not in facts and "timeout" not in facts                         # attributes stay out of the prompt

# ---------------------------------------------------------------- 3: retrieval for the prompt

DIFF = """diff --git a/quuxarc/archive.py b/quuxarc/archive.py
index 1..2 100644
--- a/quuxarc/archive.py
+++ b/quuxarc/archive.py
@@ -12,5 +12,7 @@ class QuuxFile:
     def extractall(self, path="."):
         for name in self.namelist():
-            os.makedirs(os.path.join(path, name))
+            target = os.path.realpath(os.path.join(path, name))
+            if not target.startswith(os.path.realpath(path)):
+                raise ValueError(name)
         return path
"""


def test_changed_functions_and_api_excerpt(tmp_path, pypi):
    idx = source(tmp_path, pypi).index("quuxarc", "2.0.0")
    assert changed_functions(DIFF, idx) == ["quuxarc.archive.QuuxFile.extractall"]
    v = Vulnerability(id="CVE-Q", summary="Path traversal when extracting archives with QuuxFile",
                      details="extractall writes outside the target folder", match="affected", match_reason="r")
    text, changed = api_excerpt(idx, v, DIFF)
    assert text.startswith("## Public API of quuxarc 2.0.0 (relevant excerpt")
    lines = text.split("## Functions changed by the fix")[0].splitlines()[1:]
    assert lines[0].startswith("- quuxarc.QuuxFile.extractall (method")
    assert "- quuxarc.archive.QuuxFile.extractall" in text.split("## Functions changed by the fix")[1]
    assert "_members" not in text and "_private" not in text


# ---------------------------------------------------------------- 4: validation

def test_validation_resolves_drops_and_keeps_unverifiable(tmp_path, pypi):
    src = source(tmp_path, pypi)
    checked = validate_spec(spec(trigger_symbols=["quuxarc.archive.QuuxFile.__init__", "quuxarc.Nope",
                                                  "QuuxArc.checksum"],
                                 arg_forms=[{"call": "quuxarc.QuuxFile", "kwarg": "mode", "dangerous": ["w"]},
                                            {"call": "quuxarc.Invented", "kwarg": "x"}]),
                            src.index("quuxarc", "2.0.0"))
    assert checked.trigger_symbols == ["quuxarc.QuuxFile.__init__", "quuxarc.checksum"]
    assert [f.call for f in checked.arg_forms] == ["quuxarc.QuuxFile"]
    assert any("'quuxarc.Nope' dropped" in i for i in checked.validation_issues)
    assert any("'quuxarc.Invented' dropped" in i for i in checked.validation_issues)
    native = validate_spec(spec(package="nativo", trigger_symbols=["nativo.decode"],
                                native_feature={"library": "libnat", "wrapper_symbols": ["nativo.open_image"]}),
                           src.index("nativo", "3.0"))
    assert native.trigger_symbols == ["nativo.decode"] and native.native_feature.wrapper_symbols == ["nativo.open_image"]
    assert all("kept unverified" in i for i in native.validation_issues)
    none = validate_spec(spec(trigger_symbols=["quuxarc.Nope"]), None)
    assert none.trigger_symbols == ["quuxarc.Nope"] and "no API index" in none.validation_issues[0]


def test_grounded_store_puts_facts_in_the_prompt_and_validates(tmp_path, pypi):
    prompts = []

    def reply(messages):
        prompts.append(messages[-1]["content"])
        return json.dumps({"plain_summary": "x", "trigger_symbols": ["quuxarc.QuuxFile.extractall", "quuxarc.Madeup"],
                           "needs_untrusted_input": True})
    from depscan.config import LLMConfig
    from depscan.llm.client import LLMClient
    llm = LLMClient(LLMConfig(), client=FakeOpenAI(reply), log_path=tmp_path / "l.jsonl")
    store = TriggerStore(tmp_path / "cache", tmp_path / "overrides", offline=True, variant="llm+facts",
                         source=source(tmp_path, pypi))
    v = Vulnerability(id="CVE-Q", summary="extractall path traversal in QuuxFile", match="affected", match_reason="r")
    got, generated, problem = store.get(v, "quuxarc", llm, "2.0.0")
    assert generated and not problem and got.variant == "llm+facts"
    assert "## Public API of quuxarc 2.0.0" in prompts[0] and "quuxarc.QuuxFile.extractall" in prompts[0]
    assert got.trigger_symbols == ["quuxarc.QuuxFile.extractall"]
    assert store.cache_path(v, "quuxarc").parent.name == "triggers__llm_facts"
    plain = TriggerStore(tmp_path / "cache", tmp_path / "overrides", offline=True)
    assert plain.cache_path(v, "quuxarc").parent.name == "triggers" and plain.cached(v, "quuxarc") is None


# ---------------------------------------------------------------- 5: parent triggers from code

def test_parent_triggers_come_from_the_parents_code(tmp_path, pypi):
    src = source(tmp_path, pypi)
    s = spec(trigger_symbols=["quuxarc.QuuxFile"],
             parent_triggers=[ParentTrigger(parent="zorbanet", symbols=["zorbanet.invented"], condition="on fetch")])
    [pt] = code_parent_triggers(s, {"zorbanet": src.index("zorbanet", "1.0.0")}, trigger_match)
    assert pt.source == "code" and pt.condition == "on fetch" and "zorbanet.invented" not in pt.symbols
    assert {"zorbanet.get", "zorbanet.sessions.Session.fetch"} <= set(pt.symbols)
    assert "zorbanet.ping" not in pt.symbols and not [x for x in pt.symbols if "._" in x]
    [none] = code_parent_triggers(s, {"zorbanet": None}, trigger_match)
    assert none.symbols == [] and none.note == "no API index"


def test_stepwise_reaches_a_transitive_package_through_code_parent_triggers(tmp_path, pypi):
    from test_stepwise import build, gates, vuln, write_repo
    root = write_repo(tmp_path / "repo", {
        "requirements.txt": "flask==3.1.3\nquuxarc==2.0.0\n    # via zorbanet\nzorbanet==1.0.0\n",
        "app/__init__.py": """
            from flask import Flask


            def create_app():
                app = Flask(__name__)
                from app.routes import bp
                app.register_blueprint(bp)
                return app
        """,
        "app/routes.py": """
            import zorbanet
            from flask import Blueprint, request

            bp = Blueprint("x", __name__)


            @bp.post("/fetch")
            def fetch():
                return zorbanet.get(request.form["url"])
        """})
    result = build(root, {"quuxarc": [vuln("CVE-Q")]})
    src = source(tmp_path, pypi)
    store = TriggerStore(tmp_path / "cache", tmp_path / "overrides", offline=True, variant="llm+facts", source=src)
    v = next(v for dv in result.vulnerabilities for v in dv.vulnerabilities)
    path = store.cache_path(v, "quuxarc")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(spec(trigger_symbols=["quuxarc.QuuxFile"], needs_untrusted_input=False,
                         variant="llm+facts").model_dump_json(), encoding="utf-8")
    index = CodeIndex(Path(result.repo.local_path), result.repo.source_files, result.repo_context.app_type)
    dv = next(dv for dv in result.vulnerabilities)
    rec = StepwiseAgent(store, index, None).run(result, dv, v)
    g = gates(rec)
    assert g["present"].result == "pass" and "zorbanet.get" in g["present"].explanation
    assert rec.spec_variant == "llm+facts"


# ---------------------------------------------------------------- offline mode and no network

def test_offline_uses_the_cache_alone(tmp_path, pypi):
    online = source(tmp_path, pypi)
    assert online.index("quuxarc", "2.0.0") is not None
    (tmp_path / "cache" / "api_index" / "quuxarc-2.0.0.json").unlink()        # index gone, archive still cached
    offline = source(tmp_path, pypi, offline=True)
    before = len(pypi.requests)
    idx = offline.index("quuxarc", "2.0.0")                                   # rebuilt from the cached archive
    assert idx is not None and "quuxarc.archive.QuuxFile" in idx.symbols
    assert offline.top_level("quuxarc", "2.0.0") == ["quuxarc"]
    assert len(pypi.requests) == before                                       # not a single request


def test_offline_with_empty_cache_falls_back_to_name_matching(tmp_path, pypi):
    offline = source(tmp_path, pypi, offline=True)
    assert offline.top_level("zorbanet", "1.0.0") is None and offline.index("zorbanet", "1.0.0") is None
    assert pypi.requests == []
    assert resolve_import_names("zorbanet", "1.0.0", {"zorbaNet"}, offline) == (["zorbaNet"], "name_heuristic_case")


def down() -> httpx.MockTransport:
    def fail(request):
        raise httpx.ConnectError("network is down", request=request)
    return httpx.MockTransport(fail)


def test_no_network_no_cache_scan_still_works(tmp_path):
    from test_orchestrator import FIX, make_orch
    orch = make_orch(tmp_path)
    orch.cfg.grounding.pypi = True
    orch._packages = PackageSource(orch.cfg.cache, ResponseCache(tmp_path / "http.sqlite", 3600), transport=down())
    result = orch.scan(str(FIX / "usage_repo"))                               # must not raise
    usages = list(result.usages.values())
    assert usages and all(u.import_name_source != "pypi_metadata" for u in usages)
    assert any(u.usage_status == "direct_usage" for u in usages)              # sites still found by name
    assert any("ConnectError" in m for m in orch._packages.log)
