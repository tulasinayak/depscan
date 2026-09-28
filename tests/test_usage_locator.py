from pathlib import Path

import pytest

from depscan.agents.repo_mapper import RepoMapperAgent
from depscan.agents.usage_locator import UsageLocatorAgent, regex_scan, scan_source
from depscan.import_names import import_names
from depscan.models import DependencyVulns, RepoMapperInput, UsageLocatorInput, Vulnerability
from depscan.symbols import extract_symbols, symbol_matches

FIX = Path(__file__).parent / "fixtures"


def vuln(vid, symbols=(), kind="standard", summary="", details="") -> Vulnerability:
    return Vulnerability(id=vid, kind=kind, summary=summary, details=details, advisory_symbols=list(symbols),
                         match="affected", match_reason="test")


def locate(repo_dir: str, vulns: dict[str, list[Vulnerability]]):
    repo = RepoMapperAgent(workspace=Path("unused")).run(RepoMapperInput(url=str(FIX / repo_dir)))
    deps = {d.name: d for d in repo.dependencies}
    dvs = [DependencyVulns(dependency=deps[name], vulnerabilities=vs) for name, vs in vulns.items()]
    return UsageLocatorAgent().run(UsageLocatorInput(repo_map=repo, vulnerable=dvs))


@pytest.fixture(scope="module")
def usage():
    return locate("usage_repo", {
        "pillow": [vuln("CVE-PIL-MATH", ["PIL.ImageMath.eval"]),
                   vuln("CVE-PIL-WEBP", kind="bundled_native", summary="libwebp: OOB write",
                        details="Pillow wheels bundle libwebp")],
        "pyyaml": [vuln("CVE-YAML-LOAD", ["yaml.load"])],
        "urllib3": [vuln("CVE-U3-POOL", ["PoolManager.request"])],
    })


def symbols_of(u, name, **filters):
    return {(s.file, s.symbol, s.kind) for s in u.usages[name].sites
            if all(getattr(s, k) == v for k, v in filters.items())}


@pytest.mark.parametrize("dist,names", [("Pillow", ["PIL"]), ("PyYAML", ["yaml"]), ("beautifulsoup4", ["bs4"]),
                                        ("scikit-learn", ["sklearn"]), ("python-dateutil", ["dateutil"]),
                                        ("opencv-python", ["cv2"]), ("some-unknown-pkg", ["some_unknown_pkg"])])
def test_import_name_mapping(dist, names):
    assert import_names(dist)[0] == names


def test_alias_and_attribute_chains(usage):
    pil = symbols_of(usage, "pillow", file="app/images.py")
    assert ("app/images.py", "PIL.Image", "import") in pil                 # from PIL import Image as Img
    assert ("app/images.py", "PIL.Image.open", "call") in pil              # Img.open(...)
    assert ("app/images.py", "PIL.ImageMath.eval", "call") in pil          # import PIL.ImageMath; PIL.ImageMath.eval
    assert not any("thumbnail" in s for _, s, _ in pil)                     # function return values are not tracked


def test_module_alias_and_instance_tracking(usage):
    u3 = symbols_of(usage, "urllib3")
    assert ("app/net.py", "urllib3.PoolManager", "call") in u3             # u.PoolManager(...)
    assert ("app/net.py", "urllib3.request", "call") in u3                 # u.request(...)
    assert ("app/net.py", "urllib3.PoolManager.request", "call") in u3     # pm.request(...)


def test_advisory_symbol_matching(usage):
    matched = {s.symbol for s in usage.usages["pillow"].sites if "CVE-PIL-MATH" in s.matched_vulns}
    assert matched == {"PIL.ImageMath.eval"}
    pool = {s.symbol for s in usage.usages["urllib3"].sites if s.matched_vulns}
    assert pool == {"urllib3.PoolManager.request"}


def test_star_import_is_flagged(usage):
    assert ("app/star.py", "yaml.*", "star_import") in symbols_of(usage, "pyyaml")


def test_dynamic_import_is_low_confidence(usage):
    dyn = [s for s in usage.usages["pyyaml"].sites if s.kind == "dynamic_import"]
    assert [(s.file, s.symbol, s.confidence) for s in dyn] == [("app/dyn.py", "yaml", "low")]
    assert ("app/dyn.py", "yaml.safe_load", "call") in symbols_of(usage, "pyyaml")   # mod.safe_load via the dynamic module


def test_syntax_error_falls_back_to_regex(usage):
    assert usage.parse_failures and usage.parse_failures[0].startswith("app/broken.py: SyntaxError")
    broken = [s for s in usage.usages["pyyaml"].sites if s.file == "app/broken.py"]
    assert {(s.symbol, s.kind, s.confidence) for s in broken} == {("yaml", "regex", "low"), ("yaml.load", "regex", "low")}
    assert any("CVE-YAML-LOAD" in s.matched_vulns for s in broken)


def test_test_paths_and_snippets(usage):
    test_sites = [s for s in usage.usages["pillow"].sites if s.file == "tests/test_images.py"]
    assert test_sites and all(s.in_test_path for s in test_sites)
    call = next(s for s in usage.usages["pillow"].sites if s.symbol == "PIL.Image.open" and s.file == "app/images.py")
    assert "    6>|     im = Img.open(path)" in call.snippet                # line numbers kept, target line marked
    assert call.snippet.splitlines()[0].strip().startswith("1")            # ±5 lines, clipped at file start


def test_native_reach_for_bundled_native(usage):
    reach = {(s.file, s.symbol) for s in usage.usages["pillow"].native_reach_sites}
    assert ("app/images.py", "PIL.Image.open") in reach
    assert all("libwebp" in s.via for s in usage.usages["pillow"].native_reach_sites)


def test_site_ids_are_unique_and_shared():
    u = locate("usage_repo", {"pillow": [vuln("V1")], "pyyaml": [vuln("V2")]})
    all_sites = [s for d in u.usages.values() for s in d.sites]
    assert len({s.id for s in all_sites}) == len(all_sites)


def test_snippet_cap_prefers_matching_and_non_test_sites(monkeypatch):
    import depscan.agents.usage_locator as ul
    monkeypatch.setattr(ul, "MAX_SNIPPETS_PER_DEP", 2)
    u = locate("usage_repo", {"pillow": [vuln("CVE-PIL-MATH", ["PIL.ImageMath.eval"])]})
    with_snippet = [s for s in u.usages["pillow"].sites if s.snippet]
    assert len(with_snippet) == 2 and len(u.usages["pillow"].sites) > 2
    assert with_snippet[0].symbol == "PIL.ImageMath.eval" or any(s.matched_vulns for s in with_snippet)
    assert not any(s.in_test_path for s in with_snippet)


def test_requests_only_repo_transitive_deps():
    repo = RepoMapperAgent(workspace=Path("unused")).run(RepoMapperInput(url=str(FIX / "requests_repo")))
    deps = {d.name: d for d in repo.dependencies}
    assert deps["urllib3"].required_by == ["requests"] and deps["certifi"].required_by == ["requests"]
    u = locate("requests_repo", {"requests": [vuln("R1")], "urllib3": [vuln("U1")], "certifi": [vuln("C1")]})
    assert u.usages["requests"].usage_status == "direct_usage"
    for name in ("urllib3", "certifi"):
        du = u.usages[name]
        assert du.usage_status == "no_direct_usage" and du.required_by == ["requests"]
        assert "reached via requests" in du.note and "does NOT mean" in du.note
        assert {s.symbol for s in du.indirect_sites} == {"requests", "requests.get"}


def test_parse_incomplete_when_nothing_found_but_files_failed(tmp_path):
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\nrequests==2.19.1\n")
    (tmp_path / "bad.py").write_text("def broken(:\n")
    repo = RepoMapperAgent(workspace=tmp_path / "ws").run(RepoMapperInput(url=str(tmp_path)))
    deps = {d.name: d for d in repo.dependencies}
    out = UsageLocatorAgent().run(UsageLocatorInput(repo_map=repo, vulnerable=[
        DependencyVulns(dependency=deps["requests"], vulnerabilities=[vuln("R1")])]))
    assert out.usages["requests"].usage_status == "parse_incomplete"


def test_scan_source_and_regex_scan_directly():
    refs = scan_source("import yaml as y\ny.load(x)\n", "a.py")
    assert {(r.symbol, r.kind) for r in refs} == {("yaml", "import"), ("yaml.load", "call")}
    refs = regex_scan("from yaml import load as L, dump\nimport PIL.Image\n", "b.py")
    assert {r.symbol for r in refs} >= {"yaml.load", "yaml.dump", "PIL.Image"}


# ---------------------------------------------------------------- advisory symbols

def test_extract_symbols():
    text = ("Arbitrary code execution via `yaml.load()` when using the `FullLoader`; see PIL.Image.open "
            "and PoolManager, i.e. RGBA data. https://jvn.jp/x.html os.path.join ValueError full_load()")
    syms = extract_symbols(text, ["yaml"], "pyyaml")
    assert {"yaml.load", "FullLoader", "PIL.Image.open", "PoolManager", "full_load"} <= set(syms)
    assert not {"i.e", "RGBA", "jvn.jp", "os.path.join", "ValueError"} & set(syms)


def test_extract_symbols_prose_and_escaped_code():
    prose = "untrusted YAML files through the full_load method or with the FullLoader loader"
    assert {"full_load", "FullLoader"} <= set(extract_symbols(prose, ["yaml"], "pyyaml"))
    poc = r'python -m tqdm --manpath="\" + str(exec(\"import os\nos.system(\'echo hi\')\"))'
    assert "nos.system" not in extract_symbols(poc, ["tqdm"], "tqdm")


@pytest.mark.parametrize("site,adv,expected", [
    ("yaml.load", "yaml.load", True), ("PIL.Image.open", "Image.open", True),
    ("urllib3.PoolManager.request", "PoolManager.request", True), ("urllib3.PoolManager.request", "PoolManager", True),
    ("yaml.safe_load", "yaml.load", False), ("PIL.Image.open", "Image.save", False), ("yaml.full_load", "full_load", True),
])
def test_symbol_matches(site, adv, expected):
    assert symbol_matches(site, adv) is expected


# ---------------------------------------------------------------- indirection (depscan-test-indirection)

def test_getattr_alias_and_star_import_bindings():
    src = ("import idna\nfrom jinja2.sandbox import *\n"
           "enc = getattr(idna, 'encode')\nenc('x')\n"
           "env = SandboxedEnvironment()\nenv.from_string('t')\n"
           "local = 1\nprint(local, len('x'))\n")
    refs = {(r.line, r.kind, r.symbol) for r in scan_source(src, "a.py")}
    assert (3, "attribute", "idna.encode") in refs
    assert (4, "call", "idna.encode") in refs
    assert (5, "call", "jinja2.sandbox.SandboxedEnvironment") in refs
    assert (6, "call", "jinja2.sandbox.SandboxedEnvironment.from_string") in refs
    assert not any(line == 8 for line, _, _ in refs)      # local names and builtins are not star-import names


def test_reexport_through_repo_modules():
    from depscan.agents.usage_locator import module_bindings, module_name
    utils = "from yaml import full_load as parse_cfg\n"
    routes = ("from app import utils\nfrom .utils import parse_cfg as load\n"
              "utils.parse_cfg(b'x')\nload(b'y')\n")
    assert module_name("app/utils/__init__.py") == "app.utils" and module_name("src/pkg/m.py") == "pkg.m"
    reexports = {"app.utils": module_bindings(utils, "app/utils/__init__.py")}
    calls = {(r.line, r.symbol) for r in scan_source(routes, "app/routes.py", reexports) if r.kind == "call"}
    assert calls == {(3, "yaml.full_load"), (4, "yaml.full_load")}
