"""T3: the usage locator. Python syntax coverage, and files that must be skipped or parsed safely."""

import textwrap
from pathlib import Path

import pytest

from depscan.agents.repo_mapper import RepoMapperAgent
from depscan.agents.usage_locator import UsageLocatorAgent
from depscan.models import DependencyVulns, RepoMapperInput, UsageLocatorInput


def locate(tmp_path: Path, files: dict[str, str | bytes], package: str = "pyyaml"):
    repo = tmp_path / "repo"
    for rel, text in {"requirements.txt": "pyyaml==5.3.1\nrequests==2.30.0\n", **files}.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            p.write_bytes(text)
        else:
            p.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8", newline="\n")
    rmap = RepoMapperAgent(tmp_path / "ws").run(RepoMapperInput(url=str(repo)))
    dvs = [DependencyVulns(dependency=d, vulnerabilities=[]) for d in rmap.dependencies]
    out = UsageLocatorAgent().run(UsageLocatorInput(repo_map=rmap, vulnerable=dvs))
    return out.usages[package], out


def calls(usage) -> set[tuple[str, int, str]]:
    return {(s.file, s.line, s.symbol) for s in usage.sites if s.kind == "call"}


# ---------------------------------------------------------------- syntax coverage

SYNTAX = {
    "match": ("""
        import yaml

        def handle(cmd, data):
            match cmd:
                case {"kind": "load"}:
                    return yaml.safe_load(data)
                case _:
                    return None
     """, 6, "yaml.safe_load"),
    "walrus": ("""
        import yaml

        def f(stream):
            if (doc := yaml.safe_load(stream)) is not None:
                return doc
     """, 4, "yaml.safe_load"),
    "async": ("""
        import yaml

        async def f(reader):
            data = await reader.read()
            async with reader as r:
                return yaml.safe_load(data)
     """, 6, "yaml.safe_load"),
    "decorator_with_args": ("""
        import functools
        import yaml

        @functools.lru_cache(maxsize=yaml.__version__.count("."))
        def f(text):
            return yaml.full_load(text)
     """, 6, "yaml.full_load"),
    "nested": ("""
        import yaml

        class Outer:
            class Inner:
                def method(self, text):
                    def helper():
                        return yaml.unsafe_load(text)
                    return helper()
     """, 7, "yaml.unsafe_load"),
    "try_import": ("""
        try:
            import yaml
        except ImportError:
            yaml = None

        def f(text):
            return yaml.safe_load(text)
     """, 7, "yaml.safe_load"),
    "type_checking": ("""
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            from yaml import Loader
        import yaml

        def f(text):
            return yaml.load(text, Loader=yaml.FullLoader)
     """, 7, "yaml.load"),
    "import_as_dotted": ("""
        import yaml.constructor as ctor

        def f(node):
            return ctor.FullConstructor().construct_document(node)
     """, 4, "yaml.constructor.FullConstructor"),
    "import_in_function": ("""
        def f(text):
            import yaml
            from yaml import safe_load as sl
            return sl(text) or yaml.safe_load(text)
     """, 4, "yaml.safe_load"),
}


@pytest.mark.parametrize("case", sorted(SYNTAX))
def test_syntax_forms_are_located(tmp_path, case):
    src, line, symbol = SYNTAX[case]
    usage, out = locate(tmp_path, {"app/mod.py": src})
    assert not out.parse_failures
    found = calls(usage)
    assert any(f == "app/mod.py" and ln == line and s.startswith(symbol) for f, ln, s in found), found


def test_reexport_chain_three_levels_and_relative_imports(tmp_path):
    usage, _ = locate(tmp_path, {
        "app/__init__.py": "",
        "app/lib/__init__.py": "from .inner import load\n",
        "app/lib/inner/__init__.py": "from .core import load\n",
        "app/lib/inner/core.py": "from yaml import safe_load as load\n",
        "app/views.py": """
            from .lib import load

            def view(body):
                return load(body)
        """})
    assert ("app/views.py", 4, "yaml.safe_load") in calls(usage), calls(usage)


# ---------------------------------------------------------------- files that must not crash the scan

NASTY = {
    "python2.py": b'import yaml\nprint "hello"\nexec "x = 1"\n',
    "latin1_no_decl.py": "import yaml\nNAME = 'caf\xe9'\nyaml.safe_load(NAME)\n".encode("latin-1"),
    "latin1_decl.py": "# -*- coding: latin-1 -*-\nimport yaml\nNAME = 'caf\xe9'\nyaml.safe_load(NAME)\n".encode("latin-1"),
    "nulls.py": b"import yaml\nx = 1\x00\x00\nyaml.safe_load(x)\n",
    "binary.py": bytes(range(256)) * 40,
    "deep.py": b"import yaml\nx = " + b"(" * 5000 + b"1" + b")" * 5000 + b"\nyaml.safe_load(x)\n",
    "deep_calls.py": b"import yaml\nx = " + b"f(" * 3000 + b"1" + b")" * 3000 + b"\n",
}


def test_nasty_files_are_skipped_or_parsed_and_logged(tmp_path):
    good = "import yaml\n\ndef f(t):\n    return yaml.safe_load(t)\n"
    usage, out = locate(tmp_path, {**{f"app/{k}": v for k, v in NASTY.items()}, "app/good.py": good})
    assert ("app/good.py", 4, "yaml.safe_load") in calls(usage)             # the scan went on
    failed = {f.split(":")[0].split(" ")[0] for f in out.parse_failures}
    for name in ("python2.py", "nulls.py", "binary.py"):
        assert any(name in f for f in failed), (name, out.parse_failures)
    for name in ("latin1_no_decl.py", "latin1_decl.py"):                    # decoded, not lost
        assert any(s.file == f"app/{name}" for s in usage.sites), name
    # the other readers of the same files (reachability index, repo context) must cope as well
    from depscan.agents.repo_context import RepoContextAgent
    from depscan.codeindex import CodeIndex
    from depscan.models import ScanResult
    from datetime import datetime, timezone
    repo = tmp_path / "repo"
    rmap = RepoMapperAgent(tmp_path / "ws").run(RepoMapperInput(url=str(repo)))
    index = CodeIndex(repo, rmap.source_files, "unknown")
    assert index.reach("app/good.py", 4, "yaml.safe_load").result in ("pass", "fail", "unknown")
    assert {f.split(":")[0] for f in index.parse_failures} >= {"app/python2.py", "app/binary.py"}
    ctx = RepoContextAgent(None).run(ScanResult(created_at=datetime.now(timezone.utc), repo=rmap,
                                                vulnerabilities=[], usages={}))
    assert ctx is not None


def test_a_50k_line_file(tmp_path):
    big = "import yaml\n" + "".join(f"v{i} = {i}\n" for i in range(50_000)) + "yaml.safe_load(v1)\n"
    usage, out = locate(tmp_path, {"app/big.py": big})
    assert ("app/big.py", 50_002, "yaml.safe_load") in calls(usage) and not out.parse_failures
