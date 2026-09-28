"""T1: manifest parsing. Property-based requirement lines, nasty real-world files, big lockfiles."""

import json
import time
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from packaging.requirements import Requirement

from depscan.agents.repo_mapper import RepoMapperAgent
from depscan.models import RepoMapperInput
from depscan.parsers.python_manifests import (PipfileLockParser, PoetryLockParser, PyprojectParser,
                                              RequirementsTxtParser, UvLockParser, normalize_name)

# ---------------------------------------------------------------- generated requirement lines

names = st.from_regex(r"[A-Za-z][A-Za-z0-9]{0,6}([-_.][A-Za-z0-9]{1,5}){0,2}", fullmatch=True)
versions = st.from_regex(r"[0-9]{1,3}(\.[0-9]{1,3}){0,2}((a|b|rc)[0-9]|\.post[0-9]|\.dev[0-9])?", fullmatch=True)
ops = st.sampled_from(["==", "!=", "<=", ">=", "<", ">", "~=", "==="])
extras = st.lists(st.from_regex(r"[a-z][a-z0-9]{0,6}", fullmatch=True), max_size=3, unique=True)
markers = st.sampled_from([None, 'python_version >= "3.8"', 'sys_platform == "linux"',
                           'platform_system != "Windows" and python_version < "3.13"', 'extra == "dev"'])


@st.composite
def requirement_lines(draw):
    name, ex, marker = draw(names), draw(extras), draw(markers)
    specs = draw(st.lists(st.tuples(ops, versions), max_size=2, unique_by=lambda t: t[0]))
    if any(op == "~=" and "." not in v for op, v in specs):          # ~= needs at least two release parts
        specs = [(op if not (op == "~=" and "." not in v) else ">=", v) for op, v in specs]
    if any(op == "===" for op, _ in specs):
        specs = [s for s in specs if s[0] == "==="][:1]
    req = name + (f"[{','.join(ex)}]" if ex else "") + ",".join(f"{op}{v}" for op, v in specs)
    if marker:
        req += f"; {marker}"
    line = req
    if draw(st.booleans()):
        line += " --hash=sha256:" + "a" * 64
    if draw(st.booleans()):
        line += "  # a comment"
    if draw(st.booleans()) and " " not in req:
        line = line.replace(";", " \\\n    ;", 1) if marker else line + " \\\n    "
    return req, line


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(requirement_lines())
def test_generated_requirement_lines_round_trip(tmp_path, pair):
    req_text, line = pair
    path = tmp_path / "requirements.txt"
    path.write_text(f"--index-url https://example.org/simple\n{line}\n", encoding="utf-8")
    out = RequirementsTxtParser().parse(path, "requirements.txt")
    expected = Requirement(req_text)
    assert len(out.entries) == 1, (line, out.warnings)
    e = out.entries[0]
    assert e.name == normalize_name(expected.name)
    assert e.extras == sorted(expected.extras)
    assert e.marker == (str(expected.marker) if expected.marker else None)
    assert (e.version_spec or None) == (str(expected.specifier) or None)
    pins = [s for s in expected.specifier if s.operator in ("==", "===") and "*" not in s.version]
    if len(list(expected.specifier)) == 1 and pins:
        assert e.resolved_version == pins[0].version
    else:
        assert e.resolved_version is None


# ---------------------------------------------------------------- nasty real-world requirement files

def parse_text(tmp_path: Path, text: str, name: str = "requirements.txt", raw: bytes | None = None):
    path = tmp_path / name
    path.write_bytes(raw if raw is not None else text.encode("utf-8"))
    return RequirementsTxtParser().parse(path, name)


def names_of(out) -> list[str]:
    return [e.name for e in out.entries]


def test_bom_crlf_tabs_and_long_lines(tmp_path):
    raw = "﻿flask==3.1.3\r\n\trequests==2.30.0\t# tabbed\r\n".encode("utf-8") + \
        b"pyyaml==5.3.1" + b" " * 5000 + b"# long\r\n" + ("x" * 20000).encode() + b"==1.0\r\n"
    out = parse_text(tmp_path, "", raw=raw)
    assert names_of(out)[:3] == ["flask", "requests", "pyyaml"]
    assert out.entries[0].resolved_version == "3.1.3"


def test_pip_options_are_ignored(tmp_path):
    out = parse_text(tmp_path, "--index-url https://x/simple\n--extra-index-url https://y/simple\n"
                               "-i https://z\n--find-links ./wheels\n--trusted-host x\n--pre\n--no-binary :all:\n"
                               "idna==3.7 --hash=sha256:" + "b" * 64 + " --hash=sha256:" + "c" * 64 + "\n")
    assert names_of(out) == ["idna"] and out.entries[0].resolved_version == "3.7"


def test_include_cycles_missing_files_and_env_vars(tmp_path):
    (tmp_path / "a.txt").write_text("-r b.txt\nflask==3.1.3\n")
    (tmp_path / "b.txt").write_text("-r a.txt\n-r missing.txt\n-r ${REQ_DIR}/x.txt\nidna==3.7\n")
    out = RequirementsTxtParser().parse(tmp_path / "a.txt", "a.txt")
    assert sorted(names_of(out)) == ["flask", "idna"]
    assert sum("not found" in w for w in out.warnings) == 2


def test_duplicate_conflicting_pins_are_reported(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.30.0\nrequests==2.31.0\n")
    rmap = RepoMapperAgent(tmp_path / "ws").run(RepoMapperInput(url=str(tmp_path)))
    reqs = [d for d in rmap.dependencies if d.name == "requests"]
    assert len(reqs) == 1
    assert any("requests" in w and ("2.30.0" in w or "2.31.0" in w) for w in rmap.warnings), rmap.warnings


def test_pyproject_dynamic_dependencies_and_broken_toml(tmp_path):
    repo = tmp_path / "repo"
    (repo / "svc").mkdir(parents=True)
    (repo / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "1"\ndynamic = ["dependencies"]\n')
    (repo / "svc" / "pyproject.toml").write_text('[project\nname = broken')
    (repo / "requirements.txt").write_text("flask==3.1.3\n")
    rmap = RepoMapperAgent(tmp_path / "ws").run(RepoMapperInput(url=str(repo)))
    assert [d.name for d in rmap.dependencies] == ["flask"]                  # the scan continues
    assert any("svc/pyproject.toml" in w for w in rmap.warnings)              # a clear message for the broken file
    assert any("dynamic" in w for w in rmap.warnings)


def test_invalid_lines_warn_and_parsing_continues(tmp_path):
    out = parse_text(tmp_path, "flask==3.1.3\nthis is not a requirement\n==1.0\nidna===3.7\n")
    assert names_of(out) == ["flask", "idna"] and len(out.warnings) == 2


# ---------------------------------------------------------------- big lockfiles

N = 3000


def poetry_lock(n: int) -> str:
    return "\n".join(f'[[package]]\nname = "pkg{i}"\nversion = "1.{i}.0"\noptional = false\n'
                     f'[package.dependencies]\npkg{i + 1} = "*"\n' for i in range(n))


def uv_lock(n: int) -> str:
    return 'version = 1\n' + "\n".join(f'[[package]]\nname = "pkg{i}"\nversion = "1.{i}.0"\n'
                                         f'source = {{ registry = "https://pypi.org/simple" }}\n'
                                         f'dependencies = [{{ name = "pkg{i + 1}" }}]\n' for i in range(n))


def pipfile_lock(n: int) -> str:
    return json.dumps({"_meta": {}, "default": {f"pkg{i}": {"version": f"==1.{i}.0"} for i in range(n)},
                       "develop": {}})


@pytest.mark.parametrize("parser,name,text", [
    (PoetryLockParser(), "poetry.lock", poetry_lock(N)),
    (UvLockParser(), "uv.lock", uv_lock(N)),
    (PipfileLockParser(), "Pipfile.lock", pipfile_lock(N)),
], ids=["poetry.lock", "uv.lock", "Pipfile.lock"])
def test_lockfiles_with_thousands_of_entries_are_fast(tmp_path, parser, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    start = time.perf_counter()
    out = parser.parse(path, name)
    assert time.perf_counter() - start < 2.0
    assert len(out.entries) >= N and out.entries[0].resolved_version == "1.0.0"
