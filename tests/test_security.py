"""T8: depscan's own safety against malicious repositories and packages.

Every fixture is made in a temp dir by the test itself. Nothing is fetched from the network: "remote" repos are local
git repos cloned through file:// (allowed only in tests with allow_file_urls=True).
"""

import io
import os
import subprocess
import sys
import tarfile
import textwrap
import zipfile
from pathlib import Path

import git
import pytest

from depscan import grounding, safety
from depscan.agents.repo_context import readme_head
from depscan.agents.repo_mapper import RepoMapperAgent
from depscan.codeindex import CodeIndex
from depscan.grounding import read_members, safe_filename
from depscan.models import RepoMapperInput
from depscan.safety import UnsafeRepoURL, inside, validate_repo_url

pytestmark = pytest.mark.security
SECRET = "TOP-SECRET-7f3a9c"                      # a marker that must never appear in anything depscan produces


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8", newline="\n")   # LF, as in a real repo
    return root


def link_or_skip(link: Path, target: Path, directory: bool = False) -> None:
    """A symlink, or on Windows without the privilege a directory junction; skip when neither can be made."""
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError):
        if directory and sys.platform == "win32":
            import _winapi
            _winapi.CreateJunction(str(target), str(link))
        else:
            pytest.skip("cannot create symlinks here")


def map_repo(repo: Path, tmp_path: Path):
    return RepoMapperAgent(tmp_path / "workspace").run(RepoMapperInput(url=str(repo)))


# ---------------------------------------------------------------- symlinks and paths outside the repo

@pytest.fixture
def outside(tmp_path) -> Path:
    return write(tmp_path / "outside", {"secret.txt": f"{SECRET}\n", "secret.py": f"TOKEN = '{SECRET}'\n",
                                        "pkg/mod.py": f"import requests\nKEY = '{SECRET}'\n",
                                        "requirements.txt": f"secretpkg-{SECRET.lower()}==1.0\n"})


def test_symlinked_or_junction_dirs_are_never_read(tmp_path, outside):
    repo = write(tmp_path / "repo", {"requirements.txt": "requests==2.30.0\n", "app/main.py": "import requests\n"})
    link_or_skip(repo / "vendored", outside / "pkg", directory=True)     # a junction on Windows without privileges
    link_or_skip(repo / "deps", outside, directory=True)                 # holds requirements.txt and secret.py
    rmap = map_repo(repo, tmp_path)
    assert SECRET not in rmap.model_dump_json() and SECRET.lower() not in rmap.model_dump_json()
    assert rmap.source_files == ["app/main.py"] and [d.name for d in rmap.dependencies] == ["requests"]
    assert any("symbolic link" in w for w in rmap.warnings)


def test_symlinked_files_are_never_read(tmp_path, outside):
    """Needs file symlinks (Linux/macOS, or Windows with Developer Mode); skipped otherwise."""
    repo = write(tmp_path / "repo", {"requirements.txt": "requests==2.30.0\n", "app/main.py": "import requests\n"})
    link_or_skip(repo / "app" / "stolen.py", outside / "secret.py")
    link_or_skip(repo / "requirements-dev.txt", outside / "requirements.txt")
    link_or_skip(repo / "README.md", outside / "secret.txt")
    link_or_skip(repo / "Procfile", outside / "secret.txt")
    rmap = map_repo(repo, tmp_path)
    dumped = rmap.model_dump_json()
    assert SECRET not in dumped and SECRET.lower() not in dumped
    assert rmap.source_files == ["app/main.py"]
    assert any("symbolic link" in w for w in rmap.warnings)
    assert SECRET not in readme_head(repo)
    assert SECRET not in CodeIndex(repo, rmap.source_files, "unknown")._config_text()


def test_home_and_system_folders_are_not_followed(tmp_path):
    repo = write(tmp_path / "repo", {"requirements.txt": "requests==2.30.0\n"})
    targets = [Path.home(), Path(os.environ.get("SystemRoot", "C:/Windows")) if sys.platform == "win32" else Path("/etc")]
    for i, target in enumerate(targets):
        link_or_skip(repo / f"link{i}", target, directory=True)
    rmap = map_repo(repo, tmp_path)
    assert rmap.source_files == [] and [d.name for d in rmap.dependencies] == ["requests"]


@pytest.mark.parametrize("include", ["../outside/requirements.txt", "{abs}", "sub/../../outside/requirements.txt"])
def test_requirement_includes_cannot_leave_the_repo(tmp_path, outside, include):
    include = include.format(abs=(outside / "requirements.txt").as_posix())
    repo = write(tmp_path / "repo", {"requirements.txt": f"requests==2.30.0\n-r {include}\n"})
    rmap = map_repo(repo, tmp_path)
    assert [d.name for d in rmap.dependencies] == ["requests"]
    assert any("outside the repository" in w for w in rmap.warnings)


def test_include_cycles_end(tmp_path):
    repo = write(tmp_path / "repo", {"requirements.txt": "-r b.txt\nflask==3.1.3\n", "b.txt": "-r requirements.txt\nidna==3.7\n"})
    assert sorted(d.name for d in map_repo(repo, tmp_path).dependencies) == ["flask", "idna"]


def test_inside_rejects_escapes(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    assert inside(root, root / "a" / "b.py") and not inside(root, root / ".." / "x")
    assert not inside(root, tmp_path / "other.py") and not inside(root, Path("/etc/passwd"))


# ---------------------------------------------------------------- limits

def test_size_and_count_limits_give_warnings(tmp_path, monkeypatch):
    from depscan.agents import repo_mapper
    monkeypatch.setattr(repo_mapper, "MAX_SOURCE_BYTES", 10_000)
    monkeypatch.setattr(repo_mapper, "MAX_WALK_ENTRIES", 300)
    repo = write(tmp_path / "repo", {"requirements.txt": "requests==2.30.0\n", "big.py": "x = 1\n" * 5000})
    for i in range(400):
        (repo / f"f{i:03}.txt").write_text("x")
    rmap = map_repo(repo, tmp_path)
    assert "big.py" not in rmap.source_files
    assert any("over the size limit" in w for w in rmap.warnings)
    assert any("very large" in w for w in rmap.warnings)


@pytest.mark.slow
def test_huge_file_and_many_files_finish_with_limits(tmp_path):
    repo = write(tmp_path / "repo", {"requirements.txt": "requests==2.30.0\n", "app.py": "import requests\n"})
    with (repo / "generated.py").open("wb") as fh:            # 500 MB, sparse where the file system allows it
        fh.truncate(500 * 1024 * 1024)
    many = repo / "data"
    many.mkdir()
    for i in range(20_000):
        (many / f"{i}.py").write_bytes(b"")
    rmap = map_repo(repo, tmp_path)
    assert "generated.py" not in rmap.source_files and len(rmap.source_files) == safety.MAX_SOURCE_FILES
    assert any("over the size limit" in w for w in rmap.warnings)


# ---------------------------------------------------------------- repository URLs

@pytest.mark.parametrize("url", [
    "file:///etc", "file://C:/Windows", "ext::sh -c touch% /tmp/pwned", "fd::17", "-uhelp", "--upload-pack=touch x",
    "http://github.com/a/b", "git://github.com/a/b", "ssh://git@github.com/a/b", "git@github.com:a/b.git",
    "https://user:pass@github.com/a/b", "https://ghp_token@github.com/a/b", "https:///nohost", "https://github.com/a/b?x=1",
    "https://github.com/a/b\n--upload-pack=x", "", "  ",
])
def test_unsafe_urls_are_rejected(url, tmp_path, monkeypatch):
    with pytest.raises(UnsafeRepoURL):
        validate_repo_url(url)
    monkeypatch.setattr(git.Repo, "clone_from", lambda *a, **k: pytest.fail("clone must not run"))
    if not Path(url).expanduser().is_dir():
        with pytest.raises(RuntimeError):
            RepoMapperAgent(tmp_path / "ws").run(RepoMapperInput(url=url))


@pytest.mark.parametrize("url", ["https://github.com/pallets/flask", "https://gitlab.com/group/sub/project.git"])
def test_normal_https_urls_are_accepted(url):
    assert validate_repo_url(url) == url


# ---------------------------------------------------------------- cloning runs nothing from the repo

def git_run(cwd: Path, *args: str, env=None) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=env)


@pytest.fixture
def hostile_origin(tmp_path, monkeypatch):
    """An origin with a filter attribute, a submodule and a committed symlink, plus a 'user' global git config
    that defines that filter and a hooks path. A normal clone would run both."""
    marks = tmp_path / "marks"
    marks.mkdir()
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    hook = hooks / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch '{(marks / 'hook').as_posix()}'\n", newline="\n")
    hook.chmod(0o755)
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text(textwrap.dedent(f"""
        [user]
            name = t
            email = t@t
        [core]
            hooksPath = {hooks.as_posix()}
        [filter "evil"]
            smudge = sh -c 'touch \\"{(marks / 'filter').as_posix()}\\" && cat'
            clean = cat
        [protocol "file"]
            allow = always
    """), encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    env = {**os.environ, "GIT_CONFIG_GLOBAL": str(gitconfig)}
    sub = tmp_path / "sub"
    sub.mkdir()
    git_run(sub, "init", "-q", env=env)
    (sub / "subfile.py").write_text("x = 1\n")
    git_run(sub, "add", ".", env=env)
    git_run(sub, "commit", "-qm", "sub", env=env)
    origin = write(tmp_path / "origin", {"requirements.txt": "requests==2.30.0\n", "app.py": "import requests\n",
                                         ".gitattributes": "*.py filter=evil\n"})
    git_run(origin, "init", "-q", env=env)
    git_run(origin, "add", ".", env=env)
    git_run(origin, "-c", "protocol.file.allow=always", "submodule", "add", "-q", sub.as_uri(), "vendor/sub", env=env)
    blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=origin, input=b"/etc/passwd",
                          capture_output=True, check=True, env=env).stdout.decode().strip()
    git_run(origin, "update-index", "--add", "--cacheinfo", f"120000,{blob},passwd_link", env=env)
    git_run(origin, "commit", "-qm", "origin", env=env)
    for m in marks.iterdir():                     # building the fixture itself ran the hook (submodule clone)
        m.unlink()
    return origin, marks, env


@pytest.mark.slow                                  # builds real git repos
def test_a_plain_clone_would_run_the_hook_and_filter(hostile_origin, tmp_path):
    """Control: proves the fixture is really hostile (so the next test means something)."""
    origin, marks, env = hostile_origin
    git_run(tmp_path, "clone", "-q", origin.as_uri(), "plain", env=env)
    assert (marks / "hook").exists() and (marks / "filter").exists()


@pytest.mark.slow                                  # builds real git repos
def test_depscan_clone_runs_no_hooks_filters_or_submodules(hostile_origin, tmp_path):
    origin, marks, _ = hostile_origin
    rmap = RepoMapperAgent(tmp_path / "workspace", allow_file_urls=True).run(RepoMapperInput(url=origin.as_uri()))
    clone = Path(rmap.local_path)
    assert not (marks / "hook").exists() and not (marks / "filter").exists()
    assert not any((clone / "vendor" / "sub").iterdir()) if (clone / "vendor" / "sub").exists() else True
    link = clone / "passwd_link"
    assert link.exists() and not link.is_symlink() and link.read_text() == "/etc/passwd"   # a plain file
    assert [d.name for d in rmap.dependencies] == ["requests"]
    # updating the existing clone is hardened the same way
    RepoMapperAgent(tmp_path / "workspace", allow_file_urls=True).run(RepoMapperInput(url=origin.as_uri()))
    assert not (marks / "hook").exists() and not (marks / "filter").exists()


@pytest.mark.slow                                  # builds real git repos
def test_file_urls_are_refused_outside_tests(hostile_origin, tmp_path):
    origin, _, _ = hostile_origin
    with pytest.raises(UnsafeRepoURL):
        RepoMapperAgent(tmp_path / "workspace").run(RepoMapperInput(url=origin.as_uri()))


# ---------------------------------------------------------------- downloaded package archives (5a-extra)

def make_zip(members: list[tuple[str, bytes, int]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in members:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            zf.writestr(info, data)
    return buf.getvalue()


def make_tar(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for info, data in members:
            tf.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def tinfo(name: str, size: int = 0, kind: bytes = tarfile.REGTYPE, linkname: str = "") -> tarfile.TarInfo:
    t = tarfile.TarInfo(name)
    t.size, t.type, t.linkname = size, kind, linkname
    return t


def test_zip_members_with_traversal_absolute_or_link_are_refused(tmp_path):
    path = tmp_path / "evil-1.0-py3-none-any.whl"
    path.write_bytes(make_zip([("../escape.py", b"x", 0o100644), ("/abs.py", b"x", 0o100644),
                               ("C:/win.py", b"x", 0o100644), ("..\\back.py", b"x", 0o100644),
                               ("pkg/link.py", b"/etc/passwd", 0o120777), ("pkg/ok.py", b"x = 1", 0o100644)]))
    assert [r for r, _ in read_members(path, lambda r: True)] == ["pkg/ok.py"]
    assert not list(tmp_path.glob("escape*")) and not (tmp_path.parent / "escape.py").exists()


def test_tar_members_with_traversal_links_or_devices_are_refused(tmp_path):
    path = tmp_path / "evil-1.0.tar.gz"
    path.write_bytes(make_tar([(tinfo("evil-1.0/../../escape.py", 1), b"x"), (tinfo("/abs.py", 1), b"x"),
                               (tinfo("evil-1.0/sym.py", kind=tarfile.SYMTYPE, linkname="/etc/passwd"), None),
                               (tinfo("evil-1.0/hard.py", kind=tarfile.LNKTYPE, linkname="/etc/passwd"), None),
                               (tinfo("evil-1.0/dev", kind=tarfile.CHRTYPE), None),
                               (tinfo("evil-1.0/pkg/ok.py", 5), b"x = 1")]))
    assert [r for r, _ in read_members(path, lambda r: True)] == ["evil-1.0/pkg/ok.py"]


def test_zip_and_tar_bombs_are_stopped_by_the_caps(tmp_path, monkeypatch):
    monkeypatch.setattr(grounding, "MAX_FILE_BYTES", 1000)
    monkeypatch.setattr(grounding, "MAX_UNCOMPRESSED", 50_000)
    zeros = b"\0" * 40_000
    z = tmp_path / "bomb-1.0-py3-none-any.whl"
    z.write_bytes(make_zip([(f"pkg/m{i}.py", zeros, 0o100644) for i in range(5)] + [("pkg/late.py", b"x", 0o100644)]))
    assert list(read_members(z, lambda r: True)) == []          # every member too big, and the walk stops early
    t = tmp_path / "bomb-1.0.tar.gz"
    t.write_bytes(make_tar([(tinfo(f"bomb-1.0/m{i}.py", len(zeros)), zeros) for i in range(5)]
                           + [(tinfo("bomb-1.0/late.py", 1), b"x")]))
    assert list(read_members(t, lambda r: True)) == []          # stopped before "late.py"
    monkeypatch.setattr(grounding, "MAX_MEMBERS", 3)
    many = tmp_path / "many-1.0-py3-none-any.whl"
    many.write_bytes(make_zip([(f"pkg/m{i}.py", b"x", 0o100644) for i in range(10)]))
    assert len(list(read_members(many, lambda r: True))) == 3


@pytest.mark.parametrize("name", ["../../evil.whl", "..\\evil.whl", "/abs.whl", "C:evil.whl", ".hidden.whl",
                                  "a/b.whl", "", "x.whl\n"])
def test_unsafe_release_file_names_are_refused(name):
    assert safe_filename(name) is None


def test_release_files_must_be_https_and_safely_named(tmp_path):
    src = grounding.PackageSource(tmp_path / "cache", offline=False)
    src.release = lambda name, version: [
        {"filename": "../../escape-1.0-py3-none-any.whl", "url": "https://files.example/x", "packagetype": "bdist_wheel",
         "size": 10},
        {"filename": "plain-1.0-py3-none-any.whl", "url": "http://files.example/x", "packagetype": "bdist_wheel",
         "size": 10}]
    src._download = lambda f, path: pytest.fail("must not download")
    assert src.archive("evil", "1.0") is None
    assert len([m for m in src.log if "unsafe name or not https" in m]) == 2


# ---------------------------------------------------------------- untrusted text in the GUI

@pytest.mark.slow
def test_untrusted_text_is_escaped_in_the_gui(tmp_path):
    from streamlit.testing.v1 import AppTest
    from test_gui import app_with, main_with
    from test_orchestrator import FIX, make_orch
    orch = make_orch(tmp_path)
    result = orch.scan(str(FIX / "flask_vuln_repo"))
    evil = "<script>alert(1)</script>"
    for dv in result.vulnerabilities:
        dv.dependency.name = evil
        for v in dv.vulnerabilities:
            v.summary = f"<img src=x onerror=alert(1)> {evil}"
            v.cvss.severity = evil if v is dv.vulnerabilities[0] else v.cvss.severity
    for at in (main_with(orch, result), app_with(orch, result)):
        at.run()
        assert not at.exception, at.exception
        html = [m.value for m in at.markdown if m.proto.allow_html]
        assert html, "expected some HTML-enabled elements (badges)"
        for value in html:
            assert "<script" not in value and "<img" not in value, value
