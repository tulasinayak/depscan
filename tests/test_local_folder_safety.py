"""A local-folder input must never be deleted or modified, under any code path."""

import hashlib
import os
from pathlib import Path

import git
import pytest

from depscan.agents.repo_mapper import CLONE_MARKER, RepoMapperAgent, clone_dir_name
from depscan.models import RepoMapperInput


def snapshot(root: Path) -> dict[str, tuple[str, int]]:
    """Relative path -> (content hash, mtime_ns) for every file and directory."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            digest = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "dir"
            out[p.relative_to(root).as_posix()] = (digest, p.stat().st_mtime_ns)
    return out


def make_project(root: Path) -> Path:
    (root / "app").mkdir(parents=True)
    (root / "app" / "main.py").write_text("import yaml\n")
    (root / "requirements.txt").write_text("pyyaml==3.13\n")
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    return root


@pytest.fixture
def no_clone(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("git clone must not be called")
    monkeypatch.setattr(git.Repo, "clone_from", fail)


def test_local_folder_outside_workspace_untouched(tmp_path, no_clone):
    project = make_project(tmp_path / "myproject")
    before = snapshot(project)
    result = RepoMapperAgent(workspace=tmp_path / "workspace").run(RepoMapperInput(url=str(project)))
    assert result.local_path == str(project.resolve())
    assert [d.name for d in result.dependencies] == ["pyyaml"]
    assert snapshot(project) == before
    assert not (tmp_path / "workspace").exists()                 # nothing created either


def test_local_folder_inside_workspace_untouched(tmp_path, no_clone):
    """Even a folder that sits exactly where a clone would go, and carries our clone marker, is only read."""
    workspace = tmp_path / "workspace"
    project = make_project(workspace / clone_dir_name("https://github.com/alice/tools"))
    (project / ".git" / CLONE_MARKER).write_text("https://github.com/alice/tools")
    before = snapshot(project)
    RepoMapperAgent(workspace=workspace).run(RepoMapperInput(url=str(project)))
    assert snapshot(project) == before


def test_url_never_deletes_a_folder_depscan_did_not_create(tmp_path, no_clone):
    workspace = tmp_path / "workspace"
    project = make_project(workspace / "alice__tools")            # same path a clone of alice/tools would use
    before = snapshot(project)
    with pytest.raises(RuntimeError, match="Refusing to delete"):
        RepoMapperAgent(workspace=workspace).run(RepoMapperInput(url="https://github.com/alice/tools"))
    assert snapshot(project) == before


def test_existing_clone_is_updated_with_fetch_and_reset(tmp_path, monkeypatch):
    origin = git.Repo.init(tmp_path / "origin")
    (tmp_path / "origin" / "requirements.txt").write_text("pyyaml==5.3\n")
    origin.index.add(["requirements.txt"])
    origin.index.commit("first", author=git.Actor("t", "t@t"), committer=git.Actor("t", "t@t"))
    url = (tmp_path / "origin").as_uri()                          # file:///... -> treated as a remote, not a folder
    agent = RepoMapperAgent(workspace=tmp_path / "workspace")
    first = agent.run(RepoMapperInput(url=url))

    (tmp_path / "origin" / "requirements.txt").write_text("pyyaml==6.0.1\n")
    origin.index.add(["requirements.txt"])
    second_commit = origin.index.commit("second", author=git.Actor("t", "t@t"), committer=git.Actor("t", "t@t"))
    clones = []
    real_clone = git.Repo.clone_from
    monkeypatch.setattr(git.Repo, "clone_from", lambda *a, **k: clones.append(a) or real_clone(*a, **k))
    second = agent.run(RepoMapperInput(url=url))
    assert clones == []                                           # updated in place, not re-cloned
    assert first.commit != second.commit == second_commit.hexsha
    assert second.dependencies[0].resolved_version == "6.0.1"


def test_url_replaces_only_its_own_previous_clone(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    cloned: list[str] = []

    def fake_clone(url, dest, depth):
        cloned.append(url)
        make_project(Path(dest))

    monkeypatch.setattr(git.Repo, "clone_from", fake_clone)
    agent = RepoMapperAgent(workspace=workspace)
    agent.run(RepoMapperInput(url="https://github.com/alice/tools"))
    agent.run(RepoMapperInput(url="https://github.com/alice/tools"))      # replaces its own clone
    agent.run(RepoMapperInput(url="https://github.com/bob/tools"))        # same repo name, other owner
    assert cloned == ["https://github.com/alice/tools"] * 2 + ["https://github.com/bob/tools"]
    assert sorted(p.name for p in workspace.iterdir()) == ["alice__tools", "bob__tools"]
    assert (workspace / "bob__tools" / ".git" / CLONE_MARKER).read_text() == "https://github.com/bob/tools"
