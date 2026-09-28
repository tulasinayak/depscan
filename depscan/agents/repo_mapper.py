"""RepoMapperAgent (deterministic): clone the repo, list source files and manifests, extract dependencies."""

import os
import re
import shutil
import stat
import sys
from pathlib import Path, PurePosixPath

import git

from depscan.models import Dependency, RepoMap, RepoMapperInput
from depscan.parsers import PARSERS, ParsedEntry, find_parser

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", "venv", ".venv", "env", ".env",
             "build", "dist", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages",
             ".eggs", ".idea", ".vscode",
             ".depscan"}  # holds a repo's evaluation answers; must never reach any agent or prompt
SOURCE_SUFFIXES = {".py"}
CLONE_MARKER = "depscan-clone"  # written inside .git/ of every clone we create; only such dirs are ever deleted


def parse_repo_url(url: str) -> tuple[str | None, str]:
    """'https://github.com/owner/repo.git' / 'git@github.com:owner/repo' -> ('owner', 'repo')."""
    path = re.sub(r"^[a-z+]+://[^/]+/", "", url.strip())      # scheme://host/
    path = re.sub(r"^[^@/]+@[^:/]+:", "", path)                # git@host:
    parts = [p for p in re.sub(r"\.git$", "", path.rstrip("/")).split("/") if p]
    repo = parts[-1] if parts else "repo"
    owner = parts[-2] if len(parts) >= 2 else None
    return owner, repo


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)


def repo_name_from_url(url: str) -> str:
    return _safe(parse_repo_url(url)[1])


def clone_dir_name(url: str) -> str:
    owner, repo = parse_repo_url(url)
    return f"{_safe(owner)}__{_safe(repo)}" if owner else _safe(repo)


def _force_remove(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)  # git pack files are read-only on Windows
    func(path)


class RepoMapperAgent:
    def __init__(self, workspace: Path):
        self.workspace = workspace

    def run(self, inp: RepoMapperInput) -> RepoMap:
        warnings: list[str] = []
        repo_path, repo_name, slug = self.fetch(inp.url, warnings)
        return self.map(inp.url, repo_path, repo_name, slug, warnings)

    def fetch(self, url: str, warnings: list[str]) -> tuple[Path, str, str]:
        """Clone/update a URL into the workspace, or accept a local folder as-is. -> (path, name, slug)"""
        local = Path(url).expanduser()
        if local.is_dir():
            # Local folders are only ever read: never cloned into, cleaned or deleted.
            return local.resolve(), local.resolve().name, _safe(local.resolve().name)
        repo_name, slug = repo_name_from_url(url), clone_dir_name(url)
        self._clone(url, self.workspace / slug, warnings)
        return self.workspace / slug, repo_name, slug

    def map(self, url: str, repo_path: Path, repo_name: str, slug: str, warnings: list[str]) -> RepoMap:
        """Walk the tree and extract dependencies (never executes anything)."""
        commit = self._commit(repo_path)

        source_files: list[str] = []
        manifests: list[tuple[str, Path]] = []
        for dirpath, dirnames, filenames in os.walk(repo_path):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info"))
            for fn in sorted(filenames):
                path = Path(dirpath) / fn
                rel = path.relative_to(repo_path).as_posix()
                if path.suffix in SOURCE_SUFFIXES:
                    source_files.append(rel)
                if find_parser(rel, PARSERS):
                    manifests.append((rel, path))

        parsed: list[tuple[str, int, list[ParsedEntry]]] = []
        included_by: dict[str, str] = {}
        for rel, path in manifests:
            parser = find_parser(rel, PARSERS)
            out = parser.parse(path, rel)
            warnings += out.warnings
            parsed.append((rel, parser.priority, out.entries))
            for e in out.entries:
                if e.source_file != rel:                 # pulled in with -r / -c
                    included_by.setdefault(e.source_file, rel)
        dependencies = merge_projects(parsed, included_by, warnings)
        if not manifests:
            warnings.append("No Python manifest found (requirements*.txt, pyproject.toml, Pipfile, "
                            "poetry.lock, Pipfile.lock, uv.lock).")
        return RepoMap(repo_url=url, repo_name=repo_name, slug=slug, local_path=str(repo_path), commit=commit,
                       source_files=source_files, manifest_files=[r for r, _ in manifests],
                       dependencies=dependencies, warnings=warnings)

    def _clone(self, url: str, dest: Path, warnings: list[str] | None = None) -> None:
        """Shallow clone into dest. An existing depscan clone of the same URL is updated with
        `git fetch --depth 1` + hard reset instead; any error there falls back to delete + re-clone.
        Directories without depscan's marker are never touched."""
        marker = dest / ".git" / CLONE_MARKER
        if dest.exists():
            ours = dest.resolve().is_relative_to(self.workspace.resolve()) and marker.exists()
            if not ours:
                raise RuntimeError(f"Refusing to delete {dest}: it was not created by depscan. "
                                   "Move it away or scan it as a local folder instead.")
            if marker.read_text(encoding="utf-8").strip() == url:
                try:
                    repo = git.Repo(dest)
                    repo.remotes.origin.fetch(depth=1)
                    repo.git.reset("--hard", "FETCH_HEAD")
                    repo.git.clean("-fdx")
                    return
                except Exception as e:  # corrupt clone, rewritten history, ...: start over
                    if warnings is not None:
                        warnings.append(f"Updating the existing clone failed ({e}); re-cloned from scratch.")
            if sys.version_info >= (3, 12):
                shutil.rmtree(dest, onexc=_force_remove)
            else:
                shutil.rmtree(dest, onerror=_force_remove)
        dest.parent.mkdir(parents=True, exist_ok=True)
        git.Repo.clone_from(url, dest, depth=1)
        marker.write_text(url, encoding="utf-8")

    @staticmethod
    def _commit(path: Path) -> str | None:
        try:
            return git.Repo(path, search_parent_directories=False).head.commit.hexsha
        except Exception:
            return None


def project_of(rel: str, included_by: dict[str, str]) -> str:
    """The sub-project a manifest belongs to: its directory ("requirements/" counts as its parent), or the
    project of the manifest that includes it via -r / -c."""
    for _ in range(10):
        if rel not in included_by:
            break
        rel = included_by[rel]
    folder = PurePosixPath(rel).parent
    if folder.name == "requirements":
        folder = folder.parent
    return "" if str(folder) == "." else str(folder)


def merge_projects(parsed: list[tuple[str, int, list[ParsedEntry]]], included_by: dict[str, str],
                   warnings: list[str]) -> list[Dependency]:
    """Merge per sub-project. A repo whose manifests all belong to one project (the usual case) is merged as a
    whole, as before; several projects (e.g. services/api and services/worker with their own requirements)
    are merged separately, so one package can be reported at a different version in each."""
    groups: dict[str, list[tuple[int, ParsedEntry]]] = {}
    for rel, prio, entries in parsed:
        groups.setdefault(project_of(rel, included_by), []).extend((prio, e) for e in entries)
    groups = {p: g for p, g in groups.items() if g}
    if len(groups) <= 1:
        return merge_entries([pe for g in groups.values() for pe in g], warnings)
    out: list[Dependency] = []
    for project, group in sorted(groups.items()):
        for dep in merge_entries(group, warnings):
            dep.project = project
            out.append(dep)
    return out


def merge_entries(entries: list[tuple[int, ParsedEntry]], warnings: list[str]) -> list[Dependency]:
    """One Dependency per package name.

    - Declared entries (pyproject, requirements, Pipfile) make a package direct. The preferred manifest
      (lowest priority number; an exact pin beats a range) supplies spec, extras and marker.
    - scope: "main" if any declaration is main, else "dev"; lockfile scope for lockfile-only packages.
    - Constraint pins (-c file) resolve declared packages that are otherwise unpinned; they never add packages.
    - Lockfile versions override everything (they say what is actually installed).
    """
    declared: dict[str, list[tuple[int, ParsedEntry]]] = {}
    locked: dict[str, ParsedEntry] = {}
    constraints: dict[str, ParsedEntry] = {}
    for prio, e in sorted(entries, key=lambda pe: pe[0]):
        if e.kind == "declared":
            declared.setdefault(e.name, []).append((prio, e))
        elif e.kind == "constraint":
            constraints.setdefault(e.name, e)
        elif e.name in locked:
            first = locked[e.name]
            if e.resolved_version != first.resolved_version:
                warnings.append(f"{e.name}: {first.source_file} locks {first.resolved_version} but "
                                f"{e.source_file} locks {e.resolved_version}; using {first.resolved_version}")
        else:
            locked[e.name] = e

    # Who requires whom: lockfile dependency lists, plus pip-compile "# via" annotations.
    parents: dict[str, set[str]] = {}
    for _, e in entries:
        for child in e.requires:
            parents.setdefault(child, set()).add(e.name)
        if e.via:
            parents.setdefault(e.name, set()).update(v for v in e.via if v != e.name)

    deps: list[Dependency] = []
    for name in sorted(declared.keys() | locked.keys()):
        lk = locked.get(name)
        if name in declared:
            decl = [e for _, e in declared[name]]
            best = next((e for e in decl if e.resolved_version), decl[0])
            scopes = {e.scope for e in decl}
            scope = "main" if "main" in scopes else ("dev" if "dev" in scopes else "unknown")
            resolved, reason = best.resolved_version, best.unresolved_reason
            con = constraints.get(name)
            from_url = (best.unresolved_reason or "").startswith(("installed", "editable"))
            if not resolved and con and con.resolved_version and not from_url:
                resolved, reason = con.resolved_version, None
            if lk and lk.resolved_version:
                if resolved and resolved != lk.resolved_version:
                    warnings.append(f"{name}: {best.source_file} pins {resolved} but {lk.source_file} locks "
                                    f"{lk.resolved_version}; using the lockfile version")
                resolved, reason = lk.resolved_version, None
            deps.append(Dependency(
                name=name, version_spec=best.version_spec, resolved_version=resolved, unresolved_reason=reason,
                source_file=best.source_file, scope=scope,
                direct=not all(e.direct is False for e in decl),   # pip-compile "# via <pkg>" only: transitive
                extras=sorted({x for e in decl for x in e.extras}), marker=best.marker,
                required_by=sorted(parents.get(name, ()))))
        else:
            deps.append(Dependency(
                name=name, version_spec=lk.version_spec, resolved_version=lk.resolved_version,
                unresolved_reason=lk.unresolved_reason, source_file=lk.source_file, direct=bool(lk.direct),
                scope=lk.scope, marker=lk.marker, required_by=sorted(parents.get(name, ()))))
    return deps


if __name__ == "__main__":  # quick manual check: python -m depscan.agents.repo_mapper <url-or-path>
    from depscan.config import load_config

    result = RepoMapperAgent(load_config().workspace).run(RepoMapperInput(url=sys.argv[1]))
    print(result.model_dump_json(indent=2))
