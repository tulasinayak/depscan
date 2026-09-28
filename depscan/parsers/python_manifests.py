"""Parsers for Python manifests: requirements*.txt, pyproject.toml, Pipfile, poetry.lock, Pipfile.lock, uv.lock."""

import json
import os
import posixpath
import re
import tomllib
from pathlib import Path, PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement

from depscan.parsers.base import ManifestParser, ParsedEntry, ParseOutput, Scope
from depscan.safety import MAX_MANIFEST_BYTES, inside


def normalize_name(name: str) -> str:
    """PEP 503 normalisation: 'PyYAML' -> 'pyyaml', 'Foo_Bar.baz' -> 'foo-bar-baz'."""
    return re.sub(r"[-_.]+", "-", name).lower()


def exact_version(spec: str | None) -> str | None:
    """'==3.13' -> '3.13'. Anything that is not a single exact pin -> None (never guessed)."""
    if not spec:
        return None
    m = re.fullmatch(r"\s*={2,3}\s*([A-Za-z0-9.+!_-]+)\s*", spec)
    return m.group(1) if m and "*" not in m.group(1) else None


def unpinned_reason(spec: str | None) -> str | None:
    if exact_version(spec):
        return None
    return f"version spec '{spec}' is not an exact pin" if spec else "no version specified"


def requirement_entry(raw: str, rel: str, scope: Scope, out: ParseOutput, kind: str = "declared") -> None:
    """PEP 508 string -> ParsedEntry (keeps extras and the environment marker)."""
    try:
        req = Requirement(raw)
    except InvalidRequirement as e:
        out.warnings.append(f"{rel}: cannot parse {raw!r}: {e}")
        return
    spec = str(req.specifier) or None
    reason = f"installed from URL {req.url}" if req.url else unpinned_reason(spec)
    out.entries.append(ParsedEntry(
        name=normalize_name(req.name), source_file=rel, kind=kind, scope=scope,
        version_spec=spec, resolved_version=None if req.url else exact_version(spec), unresolved_reason=reason,
        extras=sorted(req.extras), marker=str(req.marker) if req.marker else None))


def name_from_url(target: str) -> str | None:
    """Best-effort package name for URL / VCS / path requirements: '#egg=name', else the last path segment."""
    egg = re.search(r"[#&]egg=([A-Za-z0-9._-]+)", target)
    if egg:
        return egg.group(1)
    tail = re.sub(r"[#?].*$", "", target).rstrip("/").split("/")[-1]
    tail = re.sub(r"\.git$", "", tail)
    dist = re.match(r"^([A-Za-z0-9_.]+?)-\d", tail)  # foo_bar-1.0.tar.gz / foo_bar-1.0-py3-none-any.whl
    return dist.group(1) if dist else (tail or None)


# ---------------------------------------------------------------- requirements*.txt

def via_names(text: str) -> list[str]:
    """Package names from a pip-compile annotation ('via flask, requests'); skips '-r file' and '(pyproject.toml)'."""
    names = []
    for tok in re.split(r"[,\s]+", text.strip()):
        if tok and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", tok) and not re.search(r"\.(in|txt|toml|cfg)$", tok):
            names.append(normalize_name(tok))
    return names


_VIA_INPUT = re.compile(r"(^|\s)-[rc]\b|\.(in|txt)\b|\(pyproject\.toml\)|\(setup\.(cfg|py)\)")


def note_via(entry: ParsedEntry, text: str) -> None:
    """Record a pip-compile "# via" annotation. Only packages listed via an input file (-r requirements.in,
    (pyproject.toml), ...) were asked for by the project; packages listed only via other packages are transitive."""
    entry.via += via_names(text)
    if _VIA_INPUT.search(text):
        entry.direct = True
    elif entry.direct is None and via_names(text):
        entry.direct = False


DEV_FILE = re.compile(r"(^|[-_./])(dev|develop|development|test|tests|testing)([-_.]|$)", re.I)


def requirements_scope(rel_path: str) -> Scope:
    """requirements-dev*.txt, requirements-test*.txt, dev-requirements.txt, requirements/test.txt -> dev."""
    p = PurePosixPath(rel_path)
    name = f"{p.parent.name}/{p.stem}" if p.parent.name == "requirements" else p.stem
    return "dev" if DEV_FILE.search(name.replace("requirements", "")) else "main"


class RequirementsTxtParser(ManifestParser):
    priority = 20

    def matches(self, rel_path: str) -> bool:
        p = PurePosixPath(rel_path)
        return p.suffix == ".txt" and ("requirements" in p.name.lower() or p.parent.name == "requirements")

    def parse(self, path: Path, rel_path: str) -> ParseOutput:
        out = ParseOutput()
        self.root = Path(os.path.abspath(path))
        for _ in PurePosixPath(rel_path).parts:           # the repository root: rel_path is relative to it
            self.root = self.root.parent
        self._parse_file(path, rel_path, out, kind="declared", seen=set())
        return out

    def _parse_file(self, path: Path, rel: str, out: ParseOutput, kind: str, seen: set[Path]) -> None:
        path = path.resolve()
        if path in seen:                                  # -r cycles (a includes b includes a) end here
            return
        seen.add(path)
        scope = requirements_scope(rel)
        text = path.read_text(encoding="utf-8-sig", errors="replace").replace("\\\n", " ")
        last: ParsedEntry | None = None    # the most recent requirement, for pip-compile "# via" comments
        in_via = False
        for raw in text.splitlines():
            comment = re.search(r"(?:^|\s)#\s*(.*)$", raw)   # " # comment" (a URL's #egg= has no space before it)
            line = raw[:comment.start()].strip() if comment else raw.strip()
            note = comment.group(1).strip() if comment else ""
            if not line:  # comment-only line: maybe a multi-line "# via" block
                if last is not None and re.match(r"^via\b", note):
                    in_via = True
                    note_via(last, note[3:])
                elif last is not None and in_via and note:
                    note_via(last, note)
                else:
                    in_via = False
                continue
            in_via = False
            last = None
            before = len(out.entries)
            opt = re.match(r"^(-r|--requirement|-c|--constraint)[=\s]+(\S+)", line)
            if opt:  # followed relative to the including file
                target_rel = posixpath.normpath(str(PurePosixPath(rel).parent / opt.group(2)))
                target = path.parent / opt.group(2)
                if not inside(self.root, target):          # ../../etc/passwd, absolute paths, links
                    out.warnings.append(f"{rel}: referenced file {opt.group(2)} is outside the repository or a "
                                        "link; not read")
                    continue
                if not target.exists():
                    out.warnings.append(f"{rel}: referenced file {opt.group(2)} not found")
                    continue
                if target.stat().st_size > MAX_MANIFEST_BYTES:
                    out.warnings.append(f"{rel}: referenced file {opt.group(2)} is over the size limit; not read")
                    continue
                is_constraint = opt.group(1) in ("-c", "--constraint")
                self._parse_file(target, target_rel, out, "constraint" if is_constraint else kind, seen)
                continue
            editable = re.match(r"^(-e|--editable)[=\s]+(\S+)", line)
            if editable:
                self._url_entry(editable.group(2), rel, scope, kind, out, "editable install from")
                continue
            if line.startswith("-"):
                continue  # other pip options: -i, --index-url, --find-links, ...
            line = re.sub(r"\s--hash[=\s]\S+", "", line).strip()
            if re.match(r"^(git\+|hg\+|svn\+|bzr\+|https?://|file:)", line):
                self._url_entry(line, rel, scope, kind, out, "installed from URL")
                continue
            requirement_entry(line, rel, scope, out, kind)
            last = out.entries[-1] if len(out.entries) > before else None
            if last is not None and re.match(r"^via\b", note):
                note_via(last, note[3:])

    @staticmethod
    def _url_entry(target: str, rel: str, scope: Scope, kind: str, out: ParseOutput, what: str) -> None:
        name = name_from_url(target)
        if not name:
            out.warnings.append(f"{rel}: cannot tell the package name of {target!r}; skipped")
            return
        out.entries.append(ParsedEntry(name=normalize_name(name), source_file=rel, kind=kind, scope=scope,
                                       unresolved_reason=f"{what} {target}; version cannot be resolved"))


# ---------------------------------------------------------------- pyproject.toml

class PyprojectParser(ManifestParser):
    priority = 10

    def matches(self, rel_path: str) -> bool:
        return PurePosixPath(rel_path).name == "pyproject.toml"

    def parse(self, path: Path, rel_path: str) -> ParseOutput:
        out = ParseOutput()
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
        except tomllib.TOMLDecodeError as e:
            out.warnings.append(f"{rel_path}: invalid TOML: {e}")
            return out
        project = data.get("project", {})
        if "dependencies" in project.get("dynamic", []):
            out.warnings.append(f"{rel_path}: dependencies are dynamic (computed at build time); "
                                "they are not read because that would mean running the project's build")
        for r in project.get("dependencies", []):
            requirement_entry(r, rel_path, "main", out)
        for reqs in project.get("optional-dependencies", {}).values():
            for r in reqs:
                requirement_entry(r, rel_path, "dev", out)
        for group in data.get("dependency-groups", {}).values():  # PEP 735
            for r in group:
                if isinstance(r, str):  # {include-group = ...} entries are covered by the included group itself
                    requirement_entry(r, rel_path, "dev", out)

        poetry = data.get("tool", {}).get("poetry", {})
        tables: list[tuple[dict, Scope]] = [(poetry.get("dependencies", {}), "main"),
                                            (poetry.get("dev-dependencies", {}), "dev")]
        tables += [(g.get("dependencies", {}), "main" if name == "main" else "dev")
                   for name, g in poetry.get("group", {}).items()]
        for table, scope in tables:
            for name, spec in table.items():
                if name.lower() != "python":
                    self._poetry_entry(name, spec, scope, rel_path, out)
        return out

    @staticmethod
    def _poetry_entry(name: str, spec, scope: Scope, rel: str, out: ParseOutput) -> None:
        info = spec if isinstance(spec, dict) else {"version": spec}
        version = info.get("version") if isinstance(info.get("version"), str) else None
        source = next((f"{k} {info[k]}" for k in ("git", "path", "url") if k in info), None)
        # In Poetry a bare version ("1.2.3") is an exact pin; "^1.2" / "~1.2" / "*" are ranges.
        resolved = None if source else (version if version and re.fullmatch(r"\d[\w.+!-]*", version)
                                        else exact_version(version))
        if source:
            reason = f"installed from {source}; version cannot be resolved"
        elif resolved:
            reason = None
        else:
            reason = f"version spec '{version}' is not an exact pin" if version else "no version specified"
        out.entries.append(ParsedEntry(
            name=normalize_name(name), source_file=rel, kind="declared", scope=scope, version_spec=version,
            resolved_version=resolved, unresolved_reason=reason, extras=sorted(info.get("extras", [])),
            marker=info.get("markers")))


# ---------------------------------------------------------------- Pipfile (declares which Pipfile.lock entries are direct)

class PipfileParser(ManifestParser):
    priority = 30

    def matches(self, rel_path: str) -> bool:
        return PurePosixPath(rel_path).name == "Pipfile"

    def parse(self, path: Path, rel_path: str) -> ParseOutput:
        out = ParseOutput()
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
        except tomllib.TOMLDecodeError as e:
            out.warnings.append(f"{rel_path}: invalid TOML: {e}")
            return out
        for section, scope in (("packages", "main"), ("dev-packages", "dev")):
            for name, spec in data.get(section, {}).items():
                info = spec if isinstance(spec, dict) else {"version": spec}
                version = info.get("version")
                version = None if version in (None, "*") else version
                source = next((f"{k} {info[k]}" for k in ("git", "path", "file") if k in info), None)
                reason = f"installed from {source}; version cannot be resolved" if source else unpinned_reason(version)
                out.entries.append(ParsedEntry(
                    name=normalize_name(name), source_file=rel_path, kind="declared", scope=scope,
                    version_spec=version, resolved_version=None if source else exact_version(version),
                    unresolved_reason=reason, extras=sorted(info.get("extras", [])), marker=info.get("markers")))
        return out


# ---------------------------------------------------------------- lockfiles

def _toml(path: Path, rel: str, out: ParseOutput) -> dict | None:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except tomllib.TOMLDecodeError as e:
        out.warnings.append(f"{rel}: invalid TOML: {e}")
        return None


class PoetryLockParser(ManifestParser):
    def matches(self, rel_path: str) -> bool:
        return PurePosixPath(rel_path).name == "poetry.lock"

    def parse(self, path: Path, rel_path: str) -> ParseOutput:
        out = ParseOutput()
        data = _toml(path, rel_path, out) or {}
        for pkg in data.get("package", []):
            if "name" not in pkg or "version" not in pkg:
                continue
            # Poetry 1.x: category = "main" | "dev"; Poetry 2.x: groups = ["main", ...]; older: neither.
            groups = pkg.get("groups") or ([pkg["category"]] if "category" in pkg else [])
            scope = "main" if "main" in groups else ("dev" if groups else "unknown")
            # git / directory / file / url sources: the locked version is that source's own version number,
            # not a PyPI release, so PyPI advisories for a same-named package must not be matched against it.
            source = pkg.get("source", {})
            foreign = source.get("type") in ("git", "directory", "file", "url")
            out.entries.append(ParsedEntry(name=normalize_name(pkg["name"]), source_file=rel_path, kind="locked",
                                           scope=scope, version_spec=f"=={pkg['version']}",
                                           resolved_version=None if foreign else pkg["version"],
                                           unresolved_reason=f"locked from {source['type']} source "
                                                             f"{source.get('url', '?')}; not a PyPI release"
                                           if foreign else None,
                                           requires=[normalize_name(n) for n in pkg.get("dependencies", {})]))
        return out


class PipfileLockParser(ManifestParser):
    def matches(self, rel_path: str) -> bool:
        return PurePosixPath(rel_path).name == "Pipfile.lock"

    def parse(self, path: Path, rel_path: str) -> ParseOutput:
        out = ParseOutput()
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as e:
            out.warnings.append(f"{rel_path}: invalid JSON: {e}")
            return out
        for section, scope in (("default", "main"), ("develop", "dev")):
            for name, info in data.get(section, {}).items():
                version = exact_version(info.get("version"))
                source = next((f"{k} {info[k]}" for k in ("git", "path", "file") if k in info), None)
                reason = None if version else (f"locked from {source}; version cannot be resolved" if source
                                               else "lockfile entry has no exact version")
                out.entries.append(ParsedEntry(name=normalize_name(name), source_file=rel_path, kind="locked",
                                               scope=scope, version_spec=info.get("version"),
                                               resolved_version=version, unresolved_reason=reason,
                                               marker=info.get("markers")))
        return out


class UvLockParser(ManifestParser):
    def matches(self, rel_path: str) -> bool:
        return PurePosixPath(rel_path).name == "uv.lock"

    def parse(self, path: Path, rel_path: str) -> ParseOutput:
        out = ParseOutput()
        data = _toml(path, rel_path, out) or {}
        packages = data.get("package", [])
        # The project itself (and workspace members) have an editable/virtual/directory source.
        roots = [p for p in packages if set(p.get("source", {})) & {"editable", "virtual", "directory"}]
        root_names = {normalize_name(p["name"]) for p in roots}
        main: set[str] = set()
        dev: set[str] = set()
        for root in roots:
            main |= {normalize_name(d["name"]) for d in root.get("dependencies", []) if "name" in d}
            for group in (root.get("optional-dependencies", {}) | root.get("dev-dependencies", {})).values():
                dev |= {normalize_name(d["name"]) for d in group if "name" in d}
        for pkg in packages:
            name = normalize_name(pkg.get("name", ""))
            if not name or name in root_names:
                continue
            version = pkg.get("version")
            scope = "main" if name in main else ("dev" if name in dev else "unknown")
            foreign = next((f"{k} {v}" for k, v in pkg.get("source", {}).items() if k in ("git", "url", "path")), None)
            out.entries.append(ParsedEntry(
                name=name, source_file=rel_path, kind="locked", scope=scope,
                version_spec=f"=={version}" if version else None, resolved_version=None if foreign else version,
                unresolved_reason=(f"locked from {foreign}; not a PyPI release" if foreign else
                                   None if version else "lockfile entry has no version"),
                direct=(name in main or name in dev) if roots else None,
                requires=[normalize_name(d["name"]) for d in pkg.get("dependencies", []) if "name" in d]))
        return out


PYTHON_PARSERS = [PyprojectParser(), RequirementsTxtParser(), PipfileParser(),
                  PoetryLockParser(), PipfileLockParser(), UvLockParser()]
