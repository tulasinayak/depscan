"""Ground trigger specs in the package's own code (PyPI metadata, a public-API index, validation, parent triggers).

Everything here reads package archives downloaded from PyPI. Members are read in memory straight from the zip or tar
file: nothing is extracted to disk, and no code from a package (setup.py or anything else) is ever executed.
Downloads are verified against PyPI's sha256, capped per package, and cached (release JSON and top-level names in
the SQLite response cache, archives in cache/packages/, indexes in cache/api_index/<package>-<version>.json).

  1. import names:  top_level.txt (or RECORD top-level dirs) of the release's wheel
  2. API index:     modules, public classes (with methods), public functions, __all__ and re-exports, with the line
                    span and the outgoing references of every function (for items 3 and 5)
  3. retrieval:     index entries that match words of the advisory and the fix diff, plus the functions changed by
                    the fix, for the spec prompt
  4. validation:    every spec symbol must exist in the index (after resolving re-exports, casing and the
                    distribution name); unknown ones are dropped and recorded in spec.validation_issues
  5. parent triggers from code: which public APIs of a parent package lead to the child's trigger symbols
"""

import ast
import hashlib
import io
import json
import re
import tarfile
import warnings
import zipfile
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

import httpx

from depscan import __version__
from depscan.cache import ResponseCache
from depscan.models import ParentTrigger, TriggerSpec, Vulnerability
from depscan.parsers.python_manifests import normalize_name

PYPI = "https://pypi.org/pypi"
MAX_PACKAGE_BYTES = 50 * 1024 * 1024          # one archive per package, never more
MAX_FILE_BYTES = 5 * 1024 * 1024              # a single member larger than this is skipped
MAX_UNCOMPRESSED = 500 * 1024 * 1024          # declared sizes walked per archive: stops zip/tar bombs
MAX_MEMBERS = 50_000                          # members looked at per archive
MAX_RETRIEVED = 60
INDEX_VERSION = 4   # 2: definitions in if/try/with blocks; 3: base classes, class attributes; 4: Base[T]
STOP = set("the and for with that this from when into could can not are was were has have its via use used using "
           "may allow allows attacker attackers remote user users data file files code before after version versions "
           "python package vulnerability vulnerable issue fix fixed which will would been being also only other "
           "than then there their these those such some more most very does did doing any all none true false self "
           "none return import def class".split())


# ---------------------------------------------------------------- safe archive reading

def safe_member(name: str) -> str | None:
    """A member path as a relative POSIX path, or None when it is absolute or leaves the archive (..)."""
    name = name.replace("\\", "/")
    if not name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None
    parts = [p for p in PurePosixPath(name).parts if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def read_members(path: Path, want) -> Iterator[tuple[str, bytes]]:
    """(relative path, bytes) of the regular files `want(path)` accepts; unsafe or oversized members are skipped.
    Links (tar symlinks/hardlinks, zip entries with a symlink mode) are never followed."""
    walked = 0
    if path.suffix == ".whl" or path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            for n, info in enumerate(zf.infolist()):
                walked += info.file_size
                if n >= MAX_MEMBERS or walked > MAX_UNCOMPRESSED:
                    return                                 # a bomb or an absurd archive: stop, keep what we have
                rel = safe_member(info.filename)
                is_link = (info.external_attr >> 16) & 0o170000 == 0o120000
                if rel is None or info.is_dir() or is_link or info.file_size > MAX_FILE_BYTES or not want(rel):
                    continue
                yield rel, zf.read(info)
        return
    with tarfile.open(path, "r:*") as tf:
        for n, member in enumerate(tf):
            walked += member.size                          # skipping a member still decompresses it
            if n >= MAX_MEMBERS or walked > MAX_UNCOMPRESSED:
                return
            rel = safe_member(member.name)
            if rel is None or not member.isreg() or member.size > MAX_FILE_BYTES or not want(rel):
                continue
            fh = tf.extractfile(member)
            if fh is not None:
                yield rel, fh.read()


def safe_filename(name: str) -> str | None:
    """A release file name usable as a plain file name in the cache (no path parts, no odd characters)."""
    if not name or name.startswith(".") or not re.fullmatch(r"[A-Za-z0-9._+-]+", name):   # no /, \ or ..-only
        return None
    return name


def member_names(path: Path) -> list[str]:
    """Safe member paths of an archive, without reading their contents."""
    if path.suffix in (".whl", ".zip"):
        with zipfile.ZipFile(path) as zf:
            return [r for i in zf.infolist() if (r := safe_member(i.filename))]
    with tarfile.open(path, "r:*") as tf:
        return [r for m in tf if m.isreg() and (r := safe_member(m.name))]


# ---------------------------------------------------------------- the API index

@dataclass
class ApiIndex:
    package: str
    version: str
    archive: str = ""
    top_level: list[str] = field(default_factory=list)
    symbols: dict[str, str] = field(default_factory=dict)        # qualified name -> module|class|function|method
    reexports: dict[str, str] = field(default_factory=dict)      # public alias -> where it is defined
    files: dict[str, str] = field(default_factory=dict)          # module -> path inside the package
    spans: dict[str, list] = field(default_factory=dict)         # module -> [[first, last, qualified function]]
    refs: dict[str, list[str]] = field(default_factory=dict)     # function -> dotted names it references
    calls: dict[str, list[str]] = field(default_factory=dict)    # function -> simple names it calls
    opaque: list[str] = field(default_factory=list)              # modules whose names are (partly) made at runtime
    native: list[str] = field(default_factory=list)              # compiled extension files in the archive
    bases: dict[str, list[str]] = field(default_factory=dict)    # class -> its base classes (dotted, as imported)
    version_: int = INDEX_VERSION

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, text: str) -> "ApiIndex":
        return cls(**json.loads(text))

    # -------------------------------------------------------- lookups

    def home_module(self, symbol: str) -> str | None:
        """The longest indexed module the symbol lives under, or None."""
        parts = symbol.split(".")
        for n in range(len(parts), 0, -1):
            if ".".join(parts[:n]) in self.files:
                return ".".join(parts[:n])
        return None

    def verifiable(self, symbol: str) -> tuple[bool, str]:
        """Whether "not in the index" really means "does not exist" for this symbol."""
        home = self.home_module(symbol)
        if home is None:
            return False, f"no Python source for {symbol.split('.')[0]} in the package"
        if home in self.opaque:
            return False, f"{home} creates names at runtime or loads a compiled extension"
        return True, ""

    def canonical(self, symbol: str, depth: int = 0) -> str | None:
        """Where a (possibly re-exported) name is defined, or None if the index doesn't know it."""
        if symbol in self.symbols:
            return symbol
        if depth > 8:
            return None
        if symbol in self.reexports:
            return self.canonical(self.reexports[symbol], depth + 1)
        head, _, tail = symbol.rpartition(".")
        if head:
            base = self.canonical(head, depth + 1)
            if base and base != head and f"{base}.{tail}" in self.symbols:
                return f"{base}.{tail}"
            if base and self.symbols.get(base) == "class":
                return self.inherited(base, tail, depth)
        return None

    def inherited(self, cls: str, member: str, depth: int = 0) -> str | None:
        """A member a class gets from one of its base classes in this package (MedianFilter.filter is
        RankFilter.filter), nearest base first."""
        seen, todo = {cls}, list(self.bases.get(cls, []))
        while todo and len(seen) < 64:
            b = self.canonical(todo.pop(0), depth + 1)
            if not b or b in seen:
                continue
            seen.add(b)
            if f"{b}.{member}" in self.symbols:
                return f"{b}.{member}"
            todo.extend(self.bases.get(b, []))
        return None

    def aliases(self, target: str) -> list[str]:
        """Public names that lead to a defined symbol (requests.get for requests.api.get), shortest first."""
        out = [a for a in self.reexports if self.canonical(a) == target]
        return sorted(set(out), key=lambda a: (a.count("."), len(a)))

    def public_name(self, target: str) -> str:
        """The shortest public name: requests.get for requests.api.get, and quuxarc.QuuxFile.extractall for a method
        of a re-exported class."""
        aliases = self.aliases(target)
        if aliases:
            return aliases[0]
        head, _, tail = target.rpartition(".")
        if head and self.symbols.get(head) == "class":
            return f"{self.public_name(head)}.{tail}"
        return target

    def resolve(self, symbol: str, dist_names: set[str] = frozenset()) -> tuple[str | None, str]:
        """(resolved defining symbol or None, how). Tries: as written, the import name instead of the distribution
        name, other casing, then a unique match by its last one or two name parts."""
        symbol = re.sub(r"\(.*\)$", "", symbol.strip()).strip(".")
        hit = self.canonical(symbol)
        if hit:
            return hit, "exact"
        parts = symbol.split(".")
        # Only this package's own names are rewritten: its import names (any casing) or its distribution name.
        # A symbol rooted in another package (requests.PoolManager in a urllib3 spec) is never moved onto this one.
        own = parts[0].lower() in {t.lower() for t in self.top_level} or parts[0].lower() in dist_names
        if not own:
            return None, "belongs to another package"
        if parts[0].lower() in dist_names and parts[0] not in self.top_level:
            for top in self.top_level:
                for cand in (".".join([top, *parts[1:]]), ".".join([top, *parts])):
                    hit = self.canonical(cand)
                    if hit:
                        return hit, f"import name {top}"
        lower = {s.lower(): s for s in list(self.symbols) + list(self.reexports)}
        hit = self.canonical(lower[symbol.lower()]) if symbol.lower() in lower else None
        if hit and self.symbols.get(hit) not in ("variable", "attribute"):   # PIL.Image.save is not PIL.Image.SAVE
            return hit, "casing"
        for n in (2, 1):
            if len(parts) < n:
                continue
            tail = ".".join(parts[-n:])
            cands = {self.canonical(s) for s in list(self.symbols) + list(self.reexports)
                     if (s == tail or s.endswith("." + tail)) and self.canonical(s)}
            if len(cands) == 1:
                return cands.pop(), f"unique name {tail}"
        return None, "not found"


def module_name(rel: str, top_level: set[str]) -> str | None:
    """'PIL/Image.py' -> 'PIL.Image'; 'yaml/__init__.py' -> 'yaml'. Only modules under a top-level name."""
    p = PurePosixPath(rel)
    if p.suffix not in (".py", ".pyi"):
        return None
    parts = list(p.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts or not all(x.isidentifier() for x in parts):
        return None
    if top_level and parts[0] not in top_level:
        return None
    if any(x in ("tests", "test", "testing") for x in parts[1:]):
        return None
    return ".".join(parts)


def _dotted(node: ast.AST) -> list[str] | None:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return base + [node.attr] if base else None
    return None


def _resolve_from(mod: str, is_pkg: bool, level: int, target: str | None) -> str:
    if not level:
        return target or ""
    base = mod.split(".") if is_pkg else mod.split(".")[:-1]
    base = base[:len(base) - (level - 1)] if level > 1 else base
    return ".".join([*base, *([target] if target else [])])


def _flat(body: list[ast.stmt]):
    """Statements of a module or class body, including those inside if/try/with blocks there
    (``if sys.version_info >= ...: def where(): ...``, ``try: import x except ImportError: ...``)."""
    for node in body:
        if isinstance(node, ast.If):
            yield from _flat(node.body)
            yield from _flat(node.orelse)
        elif isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            yield from _flat(node.body)
            for h in node.handlers:
                yield from _flat(h.body)
            yield from _flat(node.orelse)
            yield from _flat(node.finalbody)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            yield from _flat(node.body)
        else:
            yield node


def index_sources(package: str, version: str, archive: str, top_level: list[str],
                  sources: dict[str, tuple[str, bytes]]) -> ApiIndex:
    """Build the index from {module: (path, source)}. Parsing only; nothing is executed."""
    idx = ApiIndex(package=package, version=version, archive=archive, top_level=sorted(top_level))
    stars: list[tuple[str, str]] = []
    all_lists: dict[str, list[str]] = {}
    for mod, (rel, raw) in sorted(sources.items()):
        try:
            with warnings.catch_warnings():              # old packages' invalid escapes etc.: not our concern
                warnings.simplefilter("ignore")
                tree = ast.parse(raw.decode("utf-8", errors="replace"))
        except (SyntaxError, ValueError):
            continue
        is_pkg = rel.endswith(("__init__.py", "__init__.pyi"))
        idx.files.setdefault(mod, rel)
        text = raw.decode("utf-8", errors="replace")
        if re.search(r"^def __getattr__\(|importlib|globals\(\)\s*\[|globals\(\)\.update|sys\.modules\[", text, re.M):
            idx.opaque.append(mod)
        idx.symbols[mod] = "module"
        imports: dict[str, str] = {}
        spans = idx.spans.setdefault(mod, [])
        top = list(_flat(tree.body))
        for node in top:
            if isinstance(node, ast.Import):
                for a in node.names:
                    imports[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom):
                src = _resolve_from(mod, is_pkg, node.level, node.module)
                for a in node.names:
                    if a.name == "*":
                        stars.append((mod, src))
                        continue
                    imports[a.asname or a.name] = f"{src}.{a.name}"
                    if not (a.asname or a.name).startswith("_"):
                        idx.reexports[f"{mod}.{a.asname or a.name}"] = f"{src}.{a.name}"
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Name) and t.id == "__all__" and isinstance(node.value, (ast.List, ast.Tuple)):
                        all_lists[mod] = [e.value for e in node.value.elts if isinstance(e, ast.Constant)
                                          and isinstance(e.value, str)]
                    elif isinstance(t, ast.Name) and not t.id.startswith("_"):
                        d = _dotted(node.value) if node.value is not None else None
                        if d and d[0] in imports:            # Alias = other.Name
                            idx.reexports[f"{mod}.{t.id}"] = ".".join([imports[d[0]], *d[1:]])
                        else:
                            idx.symbols.setdefault(f"{mod}.{t.id}", "variable")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)) and node not in top:
                for a in node.names:                      # imports inside functions still resolve names
                    if isinstance(node, ast.Import):
                        imports.setdefault(a.asname or a.name.split(".")[0], a.name.split(".")[0] if not a.asname
                                           else a.name)
                    elif a.name != "*":
                        src = _resolve_from(mod, is_pkg, node.level, node.module)
                        imports.setdefault(a.asname or a.name, f"{src}.{a.name}")

        def visit(body, prefix: str, cls: str | None) -> None:
            for node in _flat(body):
                if isinstance(node, ast.ClassDef):
                    q = f"{prefix}.{node.name}"
                    idx.symbols[q] = "class"
                    bases = []
                    for b in node.bases:
                        d = _dotted(b.value if isinstance(b, ast.Subscript) else b)   # Base[T] -> Base
                        if d and d[0] in imports:
                            bases.append(".".join([imports[d[0]], *d[1:]]))
                        elif d and d[0] not in ("object", "Generic", "Protocol"):
                            bases.append(".".join([mod, *d]))     # a class of the same module
                    if bases:
                        idx.bases[q] = bases
                    visit(node.body, q, q)
                elif cls and isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for t in targets:                           # __truediv__ = joinpath; timeout: float = 5
                        if isinstance(t, ast.Name) and (not t.id.startswith("_") or t.id.endswith("__")):
                            idx.symbols.setdefault(f"{prefix}.{t.id}", "attribute")
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    q = f"{prefix}.{node.name}"
                    idx.symbols[q] = "method" if cls else "function"
                    if cls:                                     # self.scope = scope in a method: an attribute
                        for sub in ast.walk(node):
                            for t in (sub.targets if isinstance(sub, ast.Assign) else
                                      [sub.target] if isinstance(sub, ast.AnnAssign) else []):
                                if (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                                        and t.value.id == "self" and not t.attr.startswith("_")):
                                    idx.symbols.setdefault(f"{cls}.{t.attr}", "attribute")
                    spans.append([node.lineno, getattr(node, "end_lineno", node.lineno), q])
                    refs, calls = set(), set()
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call):
                            f = sub.func
                            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
                            if name:
                                calls.add(name)
                        if isinstance(sub, (ast.Attribute, ast.Name)):
                            d = _dotted(sub)
                            if d and d[0] in imports:
                                refs.add(".".join([imports[d[0]], *d[1:]]))
                    idx.refs[q], idx.calls[q] = sorted(refs), sorted(calls)
        visit(tree.body, mod, None)

    roots = {m.split(".")[0] for m in idx.files}
    for alias, target in list(idx.reexports.items()):      # a name from a compiled module of the same package
        tmod = target.rsplit(".", 1)[0]
        if tmod.split(".")[0] in roots and tmod not in idx.files and target not in idx.symbols:
            idx.symbols[target] = "native"
            idx.opaque.append(alias.rsplit(".", 1)[0])      # that module's API partly lives in compiled code
    for mod, src in stars:
        if src not in idx.files:                            # star import from a compiled or foreign module
            idx.opaque.append(mod)
    for mod, src in stars:                                 # from .loader import *  -> every public name of it
        names = all_lists.get(src) or [s.rsplit(".", 1)[1] for s in idx.symbols
                                       if s.rsplit(".", 1)[0] == src and not s.rsplit(".", 1)[1].startswith("_")
                                       and idx.symbols[s] != "module"]
        for n in names:
            idx.reexports.setdefault(f"{mod}.{n}", f"{src}.{n}")
    for mod, names in all_lists.items():
        for n in names:
            if f"{mod}.{n}" not in idx.symbols and f"{mod}.{n}" not in idx.reexports:
                idx.reexports[f"{mod}.{n}"] = f"{mod}.{n}"   # listed but defined dynamically: keep as known
                idx.symbols[f"{mod}.{n}"] = "variable"
    return idx


# ---------------------------------------------------------------- PyPI

class PackageSource:
    """Release files of one exact version from PyPI: import names and the API index. Cached; offline = cache only."""

    def __init__(self, cache_dir: Path, http_cache: ResponseCache | None = None, offline: bool = False,
                 transport: httpx.BaseTransport | None = None, base_url: str = PYPI):
        self.archives = Path(cache_dir) / "packages"
        self.indexes = Path(cache_dir) / "api_index"
        self.http_cache, self.offline, self.transport, self.base_url = http_cache, offline, transport, base_url
        self.log: list[str] = []
        self._mem: dict[str, ApiIndex | None] = {}

    def _client(self) -> httpx.Client:
        return httpx.Client(follow_redirects=True, timeout=60, transport=self.transport,
                            headers={"User-Agent": f"depscan/{__version__}"})

    def release(self, name: str, version: str) -> list[dict] | None:
        key = f"pypi:release:{normalize_name(name)}=={version}"
        hit = self.http_cache.get(key) if self.http_cache else None
        if hit:
            return hit[0]
        if self.offline:
            return None
        try:
            with self._client() as c:
                r = c.get(f"{self.base_url}/{normalize_name(name)}/{version}/json")
            if r.status_code != 200:
                self.log.append(f"PyPI {name} {version}: HTTP {r.status_code}")
                return None
            files = [{k: u.get(k) for k in ("filename", "url", "packagetype", "size", "python_version")}
                     | {"sha256": (u.get("digests") or {}).get("sha256")} for u in r.json().get("urls", [])]
        except (httpx.HTTPError, ValueError) as e:
            self.log.append(f"PyPI {name} {version}: {type(e).__name__}")
            return None
        if self.http_cache:
            self.http_cache.put(key, files)
        return files

    @staticmethod
    def candidates(files: list[dict]) -> list[dict]:
        """Pure-Python wheels first, then other wheels (smallest first), then the sdist; all within the size cap."""
        def rank(f: dict) -> tuple:
            fn = f["filename"]
            if f["packagetype"] == "bdist_wheel":
                pure = fn.endswith(("-none-any.whl",))
                return (0 if pure else 1, f.get("size") or 0)
            return (2, f.get("size") or 0)
        ok = [f for f in files if f.get("packagetype") in ("bdist_wheel", "sdist")
              and (f.get("size") or 0) <= MAX_PACKAGE_BYTES
              and f["filename"].endswith((".whl", ".tar.gz", ".zip", ".tgz", ".tar.bz2"))]
        return sorted(ok, key=rank)

    def archive(self, name: str, version: str) -> Path | None:
        files = self.release(name, version)
        if not files:
            return None
        for f in self.candidates(files):
            name = safe_filename(f.get("filename", ""))
            if name is None or not str(f.get("url", "")).startswith("https://"):
                self.log.append(f"skipped release file {f.get('filename')!r}: unsafe name or not https")
                continue
            path = self.archives / name
            if path.exists():
                return path
            if self.offline:
                continue
            got = self._download(f, path)
            if got:
                return got
        return None

    def _download(self, f: dict, path: Path) -> Path | None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".part")
        digest, total = hashlib.sha256(), 0
        try:
            with self._client() as c, c.stream("GET", f["url"]) as r:
                if r.status_code != 200:
                    self.log.append(f"download {f['filename']}: HTTP {r.status_code}")
                    return None
                with tmp.open("wb") as out:
                    for chunk in r.iter_bytes():
                        total += len(chunk)
                        if total > MAX_PACKAGE_BYTES:
                            self.log.append(f"download {f['filename']}: over {MAX_PACKAGE_BYTES // 2**20} MB, skipped")
                            out.close()
                            tmp.unlink(missing_ok=True)
                            return None
                        digest.update(chunk)
                        out.write(chunk)
        except httpx.HTTPError as e:
            self.log.append(f"download {f['filename']}: {type(e).__name__}")
            tmp.unlink(missing_ok=True)
            return None
        if f.get("sha256") and digest.hexdigest() != f["sha256"]:
            self.log.append(f"download {f['filename']}: sha256 mismatch, discarded")
            tmp.unlink(missing_ok=True)
            return None
        tmp.replace(path)
        return path

    # -------------------------------------------------------- item 1: import names

    def top_level(self, name: str, version: str) -> list[str] | None:
        key = f"pypi:toplevel:{normalize_name(name)}=={version}"
        hit = self.http_cache.get(key) if self.http_cache else None
        if hit:
            return hit[0] or None
        path = self.archive(name, version)
        if path is None:
            return None
        names = top_level_of(path)
        if self.http_cache:
            self.http_cache.put(key, names)
        return names or None

    # -------------------------------------------------------- item 2: API index

    def index(self, name: str, version: str | None) -> ApiIndex | None:
        if not version:
            return None
        key = f"{normalize_name(name)}-{version}"
        if key in self._mem:
            return self._mem[key]
        file = self.indexes / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', key)}.json"
        idx = None
        if file.exists():
            try:
                idx = ApiIndex.from_json(file.read_text(encoding="utf-8"))
                idx = idx if idx.version_ == INDEX_VERSION else None
            except (ValueError, TypeError):
                idx = None
        if idx is None:
            path = self.archive(name, version)
            if path is not None:
                idx = build_index(normalize_name(name), version, path)
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(idx.to_json(), encoding="utf-8")
        self._mem[key] = idx
        return idx


def top_level_of(path: Path) -> list[str]:
    """Top-level import names of a wheel (top_level.txt, else RECORD) or an sdist (egg-info, else package dirs)."""
    meta: dict[str, bytes] = dict(read_members(path, lambda r: r.endswith(("top_level.txt", "/RECORD"))))
    for rel, raw in meta.items():
        if rel.endswith("top_level.txt") and rel.count("/") <= 2:
            names = [n.strip() for n in raw.decode("utf-8", "replace").splitlines()]
            names = [n.replace("/", ".") for n in names if n and not n.startswith("_") and n.split("/")[0].isidentifier()]
            if names:
                return sorted(set(names))
    tops: set[str] = set()
    record = next((raw for rel, raw in meta.items() if rel.endswith(".dist-info/RECORD")), None)
    if record:
        for line in record.decode("utf-8", "replace").splitlines():
            first = line.split(",")[0]
            parts = first.split("/")
            if not parts[0] or parts[0].endswith((".dist-info", ".data")) or parts[0] == "..":
                continue
            top = parts[0][:-3] if parts[0].endswith(".py") else parts[0]
            if top.isidentifier() and not top.startswith("_") and (len(parts) > 1 or parts[0].endswith(".py")):
                tops.add(top)
        return sorted(tops)
    for rel, _ in read_members(path, lambda r: r.endswith("__init__.py")):
        parts = _strip_sdist(rel).split("/")
        if len(parts) == 2 and parts[0].isidentifier() and parts[0] not in ("tests", "test", "docs"):
            tops.add(parts[0])
    return sorted(tops)


def _strip_sdist(rel: str) -> str:
    """'pkg-1.0/src/pkg/x.py' -> 'pkg/x.py' (sdist root folder and a src/ or lib/ layout)."""
    parts = rel.split("/")
    if len(parts) > 1 and re.match(r"^[\w.+-]+-\d", parts[0]):
        parts = parts[1:]
    if len(parts) > 1 and parts[0] in ("src", "lib", "lib3", "python"):
        parts = parts[1:]
    return "/".join(parts)


def build_index(package: str, version: str, path: Path) -> ApiIndex:
    top = set(top_level_of(path))
    wheel = path.suffix == ".whl"
    sources: dict[str, tuple[str, bytes]] = {}
    for rel, raw in read_members(path, lambda r: r.endswith((".py", ".pyi"))):
        inner = rel if wheel else _strip_sdist(rel)
        mod = module_name(inner, {t.split(".")[0] for t in top})
        if mod and (mod not in sources or inner.endswith(".py")):   # .py wins over its .pyi stub
            sources[mod] = (inner, raw)
    idx = index_sources(package, version, path.name, sorted(top), sources)
    idx.native = sorted(r for r in member_names(path) if r.endswith((".so", ".pyd")))
    for rel in idx.native:                                 # a compiled module next to a package's __init__
        pkg = ".".join(PurePosixPath(rel if wheel else _strip_sdist(rel)).parent.parts)
        if pkg in idx.files:
            idx.opaque.append(pkg)
    idx.opaque = sorted(set(idx.opaque))
    return idx


# ---------------------------------------------------------------- item 3: retrieval for the spec prompt

def words(text: str) -> set[str]:
    return {w.lower() for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text or "") if w.lower() not in STOP}


def changed_functions(diff: str, idx: ApiIndex) -> list[str]:
    """Functions of the indexed version that the fix diff changes (hunk lines mapped onto function spans; the
    `@@ ... def name(` context as a fallback)."""
    out: list[str] = []
    for chunk in re.split(r"^diff --git ", diff or "", flags=re.M)[1:]:
        m = re.match(r"a/(\S+) b/(\S+)", chunk)
        path = m[1] if m else ""
        if not path.endswith(".py"):
            continue
        mod = next((mo for mo, rel in idx.files.items() if path == rel or path.endswith("/" + rel)), None)
        if mod is None:
            continue
        spans = idx.spans.get(mod, [])
        old = 0
        for line in chunk.split("\n"):
            h = re.match(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@(.*)", line)
            if h:
                old = int(h[1])
                ctx = re.search(r"def (\w+)\(", h[2])
                if ctx:
                    out += [q for a, b, q in spans if q.endswith("." + ctx[1])][:1]
                continue
            if not old or line.startswith(("+++", "---")):
                continue
            if line.startswith("-") or line.startswith("+"):
                hits = [(b - a, q) for a, b, q in spans if a <= old <= b]
                if hits:
                    out.append(min(hits)[1])              # the innermost function
                if line.startswith("-"):
                    old += 1
            else:
                old += 1
    return list(dict.fromkeys(out))


def retrieve(idx: ApiIndex, vuln: Vulnerability, diff: str, changed: list[str],
             limit: int = MAX_RETRIEVED) -> list[str]:
    """Index entries whose names or modules match words of the advisory and the fix diff, most relevant first."""
    keys = words(f"{vuln.summary}\n{vuln.details}\n{' '.join(vuln.affected_functions)}") | words(diff)
    diff_mods = {mo for mo, rel in idx.files.items() if rel and rel in (diff or "")}
    scored = []
    for sym, kind in idx.symbols.items():
        if kind in ("module", "variable", "attribute") or any(
                p.startswith("_") and p not in ("__init__", "__new__", "__call__") for p in sym.split(".")[1:]):
            continue
        parts = [p.lower() for p in sym.split(".")]
        score = 6 * (sym in changed) + 3 * any(sym.startswith(m + ".") for m in diff_mods)
        score += sum(2 for p in parts[1:-1] if p in keys) + (4 if parts[-1] in keys else 0)
        score += sum(1 for p in parts[-1].split("_") if len(p) > 2 and p in keys)
        if score:
            scored.append((-score, sym.count("."), sym))
    return [s for _, _, s in sorted(scored)[:limit]]


def api_excerpt(idx: ApiIndex, vuln: Vulnerability, diff: str) -> tuple[str, list[str]]:
    """The prompt section with the retrieved entries (public names first), and the changed functions."""
    changed = changed_functions(diff, idx)
    lines = []
    for sym in retrieve(idx, vuln, diff, changed):
        public = idx.public_name(sym)
        where = f"; defined as {sym}" if public != sym else ""
        lines.append(f"- {public} ({idx.symbols[sym]}{where})")
    text = ""
    if lines:
        text += (f"## Public API of {idx.package} {idx.version} (relevant excerpt; trigger_symbols and "
                 "wrapper_symbols must use names from the package's real API such as these)\n" + "\n".join(lines))
    if changed:
        text += "\n\n## Functions changed by the fix\n" + "\n".join(f"- {c}" for c in changed[:20])
    return text.strip(), changed


# ---------------------------------------------------------------- item 4: validation

def validate_spec(spec: TriggerSpec, idx: ApiIndex | None) -> TriggerSpec:
    """Resolve every symbol against the index; drop the unknown ones (recorded in validation_issues). Symbols whose
    top-level module has no Python source in the index (a native module) are kept and noted, never dropped."""
    if idx is None:
        return spec.model_copy(update={"validation_issues": [*spec.validation_issues,
                                                             "not validated: no API index for this version"]})
    dist = {normalize_name(spec.package), normalize_name(spec.package).replace("-", "_"), spec.package.lower()}
    issues: list[str] = list(spec.validation_issues)

    def as_import_name(s: str) -> str:
        """Pillow.Image.open -> PIL.Image.open (the distribution name written where the import name belongs)."""
        parts = s.split(".")
        if not idx.top_level or parts[0] in idx.top_level or parts[0].lower() not in dist:
            return s
        if len(parts) > 1 and parts[1] in idx.top_level:
            return ".".join(parts[1:])
        return ".".join([idx.top_level[0], *parts[1:]])

    def check(symbols: list[str], what: str) -> list[str]:
        kept = []
        for s in symbols:
            hit, how = idx.resolve(s, dist)
            if hit:
                public = idx.public_name(hit)
                kept.append(public)
                if public != s:
                    issues.append(f"{what} {s!r} -> {public!r} ({how})")
                continue
            if how == "belongs to another package":
                issues.append(f"{what} {s!r} dropped: it is not in {idx.package} (another package's name)")
                continue
            ok, why = idx.verifiable(as_import_name(s))
            if not ok:
                kept.append(s)
                issues.append(f"{what} {s!r} kept unverified: {why}")
            else:
                issues.append(f"{what} {s!r} dropped: not in the API of {idx.package} {idx.version}")
        return list(dict.fromkeys(kept))

    update: dict = {"trigger_symbols": check(spec.trigger_symbols, "trigger")}
    forms = []
    for f in spec.arg_forms:
        call = check([f.call], "arg_form call")
        if call:
            forms.append(f.model_copy(update={"call": call[0]}))
    update["arg_forms"] = forms
    if spec.native_feature:
        update["native_feature"] = spec.native_feature.model_copy(update={
            "wrapper_symbols": check(spec.native_feature.wrapper_symbols, "wrapper")})
    update["validation_issues"] = issues
    update["api_index"] = f"{idx.package}-{idx.version} ({idx.archive})"
    return spec.model_copy(update=update)


# ---------------------------------------------------------------- item 5: parent triggers from code

def parent_symbols(parent: ApiIndex, child_triggers: list[str], match, max_depth: int = 8,
                   limit: int = 40) -> list[str]:
    """Public APIs of the parent that lead (through its own calls, by name) to code referencing a child trigger.
    Name-based calls over-approximate, which only makes more parent APIs count (never fewer)."""
    start = {f for f, refs in parent.refs.items() if any(match(r, t) for r in refs for t in child_triggers)}
    callers: dict[str, set[str]] = {}
    for f, names in parent.calls.items():
        for n in names:
            callers.setdefault(n, set()).add(f)
    seen, frontier = set(start), list(start)
    for _ in range(max_depth):
        nxt = []
        for f in frontier:
            last = f.rsplit(".", 1)[1]
            name = f.rsplit(".", 2)[1] if last in ("__init__", "__new__", "__call__") else last
            for g in callers.get(name, ()):
                if g not in seen:
                    seen.add(g)
                    nxt.append(g)
        frontier = nxt
        if not frontier or len(seen) > 2000:
            break
    public: set[str] = set()
    for f in seen:
        parts = f.split(".")
        if parts[-1] in ("__init__", "__new__", "__call__"):
            parts = parts[:-1]
        if any(p.startswith("_") for p in parts[1:]):
            continue
        q = ".".join(parts)
        public.add(q)
        public.update(parent.aliases(q))
    return sorted(public, key=lambda s: (s.count("."), len(s), s))[:limit]


def code_parent_triggers(spec: TriggerSpec, parents: dict[str, ApiIndex | None], match) -> list[ParentTrigger]:
    """Parent triggers found in the parents' code. The LLM's own parent entries only contribute their condition."""
    words_of = {normalize_name(p.parent): p for p in spec.parent_triggers}
    out = []
    for parent, idx in parents.items():
        llm = words_of.get(normalize_name(parent))
        condition = llm.condition if llm else ""
        if idx is None or not spec.trigger_symbols:
            out.append(ParentTrigger(parent=parent, symbols=[], condition=condition, source="code",
                                     note="no API index" if idx is None else "no trigger symbols to look for"))
            continue
        syms = parent_symbols(idx, spec.trigger_symbols, match)
        out.append(ParentTrigger(parent=parent, symbols=syms, condition=condition, source="code",
                                 note=f"{len(syms)} public APIs of {parent} {idx.version} lead to the trigger symbols"
                                 if syms else f"no code in {parent} {idx.version} references the trigger symbols"))
    return out
