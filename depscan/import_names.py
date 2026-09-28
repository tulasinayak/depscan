"""Distribution name -> top-level import names (pillow -> PIL, pyyaml -> yaml).

Order: installed package metadata (top_level.txt, else RECORD) when the package happens to be
installed in depscan's own environment; then a built-in table; then a name heuristic. The target
repository's dependencies are never installed, so the table matters most.
"""

from functools import lru_cache
from importlib import metadata

from depscan.parsers import normalize_name

BUILTIN: dict[str, list[str]] = {
    "pillow": ["PIL"],
    "pyyaml": ["yaml"],
    "beautifulsoup4": ["bs4"],
    "scikit-learn": ["sklearn"],
    "scikit-image": ["skimage"],
    "python-dateutil": ["dateutil"],
    "opencv-python": ["cv2"],
    "opencv-python-headless": ["cv2"],
    "opencv-contrib-python": ["cv2"],
    "pyjwt": ["jwt"],
    "python-dotenv": ["dotenv"],
    "psycopg2-binary": ["psycopg2"],
    "psycopg-binary": ["psycopg"],
    "pycryptodome": ["Crypto"],
    "pycryptodomex": ["Cryptodome"],
    "pyopenssl": ["OpenSSL"],
    "attrs": ["attr", "attrs"],
    "protobuf": ["google.protobuf"],
    "typing-extensions": ["typing_extensions"],
    "setuptools": ["setuptools", "pkg_resources"],
    "dnspython": ["dns"],
    "pysocks": ["socks", "sockshandler"],
    "python-multipart": ["multipart", "python_multipart"],
    "msgpack-python": ["msgpack"],
    "mysqlclient": ["MySQLdb"],
    "pyzmq": ["zmq"],
    "pywin32": ["win32api", "win32con", "pywintypes"],
    "google-api-python-client": ["googleapiclient"],
    "gitpython": ["git"],
    "pygithub": ["github"],
    "python-jose": ["jose"],
    "python-magic": ["magic"],
    "ruamel-yaml": ["ruamel.yaml"],
    "websocket-client": ["websocket"],
    "pyserial": ["serial"],
    "markdown-it-py": ["markdown_it"],
    "email-validator": ["email_validator"],
    "charset-normalizer": ["charset_normalizer"],
    "pymupdf": ["fitz"],
    "python-docx": ["docx"],
    "python-pptx": ["pptx"],
    "pyinstaller": ["PyInstaller"],
    "pyqt5": ["PyQt5"],
    "pyside6": ["PySide6"],
    "llama-cpp-python": ["llama_cpp"],
    "ua-parser": ["ua_parser"],
    "jinja2": ["jinja2"],
    "markupsafe": ["markupsafe"],
    "itsdangerous": ["itsdangerous"],
}


@lru_cache(maxsize=None)
def _installed_top_level(dist: str) -> tuple[str, ...]:
    try:
        d = metadata.distribution(dist)
    except metadata.PackageNotFoundError:
        return ()
    text = d.read_text("top_level.txt")
    if text:
        return tuple(t.strip() for t in text.splitlines() if t.strip() and not t.startswith("_"))
    tops = set()
    for f in d.files or []:
        parts = f.parts
        if not parts or parts[0].endswith((".dist-info", ".data")) or parts[0] in ("..", "__pycache__"):
            continue
        top = parts[0][:-3] if parts[0].endswith(".py") else parts[0]
        if top.isidentifier() and not top.startswith("_") and (len(parts) > 1 or parts[0].endswith(".py")):
            tops.add(top)
    return tuple(sorted(tops))


def import_names(dist: str) -> tuple[list[str], str]:
    """(names, source) where source is installed_metadata | builtin_table | name_heuristic."""
    norm = normalize_name(dist)
    installed = _installed_top_level(norm)
    if installed:
        return list(installed), "installed_metadata"
    if norm in BUILTIN:
        return BUILTIN[norm], "builtin_table"
    return guess(norm), "name_heuristic"


def guess(norm: str) -> list[str]:
    """Import names guessed from a normalised distribution name: python-dateutil -> python_dateutil, dateutil."""
    names = [norm.replace("-", "_")]
    for prefix in ("python-", "py-"):
        if norm.startswith(prefix):
            names.append(norm[len(prefix):].replace("-", "_"))
    if norm.endswith("-python"):
        names.append(norm[: -len("-python")].replace("-", "_"))
    return list(dict.fromkeys(names))


def match_case(names: list[str], source: str, imported: set[str]) -> tuple[list[str], str]:
    """A guessed name (pypdf2) also matches a module the code imports under other casing (PyPDF2, fontTools)."""
    if source != "name_heuristic":
        return names, source
    actual = {m.lower(): m for m in sorted(imported)}
    out = [actual.get(n.lower(), n) for n in names]
    return (out, "name_heuristic_case") if out != names else (names, source)


def resolve_import_names(dist: str, version: str | None, imported: set[str], pypi=None) -> tuple[list[str], str]:
    """(names, source) in this order: the release's own metadata from PyPI (top_level.txt / RECORD, cached), the
    installed package's metadata, the distribution name when the code imports it under any casing, the built-in
    table, and finally the bare guess. pypi: a grounding.PackageSource, or None to skip the network step."""
    norm = normalize_name(dist)
    if pypi is not None and version:
        names = pypi.top_level(norm, version)
        if names:
            return list(names), "pypi_metadata"
    installed = _installed_top_level(norm)
    if installed:
        return list(installed), "installed_metadata"
    guesses = guess(norm)
    lower = {m.lower(): m for m in sorted(imported)}
    matched = [lower[g.lower()] for g in guesses if g.lower() in lower]
    if matched:
        exact = all(m in guesses for m in matched)
        return matched, "name_heuristic" if exact else "name_heuristic_case"
    if norm in BUILTIN:
        return BUILTIN[norm], "builtin_table"
    return guesses, "name_heuristic"
