"""Deterministic extraction of code symbols named in advisory text, and matching them against usage sites.

Best effort only: advisories are free text, many name no function at all, and nothing downstream
may treat "no symbol matched" as "not affected".
"""

import builtins
import re
import sys

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_DOTTED = rf"{_IDENT}(?:\.{_IDENT})+"
# Words that look like code (CamelCase, dotted) but are product/format names, not symbols.
_NOT_SYMBOLS = {"pyyaml", "openssl", "libressl", "boringssl", "github", "javascript", "python", "cpython", "pypi",
                "json", "yaml", "html", "http", "https", "url", "uri", "api", "cli", "utf", "dos", "redos", "cve",
                "cvss", "nvd", "ghsa", "osv", "true", "false", "none", "null", "macos", "windows", "linux",
                "libwebp", "libjpeg", "libtiff", "libxml", "freetype", "zlib", "ossfuzz", "oss-fuzz", "readme",
                "i.e", "e.g", "etc", "poc", "get", "post", "put", "cookie", "rgb", "rgba", "gzip", "deflate", "zstd",
                "main", "init", "run", "data", "value", "self", "user", "app", "config", "retries", "headers"}
_BUILTINS = set(dir(builtins))
_STDLIB = set(sys.stdlib_module_names) | {"str", "bytes", "dict", "list", "int", "object", "self"}
_FILE_LIKE = re.compile(r"\.(com|org|net|io|dev|html?|txt|md|rst|py|json|ya?ml|toml|cfg|in|c|h|so|dll|whl|gz)$", re.I)


def extract_symbols(text: str, import_names: list[str], package: str) -> list[str]:
    """Candidate symbols from advisory text: backticked identifiers, dotted names, CamelCase classes, name()."""
    found: list[str] = []
    skip = {package.lower(), *(n.lower() for n in import_names)}
    text = re.sub(r"https?://\S+|www\.\S+", " ", text)               # URL fragments are not symbols
    text = re.sub(r"\\[nrt]", " ", text)                              # literal "\n" inside quoted PoC code

    def add(tok: str) -> None:
        tok = re.sub(r"\(.*\)$", "", tok.strip()).strip(".")
        if (not tok or tok.lower() in skip or tok.lower() in _NOT_SYMBOLS or _FILE_LIKE.search(tok)
                or re.fullmatch(r"[\d.]+", tok) or len(tok) < 3 or tok in _BUILTINS
                or re.fullmatch(r"[A-Z0-9_]+", tok)):                  # RGBA, INT_MAX: constants/formats
            return
        root = tok.split(".")[0]
        if "." in tok and root in _STDLIB and root not in import_names:
            return  # os.path.join, str.format: about Python itself, not this package
        if tok not in found:
            found.append(tok)

    for m in re.finditer(r"`([^`\n]{2,80})`", text):                       # `yaml.load`, `Image.open()`
        inner = m.group(1).strip()
        if re.fullmatch(rf"{_IDENT}(?:\.{_IDENT})*(?:\(.*\))?", inner):
            add(inner)
    for m in re.finditer(rf"\b({_DOTTED})(?:\(\))?", text):                # yaml.load, PIL.Image.open
        add(m.group(1))
    for m in re.finditer(r"\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b", text):     # PoolManager, ImageFile
        add(m.group(1))
    for m in re.finditer(rf"\b({_IDENT})\(\)", text):                     # full_load()
        add(m.group(1))
    for m in re.finditer(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\s+(?:method|function|api|call|helper)\b", text, re.I):
        add(m.group(1))                                                   # "through the full_load method"
    return found[:15]


def symbol_matches(site_symbol: str, advisory_symbol: str) -> bool:
    """'yaml.load' ~ 'yaml.load'; 'PIL.Image.open' ~ 'Image.open'; 'urllib3.PoolManager' ~ 'PoolManager'."""
    if site_symbol == advisory_symbol or site_symbol.endswith("." + advisory_symbol):
        return True
    site_parts, adv_parts = site_symbol.split("."), advisory_symbol.split(".")
    if len(adv_parts) >= 2 and len(site_parts) >= 2 and site_parts[-len(adv_parts):] == adv_parts:
        return True
    # A bare class/function name also matches when it appears inside the chain: PoolManager ~ urllib3.PoolManager.request
    return len(adv_parts) == 1 and len(advisory_symbol) >= 4 and advisory_symbol in site_parts[1:]
