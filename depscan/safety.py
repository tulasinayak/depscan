"""Safety rules for reading an untrusted repository. Every read of a scanned repo goes through here.

- Symlinks are never followed: a link to ~/.ssh or C:\\Windows could otherwise put private files into a prompt.
- A path must stay inside the repo after resolving (``-r ../../etc/passwd`` in a requirements file is refused).
- Size and count limits keep one huge or generated repo from exhausting memory; each limit adds a warning.
- Only https remotes (or an existing local folder) are cloned; see validate_repo_url.
"""

import os
import re
from pathlib import Path
from urllib.parse import urlsplit

MAX_SOURCE_BYTES = 2 * 1024 * 1024        # a .py file larger than this is skipped (generated or not source)
MAX_MANIFEST_BYTES = 5 * 1024 * 1024      # requirements / lock files larger than this are skipped
MAX_SOURCE_FILES = 20_000                 # .py files read per scan
MAX_WALK_ENTRIES = 200_000                # directory entries visited per scan


class UnsafeRepoURL(RuntimeError):      # shown to the user like a clone error
    pass


def validate_repo_url(url: str) -> str:
    """Accept https://host/owner/repo (no credentials, no options). Reject file://, ext::, ssh/git remotes, anything
    starting with "-" (it would be read as a git option) and URLs with a user name or password."""
    url = url.strip()
    if not url:
        raise UnsafeRepoURL("Empty repository URL.")
    if url.startswith("-"):
        raise UnsafeRepoURL("A repository URL may not start with '-'.")
    if "::" in url.split("/")[0] or url.lower().startswith(("ext::", "fd::")):
        raise UnsafeRepoURL("git remote helpers (ext::, fd::) are not allowed.")
    if any(ord(c) < 32 or c.isspace() for c in url):
        raise UnsafeRepoURL("A repository URL may not contain spaces or control characters.")
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise UnsafeRepoURL(f"Only https:// repository URLs (or an existing local folder) can be scanned, not "
                            f"{parts.scheme or 'this form'}.")
    if parts.username or parts.password or "@" in parts.netloc:
        raise UnsafeRepoURL("Repository URLs with a user name, password or token are not allowed.")
    if not parts.hostname or not re.fullmatch(r"[A-Za-z0-9.-]+", parts.hostname):
        raise UnsafeRepoURL("The repository URL has no valid host.")
    if parts.query or parts.fragment:
        raise UnsafeRepoURL("The repository URL may not have a query or fragment.")
    return url


def is_link(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(getattr(os.lstat(path), "st_file_attributes", 0) & 0x400)   # + junctions
    except OSError:
        return False


def inside(root: Path, path: Path) -> bool:
    """True when path is inside root and no part of it below root is a symlink or junction."""
    root = Path(root)
    try:
        rel = Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
    except ValueError:
        return False
    cur = Path(os.path.abspath(root))
    for part in rel.parts:
        if part == "..":
            return False
        cur = cur / part
        if is_link(cur):
            return False
    try:
        return cur.resolve().is_relative_to(root.resolve())
    except OSError:
        return False


def read_text(root: Path, path: Path, max_bytes: int = MAX_SOURCE_BYTES) -> str | None:
    """The file's text, or None when it is outside the repo, a link, missing or larger than max_bytes."""
    if not inside(root, path):
        return None
    try:
        if not path.is_file() or path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
