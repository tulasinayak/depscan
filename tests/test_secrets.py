"""The Gemini API key comes only from the environment and must never be written anywhere depscan writes.

Skipped when GEMINI_API_KEY is not set. The test never prints the key: a failure names the file only.
"""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
WATCHED = ["logs", "results", "cache", "workspace"]
CHUNK = 4 * 1024 * 1024


def contains(path: Path, needle: bytes) -> bool:
    """Chunked search with overlap, so a match across two chunks is found too."""
    tail = b""
    try:
        with path.open("rb") as fh:
            while chunk := fh.read(CHUNK):
                if needle in tail + chunk:
                    return True
                tail = chunk[-(len(needle) - 1):]
    except OSError:
        return False
    return False


@pytest.fixture(scope="module")
def key() -> bytes:
    value = os.environ.get("GEMINI_API_KEY", "")
    if len(value) < 8:
        pytest.skip("GEMINI_API_KEY is not set")
    return value.encode()


@pytest.mark.security
@pytest.mark.slow
@pytest.mark.parametrize("folder", WATCHED)
def test_gemini_key_never_written_to_disk(key, folder):
    base = ROOT / folder
    if not base.exists():
        pytest.skip(f"{folder}/ does not exist")
    leaks = [str(p.relative_to(ROOT)) for p in base.rglob("*") if p.is_file() and contains(p, key)]
    assert not leaks, f"the GEMINI_API_KEY value appears in: {leaks}"


@pytest.mark.security
@pytest.mark.slow
def test_gemini_key_not_in_tracked_files(key):
    files = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True).stdout.split(b"\0")
    leaks = [f.decode() for f in files if f and contains(ROOT / f.decode(), key)]
    assert not leaks, f"the GEMINI_API_KEY value appears in tracked files: {leaks}"


@pytest.mark.security
def test_the_check_itself_finds_a_planted_value(tmp_path):
    (tmp_path / "a.log").write_bytes(b"x" * (CHUNK - 3) + b"PLANTED-SECRET-123" + b"y" * 10)
    assert contains(tmp_path / "a.log", b"PLANTED-SECRET-123")                 # across a chunk boundary
    assert not contains(tmp_path / "a.log", b"OTHER-SECRET-456")
