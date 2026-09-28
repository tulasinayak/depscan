"""Parser interface. One parser per manifest type; RepoMapper merges their output."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Scope = Literal["main", "dev", "unknown"]


@dataclass
class ParsedEntry:
    name: str                              # normalised package name
    source_file: str                       # repo-relative path of the manifest
    # declared: the project asks for it; locked: a lockfile pins it;
    # constraint: a pip constraints file pins it *if* something else asks for it
    kind: Literal["declared", "locked", "constraint"]
    version_spec: str | None = None
    resolved_version: str | None = None
    unresolved_reason: str | None = None
    direct: bool | None = None             # lockfiles that know which packages are direct set this
    scope: Scope = "unknown"
    extras: list[str] = field(default_factory=list)
    marker: str | None = None
    requires: list[str] = field(default_factory=list)   # lockfiles: this package's own dependencies
    via: list[str] = field(default_factory=list)        # pip-compile "# via x" annotations: who needs it


@dataclass
class ParseOutput:
    entries: list[ParsedEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ManifestParser(ABC):
    ecosystem: str = "PyPI"
    priority: int = 50                     # lower = preferred when two manifests declare the same package

    @abstractmethod
    def matches(self, rel_path: str) -> bool:
        """True if this parser handles the file at this repo-relative path."""

    @abstractmethod
    def parse(self, path: Path, rel_path: str) -> ParseOutput:
        ...


def find_parser(rel_path: str, parsers: list[ManifestParser]) -> ManifestParser | None:
    return next((p for p in parsers if p.matches(rel_path)), None)
