from depscan.parsers.base import ManifestParser, ParsedEntry, ParseOutput, find_parser
from depscan.parsers.python_manifests import PYTHON_PARSERS, normalize_name

PARSERS: list[ManifestParser] = [*PYTHON_PARSERS]  # add npm parsers here later
