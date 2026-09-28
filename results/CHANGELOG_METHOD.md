# Method changelog

Changes to depscan's matching logic, gates or prompts, with the data each change was made after seeing. Results
from any data seen before a change can't count as held-out for it.

The held-out evaluation is pre-registered in `PREREGISTRATION.md`. Its timestamped original is the copy in the public
`depscan-test-suite` repository, commit `c5449f1`.

## 2026-09-27: after seeing held-out set 1 (depscan-heldout-1, -2, now group "dev-2")

Approved by the user after STOP 3. Tests: `tests/test_stepwise.py`, section "after held-out set 1" (made-up package
names `quuxarc`, `zorbakit`).

1. **Missing or empty input never produces "fail".** I went through every gate:
   - present: a spec with an empty `trigger_symbols` and a native feature with empty `wrapper_symbols` failed by
     code ("but not , which the vulnerability needs": opencv PYSEC-2023-184, a missed affected). It now gives
     unknown.
   - present: a trigger, wrapper or parent symbol that is not a dotted identifier (`jwt.PyJWKClient.get_signing, `)
     can't be searched for, so absence can't be shown. It now gives unknown (parents: an unknown note).
   - dangerous_form: an argument value that the spec lists as both safe and dangerous was treated as safe (fail).
     It now gives unknown.
   - attacker_input: a call with no arguments was "constant" (fail). The data may come from the object the method
     is called on (`archive.extractall()`) or from defaults, so it now gives unknown. When the spec names an input
     argument that the call doesn't pass and the other arguments are fixed, the result is also unknown, not
     constant.
   - Checked and unchanged, since each needs positive evidence: reachable (dead code, test-only, never imported or
     referenced; dynamic imports and calls already give unknown); version; parent `reachable: false` (a claim
     in the spec, not missing input); `when_absent: safe/dangerous` (a claim in the spec about the default).
2. **A class call counts as a call to its `__init__` / `__new__`.** A trigger `py7zr.SevenZipFile.__init__` now
   matches `py7zr.SevenZipFile(...)` (py7zr CVE-2026-55206, a missed affected). Method calls on the instance don't
   count.
3. **Case-insensitive import-name fallback.** When the import name is only guessed from the distribution name, it
   is matched against the modules the code imports without regard to case (`pypdf2` → `PyPDF2`, `fonttools` →
   `fontTools`). The source is recorded as `name_heuristic_case`. Stepwise normalises spec symbols with the names
   the usage locator resolved, so a spec's `PyPDF2.PdfReader` isn't rewritten back to lowercase.

Seen but not changed (candidates for spec validation, 5a-extra item 4): arg_form values written with quotes
(`"'r'"`) don't match the code index's unquoted values (`r`).

## 2026-09-27: 5a-extra items 1–5, grounding specs in the package's own code (approved by the user)

Code: `depscan/grounding.py`. Tests: `tests/test_grounding.py`, with the made-up packages quuxarc, zorbanet and nativo
served from an in-memory PyPI.

1. **Import names from the release's own metadata.** Order:
   1. `top_level.txt` or `RECORD` of the PyPI wheel for the exact pinned version (cached in the SQLite cache);
   2. installed-package metadata;
   3. the distribution name, when the code imports it under any casing;
   4. the built-in table;
   5. the bare guess.

   `[grounding] pypi = true` in config.toml. Offline mode uses the cache only.
2. **API index per package version**, built with `ast` from the downloaded archive and stored in
   `cache/api_index/<package>-<version>.json`. It records:
   - modules, public classes and their methods, public functions;
   - `__all__`, re-exports (including `from x import *`);
   - function line spans and outgoing references.

   A module is "opaque" when it makes names at runtime (a module-level `__getattr__`, `importlib`, `globals()`, a
   star import from an unindexed module) or pulls names from a compiled extension.

   Archive safety:
   - Members are read in memory, never extracted, and nothing is executed.
   - Absolute paths, `..` and links are skipped.
   - Files over 5 MB are skipped, and an archive is capped at 50 MB.
   - Each download is checked against PyPI's sha256.
3. **Retrieved facts in the spec prompt (grounded variant only).** The prompt gets a section
   "## Public API of {package} {version} (relevant excerpt; trigger_symbols and wrapper_symbols must use names from
   the package's real API such as these)":
   - up to 60 index entries, chosen by keywords from the advisory and the fix diff and by the diff's modules;
   - then "## Functions changed by the fix", with the diff's hunks mapped onto the indexed version's function spans.

   **Prompt note:** the words after "relevant excerpt;" are an instruction added inside that section. SPEC_SYSTEM
   and the prompt for the "llm" variant are unchanged.
4. **Spec validation (grounded variant).** Each trigger, arg_form call and wrapper symbol is resolved through
   re-exports, the import name instead of the distribution name, casing, then a unique match on its last one or two
   name parts.
   - Unresolvable symbols are dropped and recorded in `validation_issues`.
   - Symbols in opaque modules, or without Python source, are kept, marked "kept unverified".
   - An empty list after validation gives unknown, never fail.
5. **Parent triggers from code (grounded variant).** For each parent the scanned repo actually has, the parent's
   functions that reference the child's trigger symbols are found. They are followed back through the parent's own
   calls (by name, which over-approximates) up to 8 levels, and the public ones plus their re-export aliases are
   kept.
   - These entries are marked `source: code`, and the LLM's parent entry contributes only its condition text.
   - No index, or no trigger symbols, gives empty symbols, which the presence gate treats as unknown.

Spec variants have their own caches: `cache/triggers/` for "llm" and `cache/triggers__llm_facts/` for "llm+facts".
The stepwise verdict records `spec_variant`, and `evaluate` / `evaluate-suite --spec-variant` score one variant.
