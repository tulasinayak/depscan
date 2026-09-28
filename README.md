# depscan

Takes a Python repository (GitHub URL or local folder) and:
1. finds its dependencies,
2. matches them to known vulnerabilities (OSV.dev),
3. shows where each vulnerable dependency is used in the code,

and then, on demand, decides whether a vulnerability actually affects the repository: **affected**, **not
affected** or **needs review**, with a checklist of the six steps that led there (the *stepwise* method, mostly
code plus a few narrow questions to a **local open-source LLM**).

Agents are plain Python classes with pydantic input/output models. There is no agent framework, and no paid API.
Repository code is only ever parsed, never imported or executed.

## Setup (Windows, macOS, Linux; CPU is fine)

```bash
uv sync                          # Python 3.11+ environment with all dependencies
ollama pull qwen3:8b             # the default model (https://ollama.com)
uv run streamlit run app.py      # GUI on http://localhost:8501
```

`uv run pytest` runs the test suite. It needs no network and no model: OSV responses are replayed from
`tests/fixtures/osv/` and the LLM is faked. The real-browser GUI tests (Playwright, real local model, slow) are
excluded by default: `uv run pytest -m real_llm tests/gui -s` (screenshots in `tests/gui/screenshots/`).

**CPU speed:** on a laptop CPU, `qwen3:8b` generates about 4 tokens/s. One analysis takes about 1–3 minutes
and the repo-context summary takes about 1 minute. Scanning (steps 1–3 of the pipeline) takes seconds and
never calls the LLM.

## The three steps

| Step | What happens | LLM? |
|---|---|---|
| **1 · Scan** | RepoMapper (clone + manifests) → CVEMatcher (OSV, cached in SQLite) → UsageLocator (AST) → repo structure (app type, entry points, input sources) | never |
| **2 · Repo context summary** *(optional)* | a 3-sentence summary of what the repo is | one short call |
| **3 · Check** | **stepwise** (default): six gates, see below · **holistic** (baseline): ExploitabilityAgent, one verdict from usage snippets | stepwise: 0–5 small calls per vulnerability (+1 per advisory, cached); holistic: one call |

Every step saves `results/<owner>__<repo>_<timestamp>.json`, written atomically. Verdicts are appended and never
overwritten, so runs with and without context stay side by side. Every LLM call (prompt, raw response, parsed
result, duration) is logged to `logs/llm_calls.jsonl`.

### Verdicts are checked in code
- An evidence item citing a `file:line` that was not one of the usage snippets shown to the model is **dropped**,
  and the drop is recorded.
- A verdict other than `uncertain` needs at least one valid `file:line` citation; without one it is
  **downgraded to `uncertain`**.
- Repo context goes into the prompt only under "Background (not evidence)". It may change the model's confidence,
  never serve as evidence.

## The stepwise method

For one vulnerability, six gates run in order. Each returns `pass`, `fail` or `unknown` with one plain-English
sentence, its evidence (`file:line`) and whether code or the LLM decided it. **A gate says `fail` (not affected)
only on definite evidence; anything unclear is `unknown`**, because missing a real vulnerability is worse than a
false alarm.

| # | Gate | Decided by | Fails when |
|---|---|---|---|
| 1 | version_in_range | code | never (an unresolved version is `unknown`) |
| 2 | trigger_spec | LLM, once per advisory | — (no spec → `unknown`) |
| 3 | present | code | no use of a trigger API (directly, through a parent package, or through a bundled library's wrapper APIs), no dynamic imports, no parse failures |
| 4 | reachable | code | the use sits after a `return`/`raise`, under `if False:`, in a function nothing refers to, in a module nothing imports, or only in tests |
| 5 | dangerous_form | code, else one narrow LLM question | the call uses a safe argument (`Loader=SafeLoader`, `verify=True`), or the LLM answers "no" |
| 6 | attacker_input | code (taint), else one narrow LLM question | the input is a literal / a file bundled with the repo, or the LLM answers "no"; skipped when the advisory needs no attacker input |

Gates 4–6 run per usage site. Verdict (in code): any gate `fail` → **not affected** (citing the first failing
gate); all `pass` → **affected**; otherwise **needs review** (listing the undecided gates). Fuzz-crash records are
always *needs review*, without an LLM call.

- **Trigger spec** (`depscan/triggers.py`): from the advisory text and the changed lines of the fix commit (the
  GitHub/GitLab `.diff` of its FIX references, tests and docs removed), the model lists the trigger APIs, argument
  patterns, whether attacker input is needed, how popular parent packages reach it and, for bundled native
  libraries, which wrapper APIs reach them. It never sees the repository. Specs are cached per advisory in
  `cache/triggers/<id>__<package>.json`. A human-reviewed `overrides/triggers/<id>.yaml` (same fields; use an alias
  id if you like) always wins and is shown as *human-reviewed*.
- **Reachability** (`depscan/codeindex.py`, ast only): entry points are app factories, route handlers, app
  instances, `__main__` blocks, console scripts and modules named in Procfile/Dockerfile/…; tests are separate
  roots. Functions are linked by name (over-approximating). A condition on a config or environment value is
  *conditional* → `unknown` with the flag's name. A computed `getattr`, `import_module(variable)`, `globals()`, a
  function name inside a string, or a method of a framework subclass turns a would-be `fail` into `unknown`.
- **Taint**: `request.*`, route and CLI parameters, `sys.argv`, `input()`, followed through assignments, simple calls
  and two levels of callers. When only part of a value is attacker-controlled (`f"{BASE}/stock/{sku}"`), the LLM is
  asked.
- At most 4 narrow questions per vulnerability; each sees only the enclosing function (and for input, its callers)
  plus the spec.

## Vocabulary

**Vulnerability `kind`**
- `standard`: a bug in the package's Python code.
- `bundled_native`: a flaw in a native library shipped inside the wheel (OpenSSL in `cryptography`, libwebp in
  Pillow, …). Importing the package is not evidence. What matters is whether the repo calls APIs that reach
  the library, which is recorded as "native reach" sites using the table in `depscan/native_reach.py`
  (extend it freely).
- `fuzz_crash`: OSS-Fuzz crash records (`OSV-*`, git ranges only). They are listed separately, not counted in
  the headline numbers, and never sent to the LLM.

**`usage_status`** per vulnerable dependency
- `direct_usage`: the repository's code imports or uses it (sites listed with ±5-line snippets).
- `no_direct_usage`: never imported by repo code. When a lockfile or pip-compile annotations say which package
  requires it (e.g. `urllib3 ← requests`), `required_by` is filled in and the usage sites of those parents are
  shown as `indirect_sites`.
- `parse_incomplete`: nothing found, but some files failed to parse, so usage can't be ruled out.

**"Not imported" ≠ "not affected".** A package that is never imported can still run: `requests` calls
`urllib3` on every request, gunicorn is started from a Procfile, plugins are loaded by entry points, and
`importlib` can load anything. `no_direct_usage` only says where to look (through the parent package), and the
tool never displays or treats it as "not affected".

Other fields worth knowing:
- `advisory_symbols`: function and class names pulled deterministically from the advisory text.
- `matched_vulns`: set on each usage site that touches one of those symbols.
- `related_ids`: advisories that share a specific reference URL but are not aliases of each other. They are
  linked, not merged.

## CLI

```bash
uv run python -m depscan.cli scan https://github.com/owner/repo      # or a local folder
uv run python -m depscan.cli show results/<file>.json                # dependency -> vulnerability table
uv run python -m depscan.cli context results/<file>.json             # step 2
uv run python -m depscan.cli analyze results/<file>.json CVE-2017-18342 [--method stepwise|holistic] [--dependency pyyaml]
uv run python -m depscan.cli analyze-all results/<file>.json [--method stepwise|holistic] [--min-cvss 7]
```
`--with-context` applies to the holistic method only.

```bash
uv run python -m depscan.cli evaluate results/<file>.json [--expected PATH]                  # score against known answers
uv run python -m depscan.cli evaluate-suite suite.yaml [--method stepwise|holistic|both] [--no-llm] [--only a,b] [--redo]
```

`--verbose` shows the underlying details of an error. Ctrl+C during `analyze-all` stops the run, and every
verdict finished so far is already saved. Each agent can also be run on its own:
`python -m depscan.agents.repo_mapper|cve_matcher|usage_locator <url-or-path>`.

## Evaluation against known answers

A repository can carry its own answers in `.depscan/expected.yaml`. depscan skips `.depscan/` entirely while
scanning (like `.git/`), so the answers never reach an agent or a prompt; they are only read by `evaluate`, the
GUI's **Evaluation** tab and its green/red "expected" badges.

```yaml
advisories:                      # one entry per advisory; scored per mode (with / without repo context)
  - {id: CVE-2020-14343, package: pyyaml, expected: likely_affected,   # likely_affected | likely_not_affected | uncertain
     scenario: reachable_untrusted_input, reason: "...", key_location: app/routes.py:35, project: null}
expected_dependencies:           # optional, scores RepoMapper (only the fields given are compared)
  - {name: requests, version: "2.31.0", scope: main, direct: true, match: affected, project: null}
expected_sites:                  # optional, scores UsageLocator recall / precision per (package, file, line)
  - {package: pyyaml, location: "app/routes.py:35", symbol: full_load}
```

Methods are reported side by side (holistic without context, holistic with context, stepwise) with:
**decided accuracy** (right answers among firm affected / not-affected answers), **coverage** (share of labelled
advisories that got a firm answer), **missed affected** (expected affected, answered not affected: the most
important number), false alarms, and LLM calls and seconds per vulnerability. Entries labelled `uncertain` are
reported but not scored. `evaluate-suite` scans every repo of a suite file, carries over verdicts from earlier
result files of the same commit (so finished work is reused and an interrupted run resumes), runs the chosen
method where it has no verdict yet (`--redo` forces it), and reports per repo and per scenario; the GUI's
**Suite** page shows those results. The test suite used during development is
[depscan-test-suite](https://github.com/tulasinayak/depscan-test-suite) (11 repos, 103 labelled advisories).

## Multi-project repositories

When manifests live in separate sub-projects (e.g. `services/api/requirements.txt` and
`services/worker/requirements.txt`), each sub-project is merged on its own: the same package can be reported at a
different version per service, it is shown as `services/api:pyyaml`, and its usage sites only come from files
under that directory. A repo whose manifests form one project (the usual case) behaves exactly as before.

## Configuration (`config.toml`)

| Key | Default | Notes |
|---|---|---|
| `llm.base_url` | `http://localhost:11434/v1` | any OpenAI-compatible endpoint (Ollama, Kimi, vLLM, …) |
| `llm.model` | `qwen3:8b` | |
| `llm.api_key` | `ollama` | prefer the `DEPSCAN_LLM_API_KEY` environment variable for real keys |
| `llm.reasoning_effort` | `none` | turns qwen3's thinking mode off (about 10× faster on CPU); `""` = don't send |
| `llm.json_mode` | `true` | `response_format = json_object` |
| `llm.temperature` | `0.1` | |
| `llm.max_context_tokens` | `8192` | must match the server window. Ollama's OpenAI endpoint cannot set it per request: start Ollama with `OLLAMA_CONTEXT_LENGTH=8192` (Windows: `set OLLAMA_CONTEXT_LENGTH=8192` before `ollama serve`), or set this to 4096 for the default window |
| `llm.max_output_tokens` | `900` | |
| `osv.cache_ttl_hours` | `24` | OSV responses are cached in `workspace/cache.sqlite` |
| `osv.offline` | `false` | cache only; misses are reported (`DEPSCAN_OFFLINE=1`, or the GUI toggle) |
| `osv.max_workers` | `8` | parallel advisory downloads |

Environment overrides: `DEPSCAN_LLM_BASE_URL`, `DEPSCAN_LLM_MODEL`, `DEPSCAN_LLM_API_KEY`, `DEPSCAN_OFFLINE`.

## Supported manifests

`requirements*.txt` (with `-r`/`-c` includes, `-e`/URL/VCS requirements, extras, markers and pip-compile
`# via` annotations), `pyproject.toml` (PEP 621, PEP 735 groups, Poetry), `Pipfile`, `poetry.lock`,
`Pipfile.lock` and `uv.lock`. Versions come only from exact pins, constraint pins or lockfiles, never guessed.
Unpinned dependencies are matched against the advisory's affected versions and marked `possibly_affected`
with the reason. The parser layer (`depscan/parsers/`) has a registry, so npm can be added later.

## Safety

- A local folder given as input is read-only.
- Clones go to `workspace/<owner>__<repo>`. A rescan runs `git fetch --depth 1` plus a hard reset, falling
  back to a fresh clone.
- A directory is deleted only if it is inside `workspace/` and carries depscan's `.git/depscan-clone` marker.

## Tests

`uv run pytest` runs the **fast** tests only. They are offline, need no LLM, and each takes well under a second. The
run ends with a coverage report per module. The other groups are selected with a marker:

| marker | what | run with |
|---|---|---|
| `fast` | the default; every test without another category | `uv run pytest` |
| `slow` | offline but slower: Streamlit AppTest pages, real git clones, big inputs, the metamorphic sweep | `uv run pytest -m slow` |
| `security` | malicious repos and packages: links, path tricks, git hooks and filters, URL checks, archive bombs, HTML escaping | `uv run pytest -m security` |
| `metamorphic` | code transformations of the development repos (`results/metamorphic_report.md`) | `uv run pytest -m metamorphic` |
| `gui` | real-browser runs with Playwright; `tests/gui/test_gui_edge.py` uses a fake LLM and its own server on port 8502 | `uv run pytest -m gui tests/gui -s` |
| `llm` | needs a running model (Ollama, or a cloud profile) | `uv run pytest -m llm -s` |
| `network` | needs the internet (PyPI, OSV, GitHub) | `uv run pytest -m network` |
| `realworld` | real public projects, scanned and checked | `uv run pytest -m realworld -s` |

`security` and `metamorphic` tests that are quick also run by default. Add `--no-cov` to skip the coverage report,
and `-m "fast or slow"` to run everything offline. Nothing in the tests reads or scans the held-out repositories.

## Known limitations

- Static analysis only. Reachability and taint are name-based and simple (no types, no aliasing through data
  structures); when they cannot tell, the gate says `unknown` rather than guessing.
- A trigger spec written by a small model can be wrong; a wrong "safe" argument or a wrong "this parent never
  reaches it" can turn into a wrong *not affected*. Review specs that decide important verdicts and save them as
  overrides.
- The advisory-symbol extraction is heuristic; many advisories name no function at all.
- Without a lockfile or pip-compile annotations, transitive dependencies are not discovered.
- Small local models make mistakes. The citation checks catch invented locations, not wrong reasoning.
