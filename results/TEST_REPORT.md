# depscan test report

Written 2026-09-28. It covers the test sections that were built: T1–T6, T8 and T9. **T7 (LLM consistency),
T10 (performance on larger projects) and T11 (real-world smoke run) were not done**; see "Not done" at the end.

## Test counts

424 tests in total, counted with `pytest --collect-only`. `uv run pytest` runs the fast ones by default.

| marker | tests | runs by default | what it covers |
|---|---|---|---|
| fast | 377 | yes | everything that runs offline in seconds (the default) |
| slow | 37 | no (`-m slow`) | real clones of local fixture repos, big generated inputs, the GUI through Streamlit's AppTest |
| security | 51 | yes (subset of fast) | T8: malicious repos and archives, clone hardening, secret leaks |
| metamorphic | 13 | yes (subset of fast) | T6: behaviour-preserving and meaning-changing rewrites of the development repos |
| gui | 10 | no (`-m gui`) | T9: Playwright against a real Streamlit server with a fake LLM |
| llm | 3 | no (`-m llm`) | real calls to the local model |
| network | 0 | – | – |
| realworld | 0 | – | T11 was not done |

Last runs: fast 376 passed, 1 skipped (a symlink test that needs Windows Developer Mode; its junction half runs);
slow 37 passed; gui 7 of 7 edge-case tests passed (T9).

## Tests per part

| part | file(s) | tests |
|---|---|---|
| T1 manifests | test_manifests_robust.py (+ test_repo_mapper.py) | 10 (+42) |
| T2 version matching | test_matching_robust.py (+ test_cve_matcher.py) | 36 (+28) |
| T3 usage locator | test_usage_robust.py (+ test_usage_locator.py) | 12 (+31) |
| T4 reachability rules | test_reachability_rules.py | 22 |
| T5 gate rules | test_gate_rules.py (+ test_stepwise.py) | 21 (+34) |
| T6 metamorphic | test_metamorphic.py | 13 |
| T8 security | test_security.py, test_secrets.py, test_local_folder_safety.py | 45, 6, 5 |
| T9 GUI edge cases | tests/gui/test_gui_edge.py | 7 |
| grounding (5a-extra) | test_grounding.py | 16 |
| LLM profiles (Gemini provider) | test_llm_profiles.py | 13 |

## Coverage per module (fast tests)

Total **75%** (6,208 statements, 1,532 missed). The GUI modules show low numbers because the GUI tests drive a
separate Streamlit server process, which coverage does not measure.

| module | coverage | module | coverage |
|---|---|---|---|
| agents/cve_matcher.py | 88% | llm/client.py | 93% |
| agents/exploitability.py | 100% | llm/prompts.py | 91% |
| agents/repo_context.py | 93% | models.py | 100% |
| agents/repo_mapper.py | 91% | orchestrator.py | 90% |
| agents/stepwise.py | 94% | osv.py | 94% |
| agents/usage_locator.py | 91% | parsers/python_manifests.py | 94% |
| cache.py | 100% | report.py | 36% |
| cli.py | 52% | safety.py | 89% |
| codeindex.py | 90% | suite.py | 44% |
| config.py | 97% | symbols.py | 98% |
| evaluate.py | 95% | triggers.py | 95% |
| grounding.py | 89% | ui/* | 0–59% (see above) |
| import_names.py | 97% | | |

## Results per part

- **T1 manifests.** Hypothesis round-trips of requirement files, nasty files and big lockfiles. 2 bugs (below).
- **T2 matching.** Version ordering checked against `packaging`, specifiers, alias chains, cache. 1 bug. One test
  expectation of mine was wrong: under PEP 440, `<1.0` excludes 1.0rc1, so dropping that advisory is correct.
- **T3 usage locator.** Syntax coverage (match, walrus, async, nested and conditional imports, 3-level
  re-exports, imports inside functions) and nasty files (Python 2, latin-1, null bytes, binary, deep nesting,
  50,000 lines). No bugs.
- **T4 reachability.** Entry points of 9 kinds, function references, conservative cases. 2 bugs.
- **T5 gate rules.** All 46,656 combinations of pass / fail / unknown × code / AI for the six gates match the
  documented status rules, and missing input never gives fail. 1 bug (spec validation).
- **T6 metamorphic** ([metamorphic_report.md](metamorphic_report.md)). 277 variants, 218 applied. All 139
  meaning-changing variants changed the result as expected; 0 unexpected results.
- **T8 security.** Symlinks and junctions, includes outside the repo, git hooks, filters, LFS and submodules in
  clones, URL schemes, size and count caps, archive bombs and unsafe member names in PyPI downloads, and the
  Gemini key never appearing in logs/, results/ or cache/. Several fixes (below).
- **T9 GUI edge cases.** Nothing-found views, clone / OSV / AI failures, 210 vulnerabilities (renders in 8–13 s),
  Stop and resume (a finished check is never redone), reload in the middle of a check (the result file stays valid).
  Bugs fixed: the Check page's error was wiped by a rerun, and row keys contained characters that are not CSS-safe.

## Bugs found

The ones that change what is analysed or how a verdict is reached are also in
[CHANGELOG_METHOD.md](CHANGELOG_METHOD.md).

| part | bug | effect before the fix |
|---|---|---|
| T1 | a UTF-8 byte-order mark hid the first package of a manifest | that dependency was never checked |
| T1 | the same package pinned to two versions | silently used one; now a warning |
| T2 | corrupted cache rows (invalid JSON or wrong shape) | the scan crashed |
| T4 | Django URLconfs were not entry points | views could be called "never runs" (a wrong not affected) |
| T4 | `eval` / `exec` / `compile` / `module.__dict__[name]` were not dynamic dispatch | a function could be called unreachable |
| T5 | spec validation moved a symbol of another package onto this one | wrong trigger lists (grounded variants) |
| T8 | symlinked files were read; `-r` includes could leave the repo | files outside the repo were analysed |
| T8 | clones could run repo hooks / filters / LFS; no size caps | untrusted code or huge inputs |
| T9 | the Check page's error message disappeared on rerun; unsafe row keys | a confusing or broken GUI |
| spec review | the API index missed definitions in `if`/`try` blocks, inherited members, `Base[T]` bases, class attributes; a casing rewrite hit a variable | wrong drops or rewrites of spec symbols (grounded variants) |

## Not done

- **T7 LLM consistency** (the same question asked repeatedly, and paraphrased): not done.
- **T10 performance** on 3 larger real projects: not done.
- **T11 real-world smoke run** on 5 public projects, with 10 verdicts spot-checked by hand
  (`results/realworld_spotcheck.md`): not done.
