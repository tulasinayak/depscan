# Public release checklist

Checked on 2026-09-28. **Note: the repository `tulasinayak/depscan` has been public since it was created on
2026-09-28**, by mistake; it was meant to start private. The owner decided to keep it public. This list records what
was checked and what is still open.

| # | check | how | result |
|---|---|---|---|
| 1 | No API keys or tokens in any commit | `git log --all -p` searched for `AIza…`, `sk-…`, `ghp_…`, and for the value of `GEMINI_API_KEY` itself (value never printed) | **pass**: 0 hits |
| 2 | No key in logs/, results/ or cache/ | `tests/test_secrets.py` (runs with the fast tests) | **pass** |
| 3 | No private paths or usernames in the current files | `git grep` for the Windows home path, `TULASI~1`, the e-mail address | **pass** since commit 545f922; report headers now print `results/…` or `~/…` |
| 4 | No private paths or e-mail in the git history | same search over `git log --all -p` and the commit metadata | **open**: the e-mail address is the author of the 23 commits before 545f922, and one old version of `results/depscan-test-reachability_eval_20260925-124221.md` has the Windows path. Removing them needs a history rewrite and a force push (not done; waiting for the owner). New commits use the GitHub no-reply address. |
| 5 | Logs with prompts and LLM answers not committed | `.gitignore` has `logs/`; `git ls-files` | **pass**: no log files tracked |
| 6 | Cached third-party package source not committed | `.gitignore` has `cache/`, `workspace/`, `*.sqlite`; `git ls-files` for archives | **pass**: no `.whl`, `.tar.gz`, `.zip`, `.sqlite` or cache files tracked |
| 7 | Raw result JSON not committed | `.gitignore` has `results/*.json` | **pass**: only Markdown reports are tracked |
| 8 | Screenshots show nothing private | 25 PNGs in `tests/gui/screenshots/`; 2 were opened and checked (`01_scan_done.png`, `check_06_advanced.png`) | **pass** for those 2 (only the public GitHub user name and repo-relative paths); the other 23 were not opened one by one |
| 9 | Licence chosen | no `LICENSE` file | **open**: the owner chooses one (e.g. MIT or Apache-2.0) |
| 10 | Related public repos | `depscan-test-suite`, `depscan-heldout-*` are public | **open**: their commits also carry the e-mail address. Rewriting `depscan-test-suite` would change commit `c5449f1`, the timestamped pre-registration, so it should stay as it is. |
