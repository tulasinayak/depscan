# Held-out results: why stepwise got each one wrong (2026-09-27)

Run: `results/suite_eval_20260927-191021` (held-out only) and `results/suite_eval_20260927-191134` (combined, reused
verdicts). The labels were committed before the run (heldout-1 c39a72d, heldout-2 86c43db). No logic, prompt or spec
was changed after the results, and none of the causes below has been fixed.

| group | method | decided accuracy | coverage | missed affected | false alarms |
|---|---|---|---|---|---|
| development | holistic w/o ctx | 61% (14/23) | 70% | 0 | 9 |
| development | stepwise | 95% (72/76) | 75% | 0 | 4 |
| heldout | holistic w/o ctx | 50% (4/8) | 42% | 0 | 4 |
| heldout | holistic w/ ctx | 46% (5/11) | 58% | 2 | 4 |
| heldout | stepwise | 46% (5/11) | 58% | 2 | 4 |

## Stepwise errors, by cause

### Code (matching logic): 3 advisories, including both misses

1. **Import-name table.** `pypdf2` and `fonttools` are not in `depscan/import_names.py`. The guess falls back to the
   lowercase distribution name, which doesn't match `import PyPDF2` / `from fontTools.ttLib import TTFont`. So 9 usage
   sites were missed, the packages looked "only used through other packages", and 4 advisories (PyPDF2 ×2, fonttools
   ×2) ended as needs_review. None of these was decided wrong, but coverage suffered.
2. **Constructor vs `__init__`.** py7zr CVE-2026-55206: the spec's trigger is `py7zr.SevenZipFile.__init__`, the app
   calls `py7zr.SevenZipFile(path)`, and the matcher doesn't treat a class call as its `__init__`. The present gate
   failed **by code**, giving not_affected. **MISSED AFFECTED.**
3. **Empty trigger list counted as "not used".** For PYSEC-2023-184 (opencv), the spec has `trigger_symbols: []` and a
   native_feature with `wrapper_symbols: []`. The present gate then failed by code ("but not , which the vulnerability
   needs"). An empty list should mean unknown. **MISSED AFFECTED.** The sibling record GHSA-jh2j with a usable spec
   was right.

### Trigger specs (qwen): 5 advisories

- **pyjwt CVE-2026-48524 (needs_review, should be affected):** the trigger symbol is garbled
  (`pyjwt.PyJWKClient.get_signing, `), so the call only matched as an unconfirmed "related" candidate.
- **pyjwt CVE-2026-48523 (false alarm):** the arg_form says `algorithms` is dangerous when it is `PyJWK`
  (the flaw is about the *key* being a PyJWK), and `when_absent: dangerous`. The narrow questions then said yes.
- **pyjwt CVE-2026-48526 (false alarm):** the condition "algorithms mixes HS and RS" is right, but the app's
  `algorithms=["RS256"]` was not decided by code, and the LLM answered yes.
- **pyjwt CVE-2026-48522 (false alarm):** the condition says a jku "from a configuration file" is dangerous, which
  describes the app's safe case as dangerous.
- **py7zr CVE-2026-55195 (false alarm):** the trigger is the whole `SevenZipFile` class, with no extract/decompress call,
  and a contradictory arg_form (`mode` 'r' both dangerous and safe).

### Framework/parent reach: 3 advisories needs_review (not wrong)

- starlette 54283 / 54282: the spec has `Request.form` but no parent trigger for fastapi, so reach through FastAPI's
  `Form(...)` can't be shown.
- h11 CVE-2025-43859: no parent trigger for httpcore/httpx.

## What this says

- On unseen code, stepwise was **no better than holistic** (46% vs 46–50%). The 95% on the development suite was
  partly tuned to those repos: the name normalisation, public-name mapping and subclass rules were written while
  looking at them.
- The two misses are both code-decided failures on **missing evidence** (a name the matcher didn't recognise, an empty
  list). This breaks the rule "fail only on definite evidence". Those are the main candidates for a fix, but only
  if you approve one, since this is held-out data.
- The spec quality problems are the same kind as in `spec_issues.md`: garbled symbols, whole-class triggers,
  conditions that invert the safe case. They add to that baseline for the Gemini comparison in section 6.
