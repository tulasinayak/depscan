# depscan held-out evaluation: pre-registration

Written 2026-09-27, before depscan has been run on the held-out set.

> **The timestamped original is the copy in the public `depscan-test-suite` repository, commit `c5449f1`.** This copy
> in the depscan repository is for convenience; if the two ever differ, the depscan-test-suite copy and its git
> history count. Approved changes to the final method are committed there first.

## Rules

1. **The held-out set** is `depscan-heldout-3` (Django), `depscan-heldout-4` (pandas data processing) and
   `depscan-heldout-5` (Flask API with background jobs).
   - A subagent built them without reading depscan's source, prompts or results.
   - Each repo's answer file (`.depscan/expected.yaml`) was in its first commit: heldout-3 0e3bd26, heldout-4 6118343,
     heldout-5 be19a6a.
   - The 5 labels the builder flagged as less certain were set to `uncertain` in a separate commit before any run,
     titled "pre-registration: flagged labels set to uncertain": heldout-3 22c0d0f, heldout-4 d8ae0d7,
     heldout-5 361ff2b.
2. **Nobody working on the method** opens or reads the held-out repos' code or answer files. They are touched only
   in the final run.
3. **The final method** is the one described in the next section. It changes only when the project owner approves
   the change before the run, and each approved change is recorded below with its date.
4. **One run.** The final method runs once on the held-out set; that run is the headline result.
5. **No method changes after the held-out run.** Any later fix is reported separately as "after seeing the held-out
   results", never as a held-out number.
6. **Labels are not changed after the run.** If one looks wrong, the disagreement is reported next to the unchanged
   result.

## Final method (to be completed and approved before the run)

**Status:** draft. It describes the method as it is today; the planned additions are listed separately and are
not yet part of it.

**Current method: "stepwise"** (qwen3:8b through a local Ollama, CPU only, context 8192, temperature 0.1, JSON mode,
thinking off).

1. **Scan.**
   - Clone the repo.
   - Read the pinned dependencies from the manifests and lockfiles.
   - Match the exact versions against OSV. Aliases are merged, and fuzzing crash reports are set aside.
   - Find where the code uses each vulnerable package with `ast`. Import names come from the installed metadata,
     then a built-in table, then the distribution name compared without regard to case.
   - Nothing from the repository is executed.
2. **Trigger description ("spec") per advisory and package.** One LLM call over the advisory text plus the trimmed
   fix diff gives:
   - the trigger symbols;
   - the dangerous condition;
   - the argument forms;
   - whether untrusted input is needed, and which argument;
   - the parent-package triggers;
   - the bundled native feature.

   It is cached per advisory. A human override file wins, but there are none in the evaluation.
3. **Six checks per advisory**, each giving pass / fail / unknown with file:line evidence:
   1. version in range;
   2. spec available;
   3. vulnerable code used;
   4. that code can run (import graph from the entry points, dead code, test-only, config flags);
   5. dangerous form (argument checks in code, else one narrow LLM question that must cite a shown line to say "no");
   6. attacker-controlled input (taint over up to 2 caller hops, else one narrow LLM question).

   Checks 3–6 run per usage site, with at most 4 narrow questions per advisory. A check says "fail" only on definite
   evidence; missing or empty information gives unknown.
4. **Status.**
   - **affected:** all checks pass;
   - **not affected:** a check decided by code fails;
   - **probably not affected:** the only failures are LLM "no" answers;
   - **needs review:** otherwise.

**Planned additions, each needing approval before the run:**
- ground specs in the package's own code: import names from PyPI metadata, a public-API index, API facts retrieved
  into the spec prompt, validation of spec symbols against the index, parent triggers found in code;
- a spec source chosen from the 4-variant comparison (qwen / qwen + facts / Gemini / Gemini + facts);
- call-path slices ("stepwise+slices").

**Approved final method:** *(filled in and dated by the project owner before the run)*

## Metrics reported

For the held-out set as a whole and per repo, next to the development groups (`development`, `dev-2`):

- **decided accuracy:** correct / decided. Decided means affected, not affected or probably not affected;
  probably not affected counts as a "not affected" answer.
- **coverage:** decided / labelled advisories.
- **missed affected:** labelled affected, answered not affected (decided by code).
- **affected hidden in probably not affected:** labelled affected, answered probably not affected.
- **false alarms:** labelled not affected, answered affected.
- **AI calls per CVE and time per CVE:** the mean over all labelled advisories, including spec generation.

The advisories labelled `uncertain` (the 5 pre-registered ones) are **excluded from these numbers** and reported in
their own row with depscan's answers.

The holistic baseline (one LLM call per advisory, without and with repo context) is run on the same set for
comparison.
